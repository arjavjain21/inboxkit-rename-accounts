import hashlib
import io
import sys
from pathlib import Path
from typing import List, Optional

import pandas as pd
import streamlit as st

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from utils import (
    annotate_skip_statuses,
    apply_smartlead_export_outcome,
    clear_persisted_session,
    evaluate_smartlead_export,
    load_persisted_session,
    parse_email,
    read_csv_robust,
    persist_session_state,
    setup_logger,
)
from inboxkit_client import InboxKitClient, InboxKitError

LOG_INTERVAL = 20
logger = setup_logger()

config = st.secrets
base_url = str(config.get("INBOXKIT_BASE_URL", "https://api.inboxkit.com")).strip()
bearer = str(config.get("INBOXKIT_BEARER", "")).strip()
workspace_id = str(config.get("INBOXKIT_WORKSPACE_ID", "")).strip()
uid_lookup_mode = str(config.get("INBOXKIT_UID_LOOKUP_MODE", "auto")).strip().lower()
if uid_lookup_mode not in {"auto", "email", "search", "list"}:
    uid_lookup_mode = "auto"

st.set_page_config(page_title="InboxKit UID Mapper and Updater", page_icon="📧", layout="wide")

st.title("📧 InboxKit UID Mapper and Updater")
st.caption("Modern, minimal Streamlit tool to map mailbox UIDs from emails, then update user fields via InboxKit API.")


def _ordered_columns(df: pd.DataFrame) -> List[str]:
    """Return preferred column order for display/export while keeping extras."""

    preferred = [
        "email",
        "username",
        "domain",
        "uid",
        "uid_status",
        "uid_http",
        "domain_uid",
        "domain_uid_status",
        "domain_uid_http",
        "forwarding_url",
        "forwarding_status",
        "forwarding_http",
        "forwarding_error",
        "update_status",
        "update_http",
        "update_error",
        "smartlead_export_status",
        "smartlead_export_http",
        "smartlead_export_error",
        "first_name",
        "last_name",
        "user_name",
    ]
    ordered = [col for col in preferred if col in df.columns]
    ordered.extend(col for col in df.columns if col not in ordered)
    return ordered


def _normalize_column_name(name: str) -> str:
    return (
        str(name or "")
        .strip()
        .lower()
        .replace("-", "")
        .replace("_", "")
        .replace(" ", "")
    )


EMAIL_ALIASES = {
    "email",
    "emails",
    "emailaddress",
    "emailaddr",
    "emailid",
    "mail",
    "mailaddress",
    "e-mail",
}
FIRST_NAME_ALIASES = {
    "firstname",
    "first_name",
    "fname",
    "givenname",
    "given_name",
}
LAST_NAME_ALIASES = {
    "lastname",
    "last_name",
    "lname",
    "surname",
    "familyname",
}
USERNAME_ALIASES = {
    "username",
    "user_name",
    "user",
    "login",
    "loginname",
}
FORWARDING_ALIASES = {
    "forwardingurl",
    "forwardingto",
    "forwardto",
    "forwardurl",
    "forwardingaddress",
    "forwardaddress",
    "forwarding",
}

def _detect_column(df: pd.DataFrame, aliases: set[str]) -> Optional[str]:
    normalized_aliases = {_normalize_column_name(alias) for alias in aliases}
    for column in df.columns:
        if _normalize_column_name(column) in normalized_aliases:
            return column
    return None


def _safe_select_index(options: List[str], preferred: Optional[str]) -> int:
    if preferred and preferred in options:
        return options.index(preferred)
    return 0


def _prepare_work_dataframe(
    df: pd.DataFrame,
    email_col: str,
    first_col: Optional[str],
    last_col: Optional[str],
    user_col: Optional[str],
    forward_col: Optional[str],
) -> pd.DataFrame:
    if email_col not in df.columns:
        raise ValueError("Email column selection is invalid")

    work = df.copy()
    user_col_values = None
    if user_col and user_col in work.columns:
        user_col_values = work[user_col].copy()
    work["input_email"] = work[email_col].astype(str)
    work.rename(columns={email_col: "email"}, inplace=True)
    work["email"] = work["email"].astype(str).str.strip().str.lower()
    parsed = work["email"].apply(parse_email)
    work["username"] = parsed.apply(lambda x: x[0] if x else None)
    work["domain"] = parsed.apply(lambda x: x[1] if x else None)
    work["uid"] = None
    work["uid_status"] = ""
    work["uid_http"] = ""
    work["domain_uid"] = None
    work["domain_uid_status"] = ""
    work["domain_uid_http"] = ""
    work["forwarding_url"] = ""
    work["forwarding_status"] = ""
    work["forwarding_http"] = ""
    work["forwarding_error"] = ""
    work["update_status"] = ""
    work["update_http"] = ""
    work["update_error"] = ""
    work["smartlead_export_status"] = ""
    work["smartlead_export_http"] = ""
    work["smartlead_export_error"] = ""

    if first_col and first_col in work.columns:
        work["first_name"] = work[first_col].astype(str)
    else:
        work["first_name"] = ""
    if last_col and last_col in work.columns:
        work["last_name"] = work[last_col].astype(str)
    else:
        work["last_name"] = ""
    if user_col_values is not None:
        work["user_name"] = user_col_values.astype(str)
    else:
        work["user_name"] = ""
    if forward_col and forward_col in work.columns:
        work["forwarding_url"] = work[forward_col].fillna("").astype(str).str.strip()

    return work


def _collect_exportable_uids(df: Optional[pd.DataFrame]) -> List[str]:
    """Return unique mailbox UIDs that were successfully updated."""

    if df is None or "uid" not in df.columns:
        return []

    uid_series = df["uid"].fillna("").astype(str).str.strip()
    if "update_status" in df.columns:
        status_series = df["update_status"].fillna("").astype(str).str.upper()
        eligible_mask = uid_series.ne("") & status_series.eq("OK")
    else:
        eligible_mask = uid_series.ne("")

    if not eligible_mask.any():
        return []

    ordered = uid_series.loc[eligible_mask].tolist()
    return [uid for uid in dict.fromkeys(ordered) if uid]


def _human_yes_no(value: str) -> str:
    normalized = str(value or "").strip().upper()
    return "yes" if normalized == "OK" else "no"


def _persist_current_session(token: Optional[str]) -> None:
    data = st.session_state.get("data")
    if not token or data is None:
        return

    metadata = {
        "uid_mapped": st.session_state.get("uid_mapped", False),
        "update_done": st.session_state.get("update_done", False),
        "smartlead_export_ready": st.session_state.get("smartlead_export_ready", False),
        "smartlead_export_context": st.session_state.get(
            "smartlead_export_context"
        ),
        "domain_uid_cache": st.session_state.get("domain_uid_cache", {}),
        "smartlead_export_done": st.session_state.get("smartlead_export_done", False),
    }

    persist_session_state(token, data, metadata)


def _compose_new_email(row: pd.Series) -> str:
    """Return the mailbox email after updates succeed.

    The workflow renames an inbox by posting the desired ``user_name`` to
    ``/v1/api/mailboxes/update``. That value only becomes the actual mailbox
    address when the update request returns ``OK``. We keep the original email
    for rows that were not updated or failed so the final report clearly shows
    which mailboxes still need attention.
    """

    base_email = str(row.get("email") or row.get("input_email") or "").strip()
    user_name = str(row.get("user_name") or "").strip()
    domain = str(row.get("domain") or "").strip()
    update_status = str(row.get("update_status") or "").strip().upper()

    if update_status == "OK" and user_name and domain:
        return f"{user_name}@{domain}".lower()

    return base_email


def build_final_report(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return pd.DataFrame()

    report = pd.DataFrame()
    report["input_email"] = df.get("input_email", df.get("email", pd.Series(dtype=str)))
    report["new_email"] = df.apply(_compose_new_email, axis=1)
    report["uid"] = df.get("uid", pd.Series(dtype=str))
    report["domain_uid"] = df.get("domain_uid", pd.Series(dtype=str))
    report["forwarding_url"] = df.get("forwarding_url", pd.Series(dtype=str))
    report["update_status"] = df.get("update_status", pd.Series(dtype=str))
    report["update_http"] = df.get("update_http", pd.Series(dtype=str))
    report["update_error"] = df.get("update_error", pd.Series(dtype=str))
    report["forwarding_status"] = df.get("forwarding_status", pd.Series(dtype=str))
    report["forwarding_http"] = df.get("forwarding_http", pd.Series(dtype=str))
    report["forwarding_error"] = df.get("forwarding_error", pd.Series(dtype=str))
    report["smartlead_export_status"] = df.get(
        "smartlead_export_status", pd.Series(dtype=str)
    )
    report["smartlead_export_http"] = df.get(
        "smartlead_export_http", pd.Series(dtype=str)
    )
    report["smartlead_export_error"] = df.get(
        "smartlead_export_error", pd.Series(dtype=str)
    )

    def _summarize(row: pd.Series) -> str:
        parts = []
        upd_status = str(row.get("update_status", "") or "").upper()
        if upd_status:
            if upd_status == "OK":
                parts.append("Mailbox updated")
            elif upd_status.startswith("ERR"):
                err = row.get("update_error", "") or "Error"
                parts.append(f"Mailbox update failed: {err}")
            else:
                parts.append(f"Mailbox update: {upd_status}")

        fwd_status = str(row.get("forwarding_status", "") or "").upper()
        if fwd_status:
            if fwd_status == "OK":
                parts.append("Forwarding updated")
            elif fwd_status.startswith("ERR"):
                err = row.get("forwarding_error", "") or "Error"
                parts.append(f"Forwarding failed: {err}")
            else:
                parts.append(f"Forwarding: {fwd_status}")

        export_status = str(row.get("smartlead_export_status", "") or "").upper()
        if export_status:
            if export_status == "OK":
                parts.append("Smartlead export ready")
            elif export_status.startswith("ERR"):
                err = row.get("smartlead_export_error", "") or "Error"
                parts.append(f"Smartlead export failed: {err}")
            else:
                parts.append(f"Smartlead export: {export_status}")

        return "; ".join(parts) if parts else "No changes applied"

    report["changes_done"] = report.apply(_summarize, axis=1)
    report["updated_forwarding_status"] = report["forwarding_status"].apply(
        _human_yes_no
    )
    return report


def _categorize_row(row: pd.Series) -> str:
    statuses = []
    for col in ["update_status", "forwarding_status", "smartlead_export_status"]:
        status_val = str(row.get(col, "") or "").strip()
        if status_val:
            statuses.append(status_val)

    if not statuses:
        return "skipped"

    normalized = [s.upper() for s in statuses]
    if any("SKIP" in s for s in normalized):
        return "skipped"
    if any(s.startswith("ERR") or "FAIL" in s for s in normalized):
        return "fail"
    if any(s.startswith("INVALID") for s in normalized):
        return "fail"
    if any(s.startswith("OK") or s == "MANUAL" for s in normalized):
        return "success"
    return "skipped"


def collect_run_results(df: pd.DataFrame) -> pd.DataFrame:
    columns = [
        "email",
        "uid",
        "domain_uid",
        "update_status",
        "update_http",
        "update_error",
        "forwarding_status",
        "forwarding_http",
        "forwarding_error",
        "smartlead_export_status",
        "smartlead_export_http",
        "smartlead_export_error",
    ]

    available_cols = [c for c in columns if c in df.columns]
    if not available_cols:
        return pd.DataFrame()

    results = df.loc[:, available_cols].copy()
    results["result"] = results.apply(_categorize_row, axis=1)
    return results


def show_results_summary(df: pd.DataFrame) -> None:
    if df.empty:
        return

    results = collect_run_results(df)
    if results.empty:
        return

    st.divider()
    st.subheader("Run Results")

    counts = results["result"].value_counts()
    success_count = int(counts.get("success", 0))
    fail_count = int(counts.get("fail", 0))
    skipped_count = int(counts.get("skipped", 0))

    metrics = st.columns(3)
    metrics[0].metric("Success", f"{success_count}")
    metrics[1].metric("Failed", f"{fail_count}")
    metrics[2].metric("Skipped", f"{skipped_count}")

    failed_rows = results.loc[results["result"] == "fail"]
    if not failed_rows.empty:
        failure_csv = failed_rows.to_csv(index=False).encode("utf-8")
        st.download_button(
            "Download failures CSV",
            data=failure_csv,
            file_name="failures.csv",
            mime="text/csv",
            key="download_failures_csv",
        )
        st.caption("First few failures")
        st.dataframe(failed_rows.head(10))


def _log_progress(label: str, current: int, total: int) -> None:
    if total <= 0:
        return
    if current == 1 or current == total or current % LOG_INTERVAL == 0:
        logger.info(f"{label}: {current}/{total}")


def show_preview(placeholder, note: Optional[str] = None) -> None:
    raw_data = st.session_state.get("raw_data")
    data = raw_data if isinstance(raw_data, pd.DataFrame) else None
    if data is None:
        data = st.session_state.get("data")
        if data is None:
            placeholder.empty()
            return
    with placeholder.container():
        if note:
            st.caption(note)
        st.dataframe(data.head(5))


with st.sidebar:
    st.header("Configuration")
    st.caption("Configure these values via Streamlit secrets (see `.streamlit/secrets.toml`).")
    st.text(f"Base URL: {base_url or 'Not set'}")
    masked_token = f"{bearer[:4]}..." if bearer else "Not set"
    st.text(f"Bearer Token: {masked_token}")
    st.text(f"Workspace ID: {workspace_id or 'Not set'}")
    st.text(f"UID Lookup Mode: {uid_lookup_mode}")

    st.divider()
    st.subheader("Run Log")
    sidebar_messages = st.session_state.get("status_messages") or []
    if sidebar_messages:
        for msg in sidebar_messages[-10:]:
            st.write(f"- {msg}")
    else:
        st.caption("No status updates yet.")

st.info(
    "Upload a CSV with at least an **email** column (used to map mailbox and domain UIDs). "
    "Optional columns: **first_name**, **last_name**, **user_name** (new username to apply on update), and forwarding settings such as **forwarding_url** or **forwarding_to**. For best performance, upload **250 rows or fewer** per run."
)

uploaded = st.file_uploader("Upload CSV", type=["csv"])

if "data" not in st.session_state:
    st.session_state["data"] = None
if "uid_mapped" not in st.session_state:
    st.session_state["uid_mapped"] = False
if "update_done" not in st.session_state:
    st.session_state["update_done"] = False
if "upload_token" not in st.session_state:
    st.session_state["upload_token"] = None
if "raw_data" not in st.session_state:
    st.session_state["raw_data"] = None
if "status_messages" not in st.session_state:
    st.session_state["status_messages"] = []
if "smartlead_export_done" not in st.session_state:
    st.session_state["smartlead_export_done"] = False
if "smartlead_export_ready" not in st.session_state:
    st.session_state["smartlead_export_ready"] = False
if "smartlead_export_context" not in st.session_state:
    st.session_state["smartlead_export_context"] = None
if "domain_uid_cache" not in st.session_state:
    st.session_state["domain_uid_cache"] = {}

if uploaded:
    file_bytes_raw = uploaded.getvalue()
    token = hashlib.md5(file_bytes_raw).hexdigest()

    if st.session_state.get("upload_token") != token and st.session_state.get("data") is None:
        restored = load_persisted_session(token)
        if restored:
            restored_df, restored_meta = restored
            st.session_state["data"] = restored_df
            st.session_state["upload_token"] = token
            st.session_state["uid_mapped"] = restored_meta.get("uid_mapped", False)
            st.session_state["update_done"] = restored_meta.get("update_done", False)
            st.session_state["smartlead_export_ready"] = restored_meta.get(
                "smartlead_export_ready", False
            )
            st.session_state["smartlead_export_context"] = restored_meta.get(
                "smartlead_export_context"
            )
            st.session_state["smartlead_export_done"] = restored_meta.get(
                "smartlead_export_done", False
            )
            st.session_state["domain_uid_cache"] = restored_meta.get(
                "domain_uid_cache", {}
            )
    new_upload = st.session_state.get("upload_token") != token
    if new_upload:
        previous_token = st.session_state.get("upload_token")
        if previous_token and previous_token != token:
            clear_persisted_session(previous_token)
        st.session_state["upload_token"] = token
        st.session_state["uid_mapped"] = False
        st.session_state["update_done"] = False
        st.session_state["status_messages"] = []
        st.session_state["smartlead_export_done"] = False
        st.session_state["smartlead_export_ready"] = False
        st.session_state["smartlead_export_context"] = None
        st.session_state["domain_uid_cache"] = {}
        st.session_state["raw_data"] = None
        st.session_state["data"] = None

    if st.session_state.get("raw_data") is None:
        # Need a fresh buffer per read attempt
        file_bytes = io.BytesIO(file_bytes_raw)
        try:
            df = read_csv_robust(file_bytes)
        except Exception as e:
            st.error(f"Failed to read CSV: {e}")
            st.stop()

        if len(df) > 250:
            st.warning(
                "This tool is optimized for up to 250 rows per run. "
                "Upload a smaller file or check the box below to truncate to the first 250 rows."
            )
            truncate_confirmed = st.checkbox(
                "Truncate to the first 250 rows for processing", key=f"truncate_{token}"
            )
            if not truncate_confirmed:
                st.stop()

            df = df.head(250)

        # Normalize columns
        df.columns = [c.strip() for c in df.columns]
        st.session_state["raw_data"] = df

    preview_placeholder = st.empty()
    raw_df = st.session_state.get("raw_data")
    if raw_df is not None and not st.session_state.get("uid_mapped"):
        columns = raw_df.columns.tolist()
        if not columns:
            st.error("Uploaded CSV does not contain any columns.")
            st.stop()

        email_default = _detect_column(raw_df, EMAIL_ALIASES) or columns[0]
        email_options = columns
        email_index = _safe_select_index(email_options, email_default)
        email_col = st.selectbox(
            "Select the email column",
            options=email_options,
            index=email_index,
            key=f"email_col_{token}",
        )

        optional_options = ["<none>"] + columns
        first_default = _detect_column(raw_df, FIRST_NAME_ALIASES)
        last_default = _detect_column(raw_df, LAST_NAME_ALIASES)
        user_default = _detect_column(raw_df, USERNAME_ALIASES)
        forward_default = _detect_column(raw_df, FORWARDING_ALIASES)

        first_col = st.selectbox(
            "First name column (optional)",
            options=optional_options,
            index=_safe_select_index(optional_options, first_default or "<none>"),
            key=f"first_col_{token}",
        )
        last_col = st.selectbox(
            "Last name column (optional)",
            options=optional_options,
            index=_safe_select_index(optional_options, last_default or "<none>"),
            key=f"last_col_{token}",
        )
        user_col = st.selectbox(
            "Username column (optional)",
            options=optional_options,
            index=_safe_select_index(optional_options, user_default or "<none>"),
            key=f"user_col_{token}",
        )
        forward_col = st.selectbox(
            "Forwarding URL column (optional)",
            options=optional_options,
            index=_safe_select_index(optional_options, forward_default or "<none>"),
            key=f"forward_col_{token}",
        )

        work = _prepare_work_dataframe(
            raw_df,
            email_col,
            None if first_col == "<none>" else first_col,
            None if last_col == "<none>" else last_col,
            None if user_col == "<none>" else user_col,
            None if forward_col == "<none>" else forward_col,
        )
        st.session_state["data"] = work
        _persist_current_session(st.session_state.get("upload_token"))

    if st.session_state.get("data") is not None:
        st.subheader("Preview")
        show_preview(preview_placeholder)

        st.divider()
        st.subheader("Step 1: Map UIDs")
        st.write("We will try multiple lookup strategies unless you force a mode in the sidebar.")

    if st.button("Map UIDs now"):
        missing = []
        if not bearer:
            missing.append("INBOXKIT_BEARER")
        if not workspace_id:
            missing.append("INBOXKIT_WORKSPACE_ID")
        if missing:
            st.error(
                "Missing required InboxKit credentials: "
                + ", ".join(missing)
                + ". Update `.streamlit/secrets.toml` and restart the app."
            )
            st.stop()

        try:
            client = InboxKitClient(base_url=base_url, bearer=bearer, workspace_id=workspace_id, uid_lookup_mode=uid_lookup_mode)
        except InboxKitError as e:
            st.error(str(e))
            st.stop()

        total = len(st.session_state["data"])
        found = 0
        bad = 0
        with st.status("Mapping UIDs...", expanded=False) as status_box:
            progress = st.progress(0, text="Starting UID mapping...")
            for i, idx in enumerate(st.session_state["data"].index, start=1):
                row = st.session_state["data"].loc[idx]
                email = row["email"]
                username = row["username"]
                domain = row["domain"]
                if not username or not domain:
                    st.session_state["data"].at[idx, "uid_status"] = "Invalid email"
                    bad += 1
                else:
                    uid, err, code = client.find_uid_by_email(email, username, domain)
                    if uid:
                        st.session_state["data"].at[idx, "uid"] = uid
                        st.session_state["data"].at[idx, "uid_status"] = "OK"
                        st.session_state["data"].at[idx, "uid_http"] = str(code or "")
                        found += 1
                    else:
                        st.session_state["data"].at[idx, "uid_status"] = err or "Lookup failed"
                        st.session_state["data"].at[idx, "uid_http"] = str(code or "")
                        bad += 1

                progress.progress(i / total, text=f"Mapping UIDs... {i}/{total}")
                _log_progress("UID mapping", i, total)
            status_box.update(label="UID mapping complete", state="complete")

        domain_series = st.session_state["data"]["domain"].fillna("").astype(str)
        normalized_domains = domain_series.str.strip().str.lower()
        invalid_domain_mask = normalized_domains == ""
        if invalid_domain_mask.any():
            st.session_state["data"].loc[invalid_domain_mask, "domain_uid_status"] = "Invalid domain"
            logger.warning(
                f"Domain lookup skipped for {int(invalid_domain_mask.sum())} rows: invalid domain"
            )

        unique_domains = sorted(d for d in normalized_domains.unique() if d)
        domain_counts = {"found": 0, "failed": 0}

        def resolve_domain_lookups(domains: List[str], *, use_cache: bool = True):
            if not domains:
                return
            with st.status("Resolving domain UIDs...", expanded=False) as domain_status:
                domain_progress = st.progress(0, text="Resolving domains...")
                total_domains = len(domains)
                for i, domain_value in enumerate(domains, start=1):
                    cached = (
                        st.session_state["domain_uid_cache"].get(domain_value)
                        if use_cache
                        else None
                    )
                    mask = normalized_domains == domain_value
                    if cached and cached.get("uid"):
                        http_str = cached.get("http", "")
                        st.session_state["data"].loc[mask, "domain_uid"] = cached["uid"]
                        st.session_state["data"].loc[mask, "domain_uid_status"] = "OK"
                        st.session_state["data"].loc[mask, "domain_uid_http"] = http_str
                        domain_counts["found"] += 1
                        _log_progress("Domain lookups (cached)", i, total_domains)
                    else:
                        uid, err, code = client.get_domain_uid(domain_value)
                        http_str = str(code) if code is not None else ""
                        http_display = http_str or "n/a"
                        if uid:
                            st.session_state["domain_uid_cache"][domain_value] = {
                                "uid": uid,
                                "http": http_str,
                            }
                            st.session_state["data"].loc[mask, "domain_uid"] = uid
                            st.session_state["data"].loc[mask, "domain_uid_status"] = "OK"
                            st.session_state["data"].loc[mask, "domain_uid_http"] = http_str
                            domain_counts["found"] += 1
                            _log_progress("Domain lookups", i, total_domains)
                        else:
                            st.session_state["data"].loc[mask, "domain_uid"] = None
                            st.session_state["data"].loc[mask, "domain_uid_status"] = err or "Lookup failed"
                            st.session_state["data"].loc[mask, "domain_uid_http"] = http_str
                            domain_counts["failed"] += 1
                            logger.error(
                                f"Domain lookup failed for {domain_value}: {err or 'Lookup failed'} (HTTP {http_display})"
                            )
                    domain_progress.progress(
                        i / total_domains, text=f"Resolving domains... {i}/{total_domains}"
                    )
                domain_status.update(label="Domain lookups complete", state="complete")

        if unique_domains:
            resolve_domain_lookups(unique_domains)
        summary_message = (
            "UID mapping finished. "
            f"Mailboxes found {found}, failed {bad}. "
            f"Domains resolved {domain_counts['found']}, failed {domain_counts['failed']}."
        )
        st.success(summary_message)
        logger.info(summary_message)
        st.session_state["status_messages"].append(summary_message)
        st.session_state["uid_mapped"] = True
        _persist_current_session(token)
        show_preview(preview_placeholder, "Preview after UID mapping")

        unresolved_mask = (
            (st.session_state["data"]["domain_uid_status"] != "OK")
            & (normalized_domains != "")
        )
        unresolved_domains = sorted(
            st.session_state["data"].loc[unresolved_mask, "domain"]
            .fillna("")
            .str.strip()
            .str.lower()
            .unique()
        )
        if unresolved_domains:
            st.subheader("Unresolved domains")
            unresolved_rows = []
            for domain_value in unresolved_domains:
                mask = normalized_domains == domain_value
                status = (
                    st.session_state["data"].loc[mask, "domain_uid_status"].iloc[0]
                    if not st.session_state["data"].loc[mask].empty
                    else ""
                )
                http_code = (
                    st.session_state["data"].loc[mask, "domain_uid_http"].iloc[0]
                    if not st.session_state["data"].loc[mask].empty
                    else ""
                )
                unresolved_rows.append(
                    {
                        "domain": domain_value,
                        "status": status,
                        "http": http_code,
                    }
                )
            st.dataframe(pd.DataFrame(unresolved_rows))
            if st.button("Retry failed lookups", key="retry_failed_domains"):
                resolve_domain_lookups(unresolved_domains, use_cache=False)
                show_preview(preview_placeholder, "Preview after UID mapping")

    if st.session_state["uid_mapped"]:
        ordered_cols = _ordered_columns(st.session_state["data"])
        mapping_csv = (
            st.session_state["data"].loc[:, ordered_cols].to_csv(index=False).encode("utf-8")
        )
        st.download_button(
            "Download mapping CSV",
            data=mapping_csv,
            file_name="uid_mapping.csv",
            mime="text/csv",
            key="download_mapping_csv",
        )

        data = st.session_state["data"]
        uid_missing = data["uid"].isna() | (data["uid"].astype(str).str.strip() == "")
        domain_missing = data["domain_uid"].isna() | (data["domain_uid"].astype(str).str.strip() == "")
        manual_mask = uid_missing | domain_missing
        manual_rows = data.loc[manual_mask]
        if not manual_rows.empty:
            st.warning(
                f"{len(manual_rows)} rows are missing mailbox or domain UIDs. "
                "You can correct these manually below and click Apply Manual Fixes."
            )
            manual = manual_rows[["email", "domain", "uid", "domain_uid"]].copy()
            manual.insert(0, "row_index", manual.index)
            manual["uid"] = manual["uid"].fillna("").astype(str)
            manual["domain_uid"] = manual["domain_uid"].fillna("").astype(str)
            edited = st.data_editor(
                manual,
                num_rows="dynamic",
                width="stretch",
                key="manual_uid_editor",
                disabled=["row_index", "email", "domain"],
            )
            if st.button("Apply Manual Fixes"):
                updates = 0
                for _, r in edited.iterrows():
                    idx = r.get("row_index")
                    if idx not in st.session_state["data"].index:
                        continue
                    raw_uid = r.get("uid")
                    new_uid = "" if pd.isna(raw_uid) else str(raw_uid).strip()
                    raw_domain_uid = r.get("domain_uid")
                    new_domain_uid = "" if pd.isna(raw_domain_uid) else str(raw_domain_uid).strip()

                    orig_uid = st.session_state["data"].at[idx, "uid"]
                    orig_uid_str = "" if pd.isna(orig_uid) else str(orig_uid).strip()
                    if new_uid != orig_uid_str:
                        st.session_state["data"].at[idx, "uid"] = new_uid or None
                        st.session_state["data"].at[idx, "uid_status"] = "Manual" if new_uid else ""
                        st.session_state["data"].at[idx, "uid_http"] = ""
                        updates += 1

                    orig_domain_uid = st.session_state["data"].at[idx, "domain_uid"]
                    orig_domain_uid_str = (
                        "" if pd.isna(orig_domain_uid) else str(orig_domain_uid).strip()
                    )
                    if new_domain_uid != orig_domain_uid_str:
                        st.session_state["data"].at[idx, "domain_uid"] = new_domain_uid or None
                        st.session_state["data"].at[idx, "domain_uid_status"] = (
                            "Manual" if new_domain_uid else ""
                        )
                        st.session_state["data"].at[idx, "domain_uid_http"] = ""
                        updates += 1

                if updates:
                    st.success("Manual overrides applied.")
                else:
                    st.info("No manual overrides detected.")

        st.divider()
        st.subheader("Step 2: Update Mailboxes")

        ready = st.session_state["data"].copy()
        uid_series = ready["uid"].fillna("").astype(str).str.strip()
        missing_uid = uid_series == ""
        missing_count = int(missing_uid.sum())
        if missing_count:
            st.warning(
                f"{missing_count} row(s) are missing mailbox UID and will be skipped from updates and exports."
            )

        valid_ready = ready.loc[~missing_uid].copy()

        if st.button("Update Mailboxes now"):
            skip_message = "Skipped: no mailbox UID provided."
            if missing_count:
                ready = annotate_skip_statuses(ready, missing_uid, skip_message)

            if valid_ready.empty:
                st.info("No rows with mailbox UID available to update.")
                st.session_state["data"] = ready
                st.session_state["update_done"] = False
                st.session_state["smartlead_export_done"] = False
                skip_status_message = (
                    f"Mailbox update skipped: no rows with UID. Skipped {missing_count} row(s)."
                )
                st.session_state["status_messages"].append(skip_status_message)
                show_preview(preview_placeholder, "Preview after updates")
            else:
                try:
                    client = InboxKitClient(
                        base_url=base_url,
                        bearer=bearer,
                        workspace_id=workspace_id,
                        uid_lookup_mode=uid_lookup_mode,
                    )
                except InboxKitError as e:
                    st.error(str(e))
                    st.stop()
                st.session_state["smartlead_export_done"] = False
                total = len(valid_ready)
                ok = 0
                fail = 0
                with st.status("Updating mailboxes...", expanded=False) as status_box:
                    progress = st.progress(0, text="Starting updates...")
                    for i, idx in enumerate(valid_ready.index, start=1):
                        row = valid_ready.loc[idx]
                        success, err, code = client.update_mailbox(
                            uid=row["uid"],
                            first_name=(row.get("first_name") or "").strip() or None,
                            last_name=(row.get("last_name") or "").strip() or None,
                            user_name=(row.get("user_name") or "").strip() or None,
                        )
                        http_code = str(code or "")
                        if success:
                            ready.at[idx, "update_status"] = "OK"
                            ready.at[idx, "update_http"] = http_code
                            ready.at[idx, "update_error"] = ""
                            ok += 1
                        else:
                            ready.at[idx, "update_status"] = "ERR"
                            ready.at[idx, "update_http"] = http_code
                            ready.at[idx, "update_error"] = err or ""
                            logger.error(
                                "Mailbox update failed for UID %s (email: %s): %s",
                                row.get("uid"),
                                row.get("email"),
                                err or "Unknown error",
                            )
                            fail += 1
                        progress.progress(i / total, text=f"Updating... {i}/{total}")
                        _log_progress("Mailbox updates", i, total)
                    status_box.update(label="Mailbox updates complete", state="complete")

                st.session_state["data"] = ready
                summary = (
                    f"Mailbox update complete. Processed {total} row(s): success {ok}, failed {fail}."
                )
                if missing_count:
                    summary += f" Skipped {missing_count} row(s) without mailbox UID."
                if fail:
                    st.warning(summary)
                else:
                    st.success(summary)
                st.info(
                    f"Batch summary: ✅ {ok} successful, ❌ {fail} failed out of {total} processed."
                )
                st.session_state["status_messages"].append(summary)
                show_preview(preview_placeholder, "Preview after updates")
                st.session_state["update_done"] = bool(total)

                candidate_uids = _collect_exportable_uids(ready)
                (
                    eligible_uids,
                    export_ready,
                    export_status_message,
                    export_level,
                ) = evaluate_smartlead_export(
                    forwarding_success=True,
                    updates_ok=(fail == 0),
                    mailbox_uids=candidate_uids,
                )

                if export_ready:
                    st.session_state["smartlead_export_context"] = {
                        "eligible_uids": eligible_uids
                    }
                    st.session_state["smartlead_export_ready"] = True
                else:
                    st.session_state["smartlead_export_context"] = None
                    st.session_state["smartlead_export_ready"] = False

                if export_status_message:
                    if export_level == "warning":
                        st.warning(export_status_message)
                    else:
                        st.info(export_status_message)
                    st.session_state["status_messages"].append(export_status_message)

                _persist_current_session(token)

        st.divider()
        st.subheader("Step 3: Update Forwarding")

        current = st.session_state["data"].copy()
        forwarding_required = (
            current.get("forwarding_url", pd.Series(dtype=str))
            .fillna("")
            .astype(str)
            .str.strip()
        )
        has_forwarding_urls = forwarding_required.ne("").any()

        if not has_forwarding_urls:
            st.info(
                "No forwarding URLs provided. Skipping forwarding updates. You can proceed to "
                "Smartlead export as soon as mailbox updates finish."
            )
        else:
            uid_required = current["uid"].fillna("").astype(str).str.strip()
            domain_required = current["domain_uid"].fillna("").astype(str).str.strip()

            missing_uid_forward = uid_required == ""
            missing_domain_uid = domain_required == ""
            missing_forwarding_url = forwarding_required == ""

            skipped_forwarding_rows = int(
                (missing_uid_forward | missing_domain_uid | missing_forwarding_url).sum()
            )
            if skipped_forwarding_rows:
                messages = []
                if missing_uid_forward.any():
                    messages.append(
                        f"{int(missing_uid_forward.sum())} row(s) missing mailbox UID"
                    )
                if missing_domain_uid.any():
                    messages.append(
                        f"{int(missing_domain_uid.sum())} row(s) missing domain UID"
                    )
                if missing_forwarding_url.any():
                    messages.append(
                        f"{int(missing_forwarding_url.sum())} row(s) missing forwarding URL"
                    )
                st.warning(
                    "Forwarding updates will skip rows with incomplete data:\n- "
                    + "\n- ".join(messages)
                )

            processable_mask = (~missing_uid_forward) & (~missing_domain_uid) & (
                ~missing_forwarding_url
            )

            if st.button("Update Forwarding"):
                try:
                    client = InboxKitClient(
                        base_url=base_url,
                        bearer=bearer,
                        workspace_id=workspace_id,
                        uid_lookup_mode=uid_lookup_mode,
                    )
                except InboxKitError as e:
                    st.error(str(e))
                    st.stop()

                st.session_state["smartlead_export_done"] = False
                st.session_state["smartlead_export_ready"] = False
                st.session_state["smartlead_export_context"] = None

                data_copy = current.copy()
                processing_index = data_copy.index[processable_mask]

                data_copy.loc[processing_index, "forwarding_status"] = ""
                data_copy.loc[processing_index, "forwarding_http"] = ""
                data_copy.loc[processing_index, "forwarding_error"] = ""
                data_copy.loc[processing_index, "smartlead_export_status"] = ""
                data_copy.loc[processing_index, "smartlead_export_http"] = ""
                data_copy.loc[processing_index, "smartlead_export_error"] = ""

                skip_message = "Skipped: no mailbox UID provided."
                if missing_uid_forward.any():
                    data_copy = annotate_skip_statuses(
                        data_copy,
                        missing_uid_forward,
                        skip_message,
                        columns=("forwarding", "smartlead"),
                    )

                if missing_domain_uid.any():
                    data_copy = annotate_skip_statuses(
                        data_copy,
                        missing_domain_uid,
                        "Skipped: no domain UID provided.",
                        columns=("forwarding", "smartlead"),
                    )

                if missing_forwarding_url.any():
                    data_copy = annotate_skip_statuses(
                        data_copy,
                        missing_forwarding_url,
                        "Skipped: no forwarding URL provided.",
                        columns=("forwarding", "smartlead"),
                    )

                domain_groups = []
                for domain_uid_value, group in data_copy.loc[processable_mask].groupby(
                    "domain_uid"
                ):
                    domain_uid_str = str(domain_uid_value).strip()
                    if not domain_uid_str:
                        continue
                    domain_groups.append((domain_uid_str, group))

                if not domain_groups:
                    st.info("No domains available for forwarding updates.")
                    st.session_state["data"] = data_copy
                    _persist_current_session(token)
                    show_preview(
                        preview_placeholder, "Preview after forwarding updates"
                    )
                    if skipped_forwarding_rows:
                        st.session_state["status_messages"].append(
                            f"Forwarding skipped: no eligible rows. Skipped {skipped_forwarding_rows} row(s)."
                        )
                else:
                    total_domains = len(domain_groups)
                    success_count = 0
                    failure_count = 0
                    error_messages: List[str] = []

                    with st.status("Updating forwarding...", expanded=False) as forwarding_status:
                        progress = st.progress(0, text="Starting forwarding updates...")

                        for i, (domain_uid_value, group) in enumerate(domain_groups, start=1):
                            domain_values = (
                                group.get("domain", pd.Series(dtype=str))
                                .fillna("")
                                .astype(str)
                                .str.strip()
                            )
                            domain_name = next((d for d in domain_values if d), domain_uid_value)

                            forwarding_values = (
                                group["forwarding_url"].fillna("").astype(str).str.strip()
                            )
                            unique_forwarding = sorted({v for v in forwarding_values if v})

                            progress.progress(
                                min(i / total_domains, 1.0),
                                text=f"Updating forwarding... {i}/{total_domains}",
                            )

                            if not unique_forwarding:
                                message = (
                                    f"Forwarding skipped for {domain_name} ({domain_uid_value}): no forwarding URL provided"
                                )
                                data_copy.loc[group.index, "forwarding_status"] = "ERR"
                                data_copy.loc[group.index, "forwarding_error"] = message
                                failure_count += 1
                                error_messages.append(message)
                                logger.error(message)
                                continue

                            if len(unique_forwarding) > 1:
                                joined_urls = ", ".join(unique_forwarding)
                                message = (
                                    f"Forwarding skipped for {domain_name} ({domain_uid_value}): "
                                    f"multiple forwarding URLs found ({joined_urls})"
                                )
                                data_copy.loc[group.index, "forwarding_status"] = "ERR"
                                data_copy.loc[group.index, "forwarding_error"] = message
                                failure_count += 1
                                error_messages.append(message)
                                logger.error(message)
                                continue

                            uid_values = (
                                group["uid"].fillna("").astype(str).str.strip()
                                if "uid" in group
                                else pd.Series(dtype=str)
                            )
                            unique_mailbox_uids = sorted({uid for uid in uid_values if uid})

                            if not unique_mailbox_uids:
                                message = (
                                    f"Forwarding skipped for {domain_name} ({domain_uid_value}): "
                                    "no mailbox UIDs available"
                                )
                                data_copy.loc[group.index, "forwarding_status"] = "ERR"
                                data_copy.loc[group.index, "forwarding_error"] = message
                                failure_count += 1
                                error_messages.append(message)
                                logger.error(message)
                                continue

                            payload = {
                                "forwarding_url": unique_forwarding[0],
                            }
                            success, err, code = client.update_domain_forwarding(
                                domain_uid_value, payload
                            )
                            http_str = str(code) if code is not None else ""
                            http_display = http_str or "n/a"

                            if success:
                                data_copy.loc[group.index, "forwarding_status"] = "OK"
                                data_copy.loc[group.index, "forwarding_http"] = http_str
                                success_count += 1
                                _log_progress("Forwarding updates", i, total_domains)
                            else:
                                error_detail = err or "Unknown error"
                                data_copy.loc[group.index, "forwarding_status"] = "ERR"
                                data_copy.loc[group.index, "forwarding_http"] = http_str
                                data_copy.loc[group.index, "forwarding_error"] = error_detail
                                failure_count += 1
                                message = (
                                    f"Forwarding failed for {domain_name} ({domain_uid_value}): {error_detail}"
                                )
                                error_messages.append(f"{message} (HTTP {http_display})")
                                logger.error(f"{message} (HTTP {http_display})")
                    forwarding_status.update(
                        label="Forwarding updates complete", state="complete"
                    )

                progress.progress(1.0, text="Forwarding updates finished.")

                summary_message = (
                    f"Forwarding update complete. Domains success {success_count}, failed {failure_count}."
                )
                if skipped_forwarding_rows:
                    summary_message += (
                        f" Skipped {skipped_forwarding_rows} row(s) with incomplete data."
                    )
                logger.info(summary_message)
                if failure_count:
                    st.warning(summary_message)
                else:
                    st.success(summary_message)

                st.session_state["status_messages"].append(summary_message)
                for msg in error_messages:
                    st.session_state["status_messages"].append(msg)

                if error_messages:
                    st.error(
                        "Forwarding errors encountered:\n- "
                        + "\n- ".join(error_messages)
                    )

                forwarding_success = failure_count == 0
                update_status_series = data_copy.get("update_status")
                updates_ok = bool(st.session_state.get("update_done"))
                if isinstance(update_status_series, pd.Series):
                    updates_ok = (
                        updates_ok
                        and not update_status_series.fillna("")
                        .astype(str)
                        .str.upper()
                        .eq("ERR")
                        .any()
                    )

                candidate_uids = _collect_exportable_uids(data_copy)
                eligible_uids, export_ready, export_status_message, export_level = (
                    evaluate_smartlead_export(
                        forwarding_success,
                        updates_ok,
                        candidate_uids,
                    )
                )

                st.session_state["smartlead_export_done"] = False
                st.session_state["smartlead_export_ready"] = export_ready
                st.session_state["smartlead_export_context"] = (
                    {"eligible_uids": eligible_uids} if export_ready else None
                )

                if export_status_message:
                    if export_level == "warning":
                        logger.warning(export_status_message)
                        st.warning(export_status_message)
                    else:
                        logger.info(export_status_message)
                        st.info(export_status_message)
                    st.session_state["status_messages"].append(export_status_message)

                st.session_state["data"] = data_copy
                _persist_current_session(token)
                show_preview(
                    preview_placeholder, "Preview after forwarding updates"
                )

        export_context = st.session_state.get("smartlead_export_context") or {}
        eligible_context_uids = export_context.get("eligible_uids") or []
        if st.session_state.get("smartlead_export_ready") and eligible_context_uids:
            if st.button("Export Inboxes", key="export_inboxes_button"):
                try:
                    client = InboxKitClient(
                        base_url=base_url,
                        bearer=bearer,
                        workspace_id=workspace_id,
                        uid_lookup_mode=uid_lookup_mode,
                    )
                except InboxKitError as e:
                    st.error(str(e))
                    st.stop()

                current_data = st.session_state["data"].copy()
                mailbox_uids_series = (
                    current_data["uid"].fillna("").astype(str).str.strip()
                    if "uid" in current_data.columns
                    else pd.Series(dtype=str)
                )
                eligible_mask = mailbox_uids_series.isin(eligible_context_uids)

                export_success, export_error, export_code = (
                    client.export_inboxes_to_smartlead(eligible_context_uids)
                )

                (
                    updated_df,
                    export_status_message,
                    export_http_display,
                    severity,
                    log_level,
                    export_done,
                ) = apply_smartlead_export_outcome(
                    current_data,
                    eligible_mask,
                    eligible_context_uids,
                    export_success,
                    export_error,
                    export_code,
                )

                log_message = (
                    f"{export_status_message} (HTTP {export_http_display})"
                )
                if log_level == "error":
                    logger.error(log_message)
                else:
                    logger.info(log_message)

                if severity == "success":
                    st.success(f"{export_status_message} HTTP {export_http_display}")
                else:
                    st.error(f"{export_status_message} (HTTP {export_http_display})")

                st.session_state["data"] = updated_df
                st.session_state["status_messages"].append(export_status_message)
                st.session_state["smartlead_export_done"] = export_done

                if export_done:
                    st.session_state["smartlead_export_ready"] = False
                    st.session_state["smartlead_export_context"] = None
                else:
                    st.session_state["smartlead_export_ready"] = True
                    st.session_state["smartlead_export_context"] = export_context

                _persist_current_session(token)
                show_preview(
                    preview_placeholder, "Preview after forwarding updates"
                )

        if st.session_state["update_done"]:
            ordered_cols = _ordered_columns(st.session_state["data"])
            results_csv = (
                st.session_state["data"].loc[:, ordered_cols].to_csv(index=False).encode("utf-8")
            )
            st.download_button(
                "Download results CSV",
                data=results_csv,
                file_name="update_results.csv",
                mime="text/csv",
                key="download_results_csv",
            )

        show_results_summary(st.session_state["data"])

        final_report = build_final_report(st.session_state["data"])
        if not final_report.empty:
            final_csv = final_report.to_csv(index=False).encode("utf-8")
            st.download_button(
                "Download final report CSV",
                data=final_csv,
                file_name="final_results.csv",
                mime="text/csv",
                key="download_final_report_csv",
                help=(
                    "Complete run output including original email, normalized email, "
                    "status per step, and a concise change summary."
                ),
            )

        st.divider()
        st.subheader("Status Updates")
        if st.session_state["status_messages"]:
            for msg in st.session_state["status_messages"][-50:]:
                st.write(f"- {msg}")
        else:
            st.caption("No status updates yet.")

    st.divider()
    st.subheader("Logs")
    try:
        with open("logs/app.log", "r", encoding="utf-8") as f:
            st.text(f.read()[-8000:])
    except Exception:
        st.caption("No logs yet.")
else:
    st.caption("Awaiting CSV upload.")
