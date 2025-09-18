import hashlib
import io
from typing import List, Optional

import pandas as pd
import streamlit as st
from utils import setup_logger, parse_email, read_csv_robust
from inboxkit_client import InboxKitClient, InboxKitError

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
        "first_name",
        "last_name",
        "user_name",
    ]
    ordered = [col for col in preferred if col in df.columns]
    ordered.extend(col for col in df.columns if col not in ordered)
    return ordered


def show_preview(placeholder, note: Optional[str] = None) -> None:
    data = st.session_state.get("data")
    if data is None:
        placeholder.empty()
        return
    with placeholder.container():
        if note:
            st.caption(note)
        ordered_cols = _ordered_columns(data)
        st.dataframe(data.loc[:, ordered_cols].head(5))


with st.sidebar:
    st.header("Configuration")
    st.caption("Configure these values via Streamlit secrets (see `.streamlit/secrets.toml`).")
    st.text(f"Base URL: {base_url or 'Not set'}")
    masked_token = f"{bearer[:4]}..." if bearer else "Not set"
    st.text(f"Bearer Token: {masked_token}")
    st.text(f"Workspace ID: {workspace_id or 'Not set'}")
    st.text(f"UID Lookup Mode: {uid_lookup_mode}")

st.info(
    "Upload a CSV with at least an **email** column. Optional columns: **first_name**, **last_name**, **user_name**, forwarding settings such as **forwarding_url** or **forwarding_to**."
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
if "status_messages" not in st.session_state:
    st.session_state["status_messages"] = []

if uploaded:
    file_bytes_raw = uploaded.getvalue()
    token = hashlib.md5(file_bytes_raw).hexdigest()
    new_upload = st.session_state.get("upload_token") != token
    if new_upload:
        st.session_state["upload_token"] = token
        st.session_state["uid_mapped"] = False
        st.session_state["update_done"] = False
        st.session_state["status_messages"] = []

    if st.session_state["data"] is None or new_upload:
        # Need a fresh buffer per read attempt
        file_bytes = io.BytesIO(file_bytes_raw)
        try:
            df = read_csv_robust(file_bytes)
        except Exception as e:
            st.error(f"Failed to read CSV: {e}")
            st.stop()

        # Normalize columns
        df.columns = [c.strip() for c in df.columns]
        # Make sure required column exists or allow selection
        email_col = None
        candidates = [c for c in df.columns if c.lower() in ("email", "emails", "email_id", "e-mail")]
        if len(candidates) == 1:
            email_col = candidates[0]
        else:
            email_col = st.selectbox("Select the email column", options=df.columns.tolist())

        # Optional fields
        first_col = None
        last_col = None
        user_col = None
        forward_col = None
        for c in df.columns:
            lc = c.lower()
            if lc == "first_name" or lc == "firstname":
                first_col = c
            if lc == "last_name" or lc == "lastname":
                last_col = c
            if lc == "user_name" or lc == "username":
                user_col = c
            normalized_forward = lc.replace("-", "_").replace(" ", "_")
            if normalized_forward in {
                "forwarding_url",
                "forwarding_to",
                "forward_to",
                "forwarding",
            }:
                forward_col = c

        first_col = st.selectbox("First name column (optional)", options=["<none>"] + df.columns.tolist(), index=(["<none>"]+df.columns.tolist()).index(first_col) if first_col else 0)
        last_col = st.selectbox("Last name column (optional)", options=["<none>"] + df.columns.tolist(), index=(["<none>"]+df.columns.tolist()).index(last_col) if last_col else 0)
        user_col = st.selectbox("Username column (optional)", options=["<none>"] + df.columns.tolist(), index=(["<none>"]+df.columns.tolist()).index(user_col) if user_col else 0)
        forward_col = st.selectbox("Forwarding URL column (optional)", options=["<none>"] + df.columns.tolist(), index=(["<none>"]+df.columns.tolist()).index(forward_col) if forward_col else 0)

        # Clean and prepare
        user_series = None
        if user_col != "<none>":
            user_series = df[user_col].astype(str)
        forward_series = None
        if forward_col != "<none>":
            forward_series = df[forward_col].fillna("").astype(str).str.strip()

        work = df.copy()
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

        if first_col != "<none>":
            work["first_name"] = work[first_col].astype(str)
        else:
            work["first_name"] = ""
        if last_col != "<none>":
            work["last_name"] = work[last_col].astype(str)
        else:
            work["last_name"] = ""
        if user_series is not None:
            work["user_name"] = user_series
        else:
            work["user_name"] = ""
        if forward_series is not None:
            work["forwarding_url"] = forward_series

        st.session_state["data"] = work

    st.subheader("Preview")
    preview_placeholder = st.empty()
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
        progress = st.progress(0, text="Starting UID mapping...")
        found = 0
        bad = 0
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

        domain_series = st.session_state["data"]["domain"].fillna("").astype(str)
        normalized_domains = domain_series.str.strip().str.lower()
        invalid_domain_mask = normalized_domains == ""
        if invalid_domain_mask.any():
            st.session_state["data"].loc[invalid_domain_mask, "domain_uid_status"] = "Invalid domain"
            logger.warning(
                f"Domain lookup skipped for {int(invalid_domain_mask.sum())} rows: invalid domain"
            )

        unique_domains = sorted(d for d in normalized_domains.unique() if d)
        domain_found = 0
        domain_failed = 0
        if unique_domains:
            domain_progress = st.progress(0, text="Resolving domains...")
            total_domains = len(unique_domains)
            for i, domain_value in enumerate(unique_domains, start=1):
                uid, err, code = client.get_domain_uid(domain_value)
                mask = normalized_domains == domain_value
                http_str = str(code) if code is not None else ""
                http_display = http_str or "n/a"
                if uid:
                    st.session_state["data"].loc[mask, "domain_uid"] = uid
                    st.session_state["data"].loc[mask, "domain_uid_status"] = "OK"
                    st.session_state["data"].loc[mask, "domain_uid_http"] = http_str
                    domain_found += 1
                    logger.info(
                        f"Domain lookup OK: {domain_value} -> {uid} (HTTP {http_display})"
                    )
                else:
                    st.session_state["data"].loc[mask, "domain_uid"] = None
                    st.session_state["data"].loc[mask, "domain_uid_status"] = err or "Lookup failed"
                    st.session_state["data"].loc[mask, "domain_uid_http"] = http_str
                    domain_failed += 1
                    logger.error(
                        f"Domain lookup failed for {domain_value}: {err or 'Lookup failed'} (HTTP {http_display})"
                    )
                domain_progress.progress(
                    i / total_domains, text=f"Resolving domains... {i}/{total_domains}"
                )
        summary_message = (
            "UID mapping finished. "
            f"Mailboxes found {found}, failed {bad}. "
            f"Domains resolved {domain_found}, failed {domain_failed}."
        )
        st.success(summary_message)
        logger.info(summary_message)
        st.session_state["status_messages"].append(summary_message)
        st.session_state["uid_mapped"] = True
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
                use_container_width=True,
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
        if missing_uid.any():
            st.error("Some rows still have missing UID. Fix those first.")
        else:
            if st.button("Update Mailboxes now"):
                try:
                    client = InboxKitClient(base_url=base_url, bearer=bearer, workspace_id=workspace_id, uid_lookup_mode=uid_lookup_mode)
                except InboxKitError as e:
                    st.error(str(e))
                    st.stop()
                total = len(ready)
                progress = st.progress(0, text="Starting updates...")
                ok = 0
                fail = 0
                for i, idx in enumerate(ready.index):
                    row = ready.loc[idx]
                    success, err, code = client.update_mailbox(
                        uid=row["uid"],
                        first_name=(row.get("first_name") or "").strip() or None,
                        last_name=(row.get("last_name") or "").strip() or None,
                        user_name=(row.get("user_name") or "").strip() or None,
                    )
                    if success:
                        ready.at[idx, "update_status"] = "OK"
                        ready.at[idx, "update_http"] = str(code or "")
                        ok += 1
                    else:
                        ready.at[idx, "update_status"] = "ERR"
                        ready.at[idx, "update_http"] = str(code or "")
                        ready.at[idx, "update_error"] = err or ""
                        fail += 1
                    progress.progress((i+1)/total, text=f"Updating... {i+1}/{total}")

                st.session_state["data"] = ready
                st.success(f"Update complete. Success {ok}, failed {fail}.")
                show_preview(preview_placeholder, "Preview after updates")
                st.session_state["update_done"] = True

        st.divider()
        st.subheader("Step 3: Update Forwarding")

        current = st.session_state["data"].copy()
        uid_required = current["uid"].fillna("").astype(str).str.strip()
        domain_required = current["domain_uid"].fillna("").astype(str).str.strip()
        forwarding_required = current["forwarding_url"].fillna("").astype(str).str.strip()

        missing_uid_forward = uid_required == ""
        missing_domain_uid = domain_required == ""
        missing_forwarding_url = forwarding_required == ""

        validation_messages: List[str] = []
        if missing_uid_forward.any():
            validation_messages.append(
                f"{int(missing_uid_forward.sum())} rows missing mailbox UID"
            )
        if missing_domain_uid.any():
            validation_messages.append(
                f"{int(missing_domain_uid.sum())} rows missing domain UID"
            )
        if missing_forwarding_url.any():
            validation_messages.append(
                f"{int(missing_forwarding_url.sum())} rows missing forwarding URL"
            )

        if validation_messages:
            details = "\n- " + "\n- ".join(validation_messages)
            st.error(
                "Cannot update forwarding until all required fields are populated:" + details
            )
        else:
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

                data_copy = current.copy()
                data_copy.loc[:, "forwarding_status"] = ""
                data_copy.loc[:, "forwarding_http"] = ""
                data_copy.loc[:, "forwarding_error"] = ""

                domain_groups = []
                for domain_uid_value, group in data_copy.groupby("domain_uid"):
                    domain_uid_str = str(domain_uid_value).strip()
                    if not domain_uid_str:
                        continue
                    domain_groups.append((domain_uid_str, group))

                if not domain_groups:
                    st.info("No domains available for forwarding updates.")
                else:
                    progress = st.progress(0, text="Starting forwarding updates...")
                    total_domains = len(domain_groups)
                    success_count = 0
                    failure_count = 0
                    error_messages: List[str] = []

                    for i, (domain_uid_value, group) in enumerate(domain_groups, start=1):
                        domain_values = (
                            group.get("domain", pd.Series(dtype=str))
                            .fillna("")
                            .astype(str)
                            .str.strip()
                        )
                        domain_name = next(
                            (d for d in domain_values if d), domain_uid_value
                        )

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

                        combined_uids = [domain_uid_value]
                        combined_uids.extend(
                            uid
                            for uid in unique_mailbox_uids
                            if uid and uid not in combined_uids
                        )

                        payload = {
                            "forwarding_url": unique_forwarding[0],
                            "uids": combined_uids,
                        }
                        success, err, code = client.update_domain_forwarding(
                            domain_uid_value, payload
                        )
                        http_str = str(code) if code is not None else ""
                        http_display = http_str or "n/a"

                        if success:
                            data_copy.loc[group.index, "forwarding_status"] = "OK"
                            data_copy.loc[group.index, "forwarding_http"] = http_str
                            summary = (
                                f"Forwarding updated for {domain_name} ({domain_uid_value})"
                            )
                            logger.info(
                                f"{summary}: {payload['forwarding_url']} (HTTP {http_display})"
                            )
                            success_count += 1
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

                    progress.progress(1.0, text="Forwarding updates finished.")

                    st.session_state["data"] = data_copy
                    show_preview(
                        preview_placeholder, "Preview after forwarding updates"
                    )

                    summary_message = (
                        f"Forwarding update complete. Domains success {success_count}, failed {failure_count}."
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
