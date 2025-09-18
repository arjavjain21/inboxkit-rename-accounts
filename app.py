import hashlib
import io
from typing import Optional

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


def show_preview(placeholder, note: Optional[str] = None) -> None:
    data = st.session_state.get("data")
    if data is None:
        placeholder.empty()
        return
    with placeholder.container():
        if note:
            st.caption(note)
        st.dataframe(data.head(5), use_container_width=True)


with st.sidebar:
    st.header("Configuration")
    st.caption("Configure these values via Streamlit secrets (see `.streamlit/secrets.toml`).")
    st.text(f"Base URL: {base_url or 'Not set'}")
    masked_token = f"{bearer[:4]}..." if bearer else "Not set"
    st.text(f"Bearer Token: {masked_token}")
    st.text(f"Workspace ID: {workspace_id or 'Not set'}")
    st.text(f"UID Lookup Mode: {uid_lookup_mode}")

st.info(
    "Upload a CSV with at least an **email** column. Optional columns: **first_name**, **last_name**, **user_name**, and **forwarding_url** (or **forwarding_to**)."
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

if uploaded:
    file_bytes_raw = uploaded.getvalue()
    token = hashlib.md5(file_bytes_raw).hexdigest()
    new_upload = st.session_state.get("upload_token") != token
    if new_upload:
        st.session_state["upload_token"] = token
        st.session_state["uid_mapped"] = False
        st.session_state["update_done"] = False

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
        forwarding_col = None
        for c in df.columns:
            lc = c.lower()
            if lc == "first_name" or lc == "firstname":
                first_col = c
            if lc == "last_name" or lc == "lastname":
                last_col = c
            if lc == "user_name" or lc == "username":
                user_col = c
            if lc in ("forwarding_url", "forwarding to", "forwarding_to", "forward_to"):
                forwarding_col = c

        first_col = st.selectbox("First name column (optional)", options=["<none>"] + df.columns.tolist(), index=(["<none>"]+df.columns.tolist()).index(first_col) if first_col else 0)
        last_col = st.selectbox("Last name column (optional)", options=["<none>"] + df.columns.tolist(), index=(["<none>"]+df.columns.tolist()).index(last_col) if last_col else 0)
        user_col = st.selectbox("Username column (optional)", options=["<none>"] + df.columns.tolist(), index=(["<none>"]+df.columns.tolist()).index(user_col) if user_col else 0)
        forwarding_col = st.selectbox(
            "Forwarding URL column (optional)",
            options=["<none>"] + df.columns.tolist(),
            index=(["<none>"] + df.columns.tolist()).index(forwarding_col) if forwarding_col else 0,
        )

        # Clean and prepare
        user_series = None
        if user_col != "<none>":
            user_series = df[user_col].astype(str)

        work = df.copy()
        work.rename(columns={email_col: "email"}, inplace=True)
        work["email"] = work["email"].astype(str).str.strip().str.lower()
        parsed = work["email"].apply(parse_email)
        work["username"] = parsed.apply(lambda x: x[0] if x else None)
        work["domain"] = parsed.apply(lambda x: x[1] if x else None)
        work["uid"] = ""
        work["uid_status"] = ""
        work["uid_http"] = ""
        work["domain_uid"] = ""
        work["domain_uid_status"] = ""
        work["domain_uid_http"] = ""
        work["update_status"] = ""
        work["update_http"] = ""
        work["update_error"] = ""
        work["forwarding_url"] = ""
        work["forwarding_status"] = ""
        work["forwarding_http"] = ""
        work["forwarding_error"] = ""

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

        if forwarding_col != "<none>":
            forwarding_series = df[forwarding_col].fillna("").astype(str).str.strip()
            work["forwarding_url"] = forwarding_series

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

        data = st.session_state["data"]

        total = len(data)
        progress = st.progress(0, text="Starting mailbox UID mapping...")
        found = 0
        bad = 0
        for i, idx in enumerate(data.index, start=1):
            row = data.loc[idx]
            email = row["email"]
            username = row["username"]
            domain = row["domain"]
            if not username or not domain:
                data.at[idx, "uid_status"] = "Invalid email"
                bad += 1
            else:
                uid, err, code = client.find_uid_by_email(email, username, domain)
                if uid:
                    data.at[idx, "uid"] = uid
                    data.at[idx, "uid_status"] = "OK"
                    data.at[idx, "uid_http"] = str(code or "")
                    found += 1
                else:
                    data.at[idx, "uid_status"] = err or "Lookup failed"
                    data.at[idx, "uid_http"] = str(code or "")
                    bad += 1
            progress.progress(i / total, text=f"Mapping mailbox UIDs... {i}/{total}")
        st.success(f"Mailbox UID mapping finished. Found {found}, failed {bad}.")

        domain_progress = st.progress(0, text="Starting domain UID mapping...")
        domain_values = [d for d in data["domain"].astype(str).str.strip().str.lower().unique() if d and d != "nan"]
        domain_found = 0
        domain_failed = 0
        invalid_mask = data["domain"].isna() | (data["domain"].astype(str).str.strip() == "")
        if invalid_mask.any():
            data.loc[invalid_mask, "domain_uid_status"] = "Invalid domain"
        for i, domain_value in enumerate(domain_values, start=1):
            domain_progress.progress(i / max(len(domain_values), 1), text=f"Mapping domain UIDs... {i}/{len(domain_values)}")
            uid, err, code = client.find_domain_uid(domain_value)
            mask = data["domain"].astype(str).str.strip().str.lower() == domain_value
            if uid:
                data.loc[mask, "domain_uid"] = uid
                data.loc[mask, "domain_uid_status"] = "OK"
                data.loc[mask, "domain_uid_http"] = str(code or "")
                domain_found += mask.sum()
            else:
                data.loc[mask, "domain_uid_status"] = err or "Lookup failed"
                data.loc[mask, "domain_uid_http"] = str(code or "")
                domain_failed += mask.sum()
        domain_progress.progress(1.0, text="Domain UID mapping complete")
        st.success(f"Domain UID mapping finished. Updated {domain_found} rows, failed {domain_failed}.")

        st.session_state["data"] = data
        st.session_state["uid_mapped"] = True
        show_preview(preview_placeholder, "Preview after UID mapping")

        csv = st.session_state["data"].to_csv(index=False).encode("utf-8")
        st.download_button("Download mapping CSV", data=csv, file_name="uid_mapping.csv", mime="text/csv")

    if st.session_state["uid_mapped"]:
        failed = st.session_state["data"][st.session_state["data"]["uid"].isna() | (st.session_state["data"]["uid"] == "")]
        if not failed.empty:
            st.warning(
                f"{len(failed)} rows have no UID. You can correct these manually below and click Apply Manual Mailbox Fixes."
            )
            manual = failed[["email", "uid"]].copy()
            manual["uid"] = manual["uid"].astype(str)
            edited = st.data_editor(manual, num_rows="dynamic", use_container_width=True, key="manual_uid_editor")
            if st.button("Apply Manual Mailbox Fixes"):
                # Merge edited values
                for _, r in edited.iterrows():
                    email = str(r["email"]).strip().lower()
                    uid = str(r["uid"]).strip()
                    mask = st.session_state["data"]["email"] == email
                    st.session_state["data"].loc[mask, "uid"] = uid
                    st.session_state["data"].loc[mask, "uid_status"] = "Manual"
                    st.session_state["data"].loc[mask, "uid_http"] = ""
                st.success("Manual mailbox UIDs applied.")

        domain_failed = st.session_state["data"][
            (st.session_state["data"]["domain"].notna())
            & (st.session_state["data"]["domain"].astype(str).str.strip() != "")
            & ((st.session_state["data"]["domain_uid"].isna()) | (st.session_state["data"]["domain_uid"] == ""))
        ]
        if not domain_failed.empty:
            st.warning(
                f"{len(domain_failed)} rows have no domain UID. You can correct these below and click Apply Manual Domain Fixes."
            )
            domain_manual = (
                domain_failed[["domain", "domain_uid"]]
                .copy()
                .drop_duplicates(subset=["domain"])
                .reset_index(drop=True)
            )
            domain_manual["domain_uid"] = domain_manual["domain_uid"].astype(str)
            edited_domains = st.data_editor(
                domain_manual,
                num_rows="dynamic",
                use_container_width=True,
                key="manual_domain_editor",
            )
            if st.button("Apply Manual Domain Fixes"):
                for _, r in edited_domains.iterrows():
                    domain_value = str(r["domain"]).strip().lower()
                    domain_uid = str(r["domain_uid"]).strip()
                    mask = st.session_state["data"]["domain"].astype(str).str.strip().str.lower() == domain_value
                    st.session_state["data"].loc[mask, "domain_uid"] = domain_uid
                    st.session_state["data"].loc[mask, "domain_uid_status"] = "Manual"
                    st.session_state["data"].loc[mask, "domain_uid_http"] = ""
                st.success("Manual domain UIDs applied.")

        st.divider()
        st.subheader("Step 2: Update Mailboxes")

        ready = st.session_state["data"].copy()
        missing_uid = ready["uid"].isna() | (ready["uid"] == "")
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

                csv = ready.to_csv(index=False).encode("utf-8")
                st.download_button("Download results CSV", data=csv, file_name="update_results.csv", mime="text/csv")

    if st.session_state.get("update_done"):
        st.divider()
        st.subheader("Step 3: Update Domain Forwarding")
        forwarding_data = st.session_state["data"]
        uid_missing = forwarding_data["uid"].fillna("").astype(str).str.strip() == ""
        domain_uid_missing = forwarding_data["domain_uid"].fillna("").astype(str).str.strip() == ""
        forwarding_missing = forwarding_data["forwarding_url"].fillna("").astype(str).str.strip() == ""
        if forwarding_missing.all():
            st.info("No forwarding URLs provided in the CSV; skipping domain forwarding updates.")
        elif uid_missing.any() or domain_uid_missing.any() or forwarding_missing.any():
            st.error(
                "Each row must have a mailbox UID, domain UID, and forwarding URL before updating domain forwarding."
            )
        else:
            if st.button("Update Domain Forwarding now"):
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

                grouped = forwarding_data.groupby("domain_uid", dropna=False)
                total_domains = len(grouped)
                progress = st.progress(0, text="Starting domain forwarding updates...")
                ok_domains = 0
                failed_domains = 0
                for i, (domain_uid_value, group) in enumerate(grouped, start=1):
                    progress.progress(i / max(total_domains, 1), text=f"Updating domain forwarding... {i}/{total_domains}")
                    forwarding_values = (
                        group["forwarding_url"].fillna("").astype(str).str.strip().unique().tolist()
                    )
                    forwarding_values = [v for v in forwarding_values if v]
                    mask = forwarding_data["domain_uid"] == domain_uid_value
                    if len(forwarding_values) != 1:
                        forwarding_data.loc[mask, "forwarding_status"] = "ERR"
                        forwarding_data.loc[mask, "forwarding_error"] = (
                            "Multiple forwarding URLs found for domain" if forwarding_values else "Missing forwarding URL"
                        )
                        forwarding_data.loc[mask, "forwarding_http"] = ""
                        failed_domains += 1
                        continue

                    forwarding_url_value = forwarding_values[0]
                    success, err, code = client.set_domain_forwarding([str(domain_uid_value)], forwarding_url_value)
                    if success:
                        forwarding_data.loc[mask, "forwarding_status"] = "OK"
                        forwarding_data.loc[mask, "forwarding_http"] = str(code or "")
                        forwarding_data.loc[mask, "forwarding_error"] = ""
                        ok_domains += 1
                    else:
                        forwarding_data.loc[mask, "forwarding_status"] = "ERR"
                        forwarding_data.loc[mask, "forwarding_http"] = str(code or "")
                        forwarding_data.loc[mask, "forwarding_error"] = err or ""
                        failed_domains += 1

                st.session_state["data"] = forwarding_data
                st.success(
                    f"Domain forwarding updates complete. Success for {ok_domains} domains, failed for {failed_domains}."
                )
                show_preview(preview_placeholder, "Preview after domain forwarding updates")

                csv = forwarding_data.to_csv(index=False).encode("utf-8")
                st.download_button(
                    "Download forwarding results CSV",
                    data=csv,
                    file_name="forwarding_results.csv",
                    mime="text/csv",
                )

    st.divider()
    st.subheader("Logs")
    try:
        with open("logs/app.log", "r", encoding="utf-8") as f:
            st.text(f.read()[-8000:])
    except Exception:
        st.caption("No logs yet.")
else:
    st.caption("Awaiting CSV upload.")
