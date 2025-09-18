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
        st.dataframe(data.head(5))


with st.sidebar:
    st.header("Configuration")
    st.caption("Configure these values via Streamlit secrets (see `.streamlit/secrets.toml`).")
    st.text(f"Base URL: {base_url or 'Not set'}")
    masked_token = f"{bearer[:4]}..." if bearer else "Not set"
    st.text(f"Bearer Token: {masked_token}")
    st.text(f"Workspace ID: {workspace_id or 'Not set'}")
    st.text(f"UID Lookup Mode: {uid_lookup_mode}")

st.info("Upload a CSV with at least an **email** column. Optional columns: **first_name**, **last_name**, **user_name**.")

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
        for c in df.columns:
            lc = c.lower()
            if lc == "first_name" or lc == "firstname":
                first_col = c
            if lc == "last_name" or lc == "lastname":
                last_col = c
            if lc == "user_name" or lc == "username":
                user_col = c

        first_col = st.selectbox("First name column (optional)", options=["<none>"] + df.columns.tolist(), index=(["<none>"]+df.columns.tolist()).index(first_col) if first_col else 0)
        last_col = st.selectbox("Last name column (optional)", options=["<none>"] + df.columns.tolist(), index=(["<none>"]+df.columns.tolist()).index(last_col) if last_col else 0)
        user_col = st.selectbox("Username column (optional)", options=["<none>"] + df.columns.tolist(), index=(["<none>"]+df.columns.tolist()).index(user_col) if user_col else 0)

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
        work["uid"] = None
        work["uid_status"] = ""
        work["uid_http"] = ""
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
        for idx in st.session_state["data"].index:
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
            progress.progress((idx+1)/total, text=f"Mapping UIDs... {idx+1}/{total}")
        st.success(f"UID mapping finished. Found {found}, failed {bad}.")
        st.session_state["uid_mapped"] = True
        show_preview(preview_placeholder, "Preview after UID mapping")

        csv = st.session_state["data"].to_csv(index=False).encode("utf-8")
        st.download_button("Download mapping CSV", data=csv, file_name="uid_mapping.csv", mime="text/csv")

    if st.session_state["uid_mapped"]:
        failed = st.session_state["data"][st.session_state["data"]["uid"].isna() | (st.session_state["data"]["uid"] == "")]
        if not failed.empty:
            st.warning(f"{len(failed)} rows have no UID. You can correct these manually below and click Apply Manual Fixes.")
            manual = failed[["email", "uid"]].copy()
            manual["uid"] = ""
            edited = st.data_editor(manual, num_rows="dynamic", use_container_width=True, key="manual_uid_editor")
            if st.button("Apply Manual Fixes"):
                # Merge edited values
                for _, r in edited.iterrows():
                    email = str(r["email"]).strip().lower()
                    uid = str(r["uid"]).strip()
                    mask = st.session_state["data"]["email"] == email
                    st.session_state["data"].loc[mask, "uid"] = uid
                    st.session_state["data"].loc[mask, "uid_status"] = "Manual"
                st.success("Manual UIDs applied.")

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

    st.divider()
    st.subheader("Logs")
    try:
        with open("logs/app.log", "r", encoding="utf-8") as f:
            st.text(f.read()[-8000:])
    except Exception:
        st.caption("No logs yet.")
else:
    st.caption("Awaiting CSV upload.")
