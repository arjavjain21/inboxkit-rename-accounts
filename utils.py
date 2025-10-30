import logging
import os
import re
from typing import Iterable, List, Optional, Sequence, Tuple
import pandas as pd

EMAIL_REGEX = re.compile(r"^\s*([A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\s*$")

def setup_logger() -> logging.Logger:
    logger = logging.getLogger("inboxkit_tool")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        os.makedirs("logs", exist_ok=True)
        fh = logging.FileHandler("logs/app.log", encoding="utf-8")
        fh.setLevel(logging.INFO)
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        fh.setFormatter(fmt)
        ch.setFormatter(fmt)
        logger.addHandler(fh)
        logger.addHandler(ch)
    return logger

def parse_email(email: str) -> Optional[Tuple[str, str]]:
    if not isinstance(email, str):
        return None
    m = EMAIL_REGEX.match(email.strip())
    if not m:
        return None
    return m.group(1), m.group(2)

def read_csv_robust(file_bytes, fallback_encoding="utf-8"):
    """
    Try pandas with automatic delimiter detection, fall back to common separators.
    """
    # Try engine=python with sep=None to sniff
    for enc in (fallback_encoding, "utf-8-sig", "latin-1"):
        try:
            df = pd.read_csv(file_bytes, sep=None, engine="python", encoding=enc, dtype=str, keep_default_na=False)
            if len(df.columns) == 1 and df.columns[0].count(",") > 0:
                # Bad sniff, try comma
                file_bytes.seek(0)
                df = pd.read_csv(file_bytes, sep=",", encoding=enc, dtype=str, keep_default_na=False)
            return df
        except Exception:
            try:
                file_bytes.seek(0)
            except Exception:
                pass
            continue
    # Last resort try common seps
    for sep in [",", ";", "\t", "|"]:
        try:
            file_bytes.seek(0)
            df = pd.read_csv(file_bytes, sep=sep, dtype=str, keep_default_na=False)
            return df
        except Exception:
            try:
                file_bytes.seek(0)
            except Exception:
                pass
            continue
    raise ValueError("Could not parse CSV. Please upload a valid CSV file.")


def annotate_skip_statuses(
    df: pd.DataFrame,
    mask: pd.Series,
    message: str,
    columns: Iterable[str] = ("update", "forwarding", "smartlead"),
) -> pd.DataFrame:
    """Mark rows as skipped for the provided operation columns.

    Parameters
    ----------
    df:
        DataFrame to annotate. Columns are created if missing.
    mask:
        Boolean mask aligned with ``df.index`` identifying rows to mark as skipped.
    message:
        Human readable explanation recorded in the ``*_error`` columns.
    columns:
        Iterable selecting which operation families to annotate. Supported values
        are ``"update"``, ``"forwarding"`` and ``"smartlead"``.

    Returns
    -------
    pandas.DataFrame
        The same DataFrame instance with in-place updates for the selected rows.
    """

    if df is None:
        raise ValueError("DataFrame is required")

    valid_mask = pd.Series(mask, index=df.index)
    if not valid_mask.any():
        return df

    column_map = {
        "update": ("update_status", "update_http", "update_error"),
        "forwarding": (
            "forwarding_status",
            "forwarding_http",
            "forwarding_error",
        ),
        "smartlead": (
            "smartlead_export_status",
            "smartlead_export_http",
            "smartlead_export_error",
        ),
    }

    selected_columns = [column_map[name] for name in columns if name in column_map]

    for status_col, http_col, error_col in selected_columns:
        if status_col not in df.columns:
            df[status_col] = ""
        if http_col not in df.columns:
            df[http_col] = ""
        if error_col not in df.columns:
            df[error_col] = ""

        df.loc[valid_mask, status_col] = "Skipped"
        df.loc[valid_mask, http_col] = ""
        df.loc[valid_mask, error_col] = message

    return df


def evaluate_smartlead_export(
    forwarding_success: bool,
    updates_ok: bool,
    mailbox_uids: Sequence[str],
) -> Tuple[List[str], bool, str, str]:
    """Determine Smartlead export eligibility and user-facing messaging.

    Returns
    -------
    tuple
        ``(eligible_uids, ready, message, level)`` where ``eligible_uids`` is a
        de-duplicated list of non-empty mailbox UIDs, ``ready`` indicates
        whether the export button should be displayed, ``message`` contains the
        status text to surface to the user, and ``level`` is either ``"info"``
        or ``"warning"`` to aid in logging/UI severity selection.
    """

    normalized = [str(uid).strip() for uid in mailbox_uids if uid is not None]
    eligible = [uid for uid in dict.fromkeys(normalized) if uid]

    if forwarding_success and updates_ok and eligible:
        message = (
            f"Smartlead export ready for {len(eligible)} mailbox(es). "
            "Click \"Export Inboxes\" to proceed."
        )
        return eligible, True, message, "info"

    if forwarding_success and updates_ok:
        message = "Smartlead export skipped: no mailbox UIDs available."
        return eligible, False, message, "info"

    if not forwarding_success:
        message = "Smartlead export skipped due to forwarding errors."
        return eligible, False, message, "warning"

    message = "Smartlead export skipped due to mailbox update errors."
    return eligible, False, message, "warning"


def apply_smartlead_export_outcome(
    df: pd.DataFrame,
    eligible_mask: pd.Series,
    eligible_uids: Sequence[str],
    export_success: bool,
    export_error: Optional[str],
    export_code: Optional[int],
) -> Tuple[pd.DataFrame, str, str, str, str, bool]:
    """Update Smartlead export columns based on the API response.

    Parameters
    ----------
    df:
        DataFrame to update.
    eligible_mask:
        Boolean mask indicating which rows were part of the export attempt.
    eligible_uids:
        Sequence of unique mailbox UIDs submitted to the export endpoint.
    export_success:
        Result flag returned by ``InboxKitClient.export_inboxes_to_smartlead``.
    export_error:
        Error message returned by the client when ``export_success`` is false.
    export_code:
        Optional HTTP status code returned by the client.

    Returns
    -------
    tuple
        ``(updated_df, message, http_display, severity, log_level, done)``
        where ``severity`` is either ``"success"`` or ``"error"`` and
        ``log_level`` is ``"info"`` or ``"error"``.
    """

    if df is None:
        raise ValueError("DataFrame is required")

    http_str = str(export_code) if export_code is not None else ""
    http_display = http_str or "n/a"

    if "smartlead_export_status" not in df.columns:
        df["smartlead_export_status"] = ""
    if "smartlead_export_http" not in df.columns:
        df["smartlead_export_http"] = ""
    if "smartlead_export_error" not in df.columns:
        df["smartlead_export_error"] = ""

    if export_success:
        df.loc[eligible_mask, "smartlead_export_status"] = "OK"
        df.loc[eligible_mask, "smartlead_export_http"] = http_str
        df.loc[eligible_mask, "smartlead_export_error"] = ""
        message = f"Smartlead export triggered for {len(eligible_uids)} mailbox(es)."
        return df, message, http_display, "success", "info", True

    df.loc[eligible_mask, "smartlead_export_status"] = "ERR"
    df.loc[eligible_mask, "smartlead_export_http"] = http_str
    df.loc[eligible_mask, "smartlead_export_error"] = export_error or "Unknown error"
    message = f"Smartlead export failed: {export_error or 'Unknown error'}"
    return df, message, http_display, "error", "error", False
