import logging
import os
import re
from typing import Optional, Tuple
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
