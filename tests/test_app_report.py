from pathlib import Path
import sys

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import build_final_report


def test_build_final_report_uses_updated_username_for_new_email():
    df = pd.DataFrame(
        [
            {
                "input_email": "old@example.com",
                "email": "old@example.com",
                "domain": "example.com",
                "user_name": "new",
                "update_status": "OK",
            }
        ]
    )

    report = build_final_report(df)

    assert list(report["new_email"]) == ["new@example.com"]


def test_build_final_report_keeps_original_email_when_update_fails():
    df = pd.DataFrame(
        [
            {
                "input_email": "old@example.com",
                "email": "old@example.com",
                "domain": "example.com",
                "user_name": "new",
                "update_status": "ERR",
            }
        ]
    )

    report = build_final_report(df)

    assert list(report["new_email"]) == ["old@example.com"]
