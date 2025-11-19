from pathlib import Path
import sys

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import _prepare_work_dataframe


def test_prepare_work_dataframe_extracts_username_from_new_email_column():
    df = pd.DataFrame(
        [
            {
                "email": "old@example.com",
                "new_email": "renamed@example.com",
            }
        ]
    )

    work = _prepare_work_dataframe(df, "email", None, None, None, None, "new_email")

    assert list(work["user_name"]) == ["renamed"]


def test_prepare_work_dataframe_keeps_explicit_username_over_new_email():
    df = pd.DataFrame(
        [
            {
                "email": "old@example.com",
                "new_email": "renamed@example.com",
                "custom_username": "preferred",
            }
        ]
    )

    work = _prepare_work_dataframe(
        df,
        "email",
        None,
        None,
        "custom_username",
        None,
        "new_email",
    )

    assert list(work["user_name"]) == ["preferred"]
