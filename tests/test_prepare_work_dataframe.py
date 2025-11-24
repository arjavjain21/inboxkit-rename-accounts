from pathlib import Path
import sys

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import _prepare_work_dataframe


def test_prepare_work_dataframe_sets_user_name_from_column():
    df = pd.DataFrame(
        [
            {
                "email": "old@example.com",
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
    )

    assert list(work["user_name"]) == ["preferred"]


def test_prepare_work_dataframe_leaves_user_name_blank_when_missing():
    df = pd.DataFrame([
        {
            "email": "old@example.com",
        }
    ])

    work = _prepare_work_dataframe(df, "email", None, None, None, None)

    assert list(work["user_name"]) == [""]


def test_prepare_work_dataframe_preserves_user_column_even_when_named_username():
    df = pd.DataFrame(
        [
            {
                "email": "someone@example.com",
                "username": "new-login",
            }
        ]
    )

    work = _prepare_work_dataframe(
        df,
        "email",
        None,
        None,
        "username",
        None,
    )

    assert list(work["user_name"]) == ["new-login"]
    assert list(work["username"]) == ["someone"]


def test_prepare_work_dataframe_preserves_forwarding_column_when_named_forwarding_url():
    df = pd.DataFrame(
        [
            {
                "email": "someone@example.com",
                "forwarding_url": "https://forward.example.com/ ",
            }
        ]
    )

    work = _prepare_work_dataframe(
        df,
        "email",
        None,
        None,
        None,
        "forwarding_url",
    )

    assert list(work["forwarding_url"]) == ["https://forward.example.com/"]
