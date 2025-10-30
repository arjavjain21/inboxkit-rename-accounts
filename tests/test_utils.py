import pandas as pd

from utils import annotate_skip_statuses


def test_annotate_skip_statuses_creates_and_updates_columns():
    df = pd.DataFrame(
        {
            "email": ["a@example.com", "b@example.com"],
            "uid": ["UID-1", ""],
        }
    )

    mask = df["uid"].eq("")
    result = annotate_skip_statuses(df.copy(), mask, "Skipped: no mailbox UID provided.")

    skipped_row = result.loc[1]
    assert skipped_row["update_status"] == "Skipped"
    assert skipped_row["update_http"] == ""
    assert skipped_row["update_error"] == "Skipped: no mailbox UID provided."
    assert skipped_row["forwarding_status"] == "Skipped"
    assert skipped_row["smartlead_export_status"] == "Skipped"


def test_annotate_skip_statuses_subset_columns():
    df = pd.DataFrame(
        {
            "email": ["a@example.com", "b@example.com"],
            "forwarding_status": ["", ""],
        }
    )

    mask = pd.Series([False, True], index=df.index)
    result = annotate_skip_statuses(
        df.copy(),
        mask,
        "Skipped: no domain UID provided.",
        columns=("forwarding", "smartlead"),
    )

    skipped_row = result.loc[1]
    assert skipped_row["forwarding_status"] == "Skipped"
    assert skipped_row["forwarding_error"] == "Skipped: no domain UID provided."
    assert skipped_row["smartlead_export_status"] == "Skipped"
    assert skipped_row["smartlead_export_error"] == "Skipped: no domain UID provided."
    # Update columns should not be created when not requested.
    assert "update_status" not in result.columns
