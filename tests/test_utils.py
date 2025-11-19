import pandas as pd

from utils import (
    annotate_skip_statuses,
    apply_smartlead_export_outcome,
    evaluate_smartlead_export,
)


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


def test_evaluate_smartlead_export_ready_message_and_uids():
    eligible_uids, ready, message, level = evaluate_smartlead_export(
        forwarding_success=True,
        updates_ok=True,
        mailbox_uids=["UID-1", "", "UID-2", "UID-1"],
    )

    assert eligible_uids == ["UID-1", "UID-2"]
    assert ready is True
    assert "Export Inboxes" in message
    assert level == "info"


def test_evaluate_smartlead_export_skips_when_no_uids():
    eligible_uids, ready, message, level = evaluate_smartlead_export(
        forwarding_success=True,
        updates_ok=True,
        mailbox_uids=["", " ", None],
    )

    assert eligible_uids == []
    assert ready is False
    assert message == "Smartlead export skipped: no mailbox UIDs available."
    assert level == "info"


def test_evaluate_smartlead_export_skip_due_to_forwarding_errors():
    _, ready, message, level = evaluate_smartlead_export(
        forwarding_success=False,
        updates_ok=True,
        mailbox_uids=["UID-1"],
    )

    assert ready is False
    assert message == "Smartlead export skipped due to forwarding errors."
    assert level == "warning"


def test_apply_smartlead_export_outcome_success_updates_columns():
    df = pd.DataFrame(
        {
            "uid": ["UID-1", "UID-2", "UID-3"],
            "smartlead_export_status": ["", "", ""],
            "smartlead_export_http": ["", "", ""],
            "smartlead_export_error": ["", "", ""],
        }
    )
    mask = pd.Series([True, True, False])

    (
        updated,
        message,
        http_display,
        severity,
        log_level,
        done,
    ) = apply_smartlead_export_outcome(
        df,
        mask,
        ["UID-1", "UID-2"],
        export_success=True,
        export_error=None,
        export_code=202,
    )

    assert updated.loc[mask, "smartlead_export_status"].eq("OK").all()
    assert updated.loc[mask, "smartlead_export_http"].eq("202").all()
    assert updated.loc[mask, "smartlead_export_error"].eq("").all()
    assert message == "Smartlead export triggered for 2 mailbox(es)."
    assert http_display == "202"
    assert severity == "success"
    assert log_level == "info"
    assert done is True


def test_apply_smartlead_export_outcome_failure_records_error():
    df = pd.DataFrame(
        {
            "uid": ["UID-1", "UID-2"],
            "smartlead_export_status": ["", ""],
            "smartlead_export_http": ["", ""],
            "smartlead_export_error": ["", ""],
        }
    )
    mask = pd.Series([True, False])

    (
        updated,
        message,
        http_display,
        severity,
        log_level,
        done,
    ) = apply_smartlead_export_outcome(
        df,
        mask,
        ["UID-1"],
        export_success=False,
        export_error="Boom",
        export_code=500,
    )

    assert updated.loc[0, "smartlead_export_status"] == "ERR"
    assert updated.loc[0, "smartlead_export_http"] == "500"
    assert updated.loc[0, "smartlead_export_error"] == "Boom"
    assert message == "Smartlead export failed: Boom"
    assert http_display == "500"
    assert severity == "error"
    assert log_level == "error"
    assert done is False


def test_manual_skip_keeps_export_columns_blank():
    df = pd.DataFrame(
        {
            "uid": ["UID-1"],
            "smartlead_export_status": [""],
            "smartlead_export_http": [""],
            "smartlead_export_error": [""],
        }
    )

    _, ready, message, _ = evaluate_smartlead_export(
        forwarding_success=True,
        updates_ok=True,
        mailbox_uids=df["uid"].tolist(),
    )

    assert ready is True
    assert "Export Inboxes" in message
    assert df["smartlead_export_status"].eq("").all()
    assert df["smartlead_export_http"].eq("").all()
    assert df["smartlead_export_error"].eq("").all()
