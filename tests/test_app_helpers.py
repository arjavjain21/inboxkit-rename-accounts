from pathlib import Path
import sys

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import (
    _categorize_row,
    _collect_exportable_uids,
    _compose_new_email,
    _detect_column,
    _human_yes_no,
    _ordered_columns,
    _safe_select_index,
    build_final_report,
    collect_run_results,
)


def test_ordered_columns_preserves_preference_and_appends_extras():
    df = pd.DataFrame(columns=["uid", "email", "extra", "domain_uid", "uid_status"])

    ordered = _ordered_columns(df)

    assert ordered[:4] == ["email", "uid", "uid_status", "domain_uid"]
    assert ordered[-1] == "extra"


def test_detect_column_matches_aliases_and_ignores_case_spacing():
    df = pd.DataFrame(columns=["Email Address", "First Name"])

    detected = _detect_column(df, {"email", "emailaddress"})

    assert detected == "Email Address"


def test_detect_column_handles_forwarding_url_variants():
    df = pd.DataFrame(columns=["Forwarding_URL", "Other"])

    detected = _detect_column(df, {"forwardingurl", "forwardingto"})

    assert detected == "Forwarding_URL"


def test_safe_select_index_prefers_existing_option_or_defaults():
    options = ["a", "b", "c"]

    assert _safe_select_index(options, "b") == 1
    assert _safe_select_index(options, "missing") == 0


def test_collect_exportable_uids_filters_and_deduplicates_ok_updates():
    df = pd.DataFrame(
        {
            "uid": ["123", "", "123", "456"],
            "update_status": ["OK", "OK", "ERR", "OK"],
        }
    )

    uids = _collect_exportable_uids(df)

    assert uids == ["123", "456"]


def test_human_yes_no_interprets_ok_only():
    assert _human_yes_no("ok") == "yes"
    assert _human_yes_no("ERR") == "no"
    assert _human_yes_no("") == "no"


def test_compose_new_email_uses_user_name_after_successful_update():
    row = pd.Series(
        {
            "email": "old@example.com",
            "input_email": "old@example.com",
            "user_name": "NewName",
            "domain": "example.com",
            "update_status": "OK",
        }
    )

    composed = _compose_new_email(row)

    assert composed == "newname@example.com"

    row["update_status"] = "ERR"
    assert _compose_new_email(row) == "old@example.com"


def test_build_final_report_summarizes_changes_and_uses_fallback_input_email():
    df = pd.DataFrame(
        {
            "input_email": ["user@example.com"],
            "uid": ["1"],
            "domain_uid": ["10"],
            "forwarding_url": ["https://example.com"],
            "update_status": ["OK"],
            "update_http": [200],
            "forwarding_status": ["ERR_FORWARD"],
            "forwarding_http": [500],
            "forwarding_error": ["bad"],
            "smartlead_export_status": [""],
        }
    )

    report = build_final_report(df)

    assert report.loc[0, "new_email"] == "user@example.com"
    assert report.loc[0, "changes_done"] == "Mailbox updated; Forwarding failed: bad"
    assert report.loc[0, "updated_forwarding_status"] == "no"


def test_categorize_row_and_collect_run_results_classify_outcomes():
    df = pd.DataFrame(
        {
            "email": ["a@example.com", "b@example.com", "c@example.com"],
            "uid": ["1", "2", "3"],
            "update_status": ["OK", "ERR_UPDATE", ""],
            "forwarding_status": ["", "", "SKIP"],
            "smartlead_export_status": ["", "OK", ""],
        }
    )

    results = collect_run_results(df)

    assert list(results["result"]) == ["success", "fail", "skipped"]
