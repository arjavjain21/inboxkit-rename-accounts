import requests
from unittest import mock
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from inboxkit_client import InboxKitClient


class DummyResponse:
    def __init__(self, status_code, json_data=None, text=""):
        self.status_code = status_code
        self._json_data = json_data if json_data is not None else {}
        self.text = text

    def json(self):
        return self._json_data


@pytest.fixture
def client():
    return InboxKitClient(
        base_url="https://example.com",
        bearer="token",
        workspace_id="workspace",
        uid_lookup_mode="auto",
    )


def test_export_inboxes_success(client):
    response = DummyResponse(200, {"status": "ok"})
    with mock.patch.object(client, "_request", return_value=response) as mocked_request:
        success, error, code = client.export_inboxes_to_smartlead([
            "uid-1",
            "uid-2",
            "uid-1",
            "  uid-3  ",
        ])

    assert success is True
    assert error is None
    assert code == 200
    mocked_request.assert_called_once()
    called_args, called_kwargs = mocked_request.call_args
    assert called_args == ("POST", "/v1/api/sequencers/export")
    payload = called_kwargs["json"]
    assert payload["sequencer_uid"] == client.SMARTLEAD_SEQUENCER_UID
    assert payload["mailbox_uids"] == ["uid-1", "uid-2", "uid-3"]


def test_export_inboxes_rejects_empty_input(client):
    success, error, code = client.export_inboxes_to_smartlead([])
    assert success is False
    assert error == "At least one mailbox UID is required"
    assert code is None


def test_export_inboxes_handles_http_error(client):
    response = DummyResponse(400, {"message": "bad request"})
    with mock.patch.object(client, "_request", return_value=response):
        success, error, code = client.export_inboxes_to_smartlead(["uid-1"])

    assert success is False
    assert "HTTP 400" in error
    assert "bad request" in error
    assert code == 400


def test_export_inboxes_handles_network_error(client):
    with mock.patch.object(
        client,
        "_request",
        side_effect=requests.RequestException("timeout"),
    ):
        success, error, code = client.export_inboxes_to_smartlead(["uid-1"])

    assert success is False
    assert "Network error" in error
    assert code is None


def test_update_domain_forwarding_only_sends_domain_uids(client):
    response = DummyResponse(200, {"status": "ok"})
    with mock.patch.object(client, "_request", return_value=response) as mocked_request:
        success, error, code = client.update_domain_forwarding(
            "domain-uid",
            {
                "forwarding_url": "https://forward.example.com",
                "uids": ["mailbox-1", "mailbox-2"],
            },
        )

    assert success is True
    assert error is None
    assert code == 200
    mocked_request.assert_called_once()
    called_args, called_kwargs = mocked_request.call_args
    assert called_args == ("POST", "/v1/api/domains/forwarding")
    payload = called_kwargs["json"]
    assert payload["forwarding_url"] == "https://forward.example.com"
    assert payload["uids"] == ["domain-uid"]


def test_update_domain_forwarding_deduplicates_domains(client):
    response = DummyResponse(200, {"status": "ok"})
    with mock.patch.object(client, "_request", return_value=response) as mocked_request:
        success, error, code = client.update_domain_forwarding(
            ["domain-uid", "domain-uid  ", "another", None],
            {"forwarding_url": "https://forward.example.com"},
        )

    assert success is True
    assert error is None
    assert code == 200
    mocked_request.assert_called_once()
    payload = mocked_request.call_args[1]["json"]
    assert payload["uids"] == ["domain-uid", "another"]


def test_find_uid_by_email_pagination_miss(client):
    """Mailbox lookup fails when the paginated list omits the target mailbox."""

    list_payload = {
        "mailboxes": [
            {
                "username": "other",
                "domain_name": "example.com",
                "uid": "uid-other",
            }
        ]
    }

    responses = iter(
        [
            DummyResponse(404),  # /find 404
            DummyResponse(404),  # /search 404
            DummyResponse(200, list_payload),  # /list returns the wrong mailbox because limit=1
        ]
    )

    def fake_request(method, path, **kwargs):
        return next(responses)

    with mock.patch.object(client, "_request", side_effect=fake_request):
        uid, err, code = client.find_uid_by_email(
            "target@example.com", "target", "example.com"
        )

    assert uid is None
    assert "No mailbox matching target@example.com" in err
    assert code is None


def test_find_uid_in_mailboxes_requires_domain_name_key(client):
    """The helper ignores entries that expose `domain` instead of `domain_name`."""

    payload = {
        "mailboxes": [
            {
                "username": "target",
                "domain": "example.com",
                "uid": "uid-123",
            }
        ]
    }

    uid = client._find_uid_in_mailboxes(payload, "target", "example.com")

    assert uid is None
