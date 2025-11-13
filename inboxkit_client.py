from typing import Any, Dict, Optional, Tuple, List, Sequence, Iterable
import os
import requests
import logging
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

class InboxKitError(Exception):
    pass

class InboxKitClient:
    """
    Minimal client for InboxKit API with resilient calls.
    """
    SMARTLEAD_SEQUENCER_UID = "33d23a0a-e5fc-42b6-93ae-49775fac3a40"

    def __init__(
        self,
        base_url: Optional[str] = None,
        bearer: Optional[str] = None,
        workspace_id: Optional[str] = None,
        uid_lookup_mode: Optional[str] = None,
        mailbox_list_limit: Optional[int] = None,
    ):
        self._logger = logging.getLogger(__name__)
        self.base_url = (base_url or os.getenv("INBOXKIT_BASE_URL") or "https://api.inboxkit.com").rstrip("/")
        self.bearer = bearer or os.getenv("INBOXKIT_BEARER")
        self.workspace_id = workspace_id or os.getenv("INBOXKIT_WORKSPACE_ID")
        self.uid_lookup_mode = (uid_lookup_mode or os.getenv("INBOXKIT_UID_LOOKUP_MODE") or "auto").lower()
        limit_value = mailbox_list_limit
        if limit_value is None:
            env_limit = os.getenv("INBOXKIT_MAILBOX_LIST_LIMIT")
            limit_value = env_limit if env_limit is not None else 100000
        try:
            parsed_limit = int(limit_value)
        except (TypeError, ValueError):
            raise InboxKitError("Mailbox list limit must be an integer between 1 and 100000")
        if not 1 <= parsed_limit <= 100000:
            raise InboxKitError("Mailbox list limit must be between 1 and 100000")
        self.mailbox_list_limit = parsed_limit
        self._domain_uid_cache: Dict[str, str] = {}
        if not self.bearer or not self.workspace_id:
            raise InboxKitError("Missing credentials. Set INBOXKIT_BEARER and INBOXKIT_WORKSPACE_ID as environment variables or Streamlit secrets.")

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.bearer}",
            "X-Workspace-Id": self.workspace_id,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    @retry(reraise=True, stop=stop_after_attempt(3), wait=wait_exponential(multiplier=0.5, min=0.5, max=4), retry=retry_if_exception_type(requests.RequestException))
    def _request(self, method: str, path: str, *, params: Optional[Dict[str, Any]] = None, json: Optional[Dict[str, Any]] = None) -> requests.Response:
        url = f"{self.base_url}{path}"
        resp = requests.request(method, url, headers=self._headers(), params=params, json=json, timeout=30)
        if resp.status_code >= 500:
            # Raise to trigger retry
            resp.raise_for_status()
        return resp

    # Heuristic parser to extract a UID from an arbitrary JSON payload.
    def _extract_uid(self, data: Any) -> Optional[str]:
        if data is None:
            return None
        if isinstance(data, dict):
            if "uid" in data and isinstance(data["uid"], str) and data["uid"]:
                return data["uid"]
            # common nested shapes
            for key in ("data", "result", "mailbox", "mailboxes", "items", "records"):
                if key in data:
                    found = self._extract_uid(data[key])
                    if found:
                        return found
            # search all values
            for v in data.values():
                found = self._extract_uid(v)
                if found:
                    return found
        elif isinstance(data, list):
            for item in data:
                found = self._extract_uid(item)
                if found:
                    return found
        return None

    def _extract_mailboxes(self, data: Any) -> List[Dict[str, Any]]:
        def locate_mailboxes(payload: Any) -> Optional[List[Dict[str, Any]]]:
            if payload is None:
                return None
            if isinstance(payload, dict):
                mailboxes = payload.get("mailboxes")
                if isinstance(mailboxes, list):
                    return mailboxes
                for value in payload.values():
                    nested = locate_mailboxes(value)
                    if nested is not None:
                        return nested
            elif isinstance(payload, list):
                for item in payload:
                    nested = locate_mailboxes(item)
                    if nested is not None:
                        return nested
            return None

        mailboxes = locate_mailboxes(data)
        if not mailboxes:
            return []
        return [entry for entry in mailboxes if isinstance(entry, dict)]

    def _find_uid_in_mailboxes(self, data: Any, username: str, domain: str) -> Optional[str]:
        """Attempt to locate the UID for the given username/domain within a mailboxes array."""
        target_username = (username or "").strip().lower()
        target_domain = (domain or "").strip().lower()

        mailboxes = self._extract_mailboxes(data)
        if not mailboxes:
            return None

        domain_keys: Sequence[str] = ("domain_name", "domain", "domainName")

        for mailbox in mailboxes:
            entry_username = str(mailbox.get("username", "")).strip().lower()
            entry_domain = ""
            for key in domain_keys:
                value = mailbox.get(key)
                if isinstance(value, str) and value.strip():
                    entry_domain = value.strip().lower()
                    break
            if entry_username == target_username and entry_domain == target_domain:
                uid = mailbox.get("uid")
                if isinstance(uid, str) and uid:
                    return uid
        return None

    def _determine_next_page(
        self,
        current_page: int,
        payload: Any,
        mailboxes: Sequence[Dict[str, Any]],
        limit: int,
    ) -> Optional[int]:
        def extract_int(value: Any) -> Optional[int]:
            if isinstance(value, int):
                return value
            if isinstance(value, str) and value.isdigit():
                return int(value)
            return None

        pagination = payload.get("pagination") if isinstance(payload, dict) else None
        if isinstance(pagination, dict):
            next_page = extract_int(pagination.get("next_page") or pagination.get("next"))
            if next_page and next_page > current_page:
                return next_page
            has_more = pagination.get("has_more") or pagination.get("has_next")
            if has_more:
                return current_page + 1
            total_pages = extract_int(pagination.get("total_pages") or pagination.get("pages"))
            current = extract_int(pagination.get("page") or pagination.get("current_page"))
            if total_pages and current and total_pages > current:
                return current + 1

        if isinstance(payload, dict):
            direct_next = extract_int(payload.get("next_page"))
            if direct_next and direct_next > current_page:
                return direct_next
            if payload.get("has_more") is True:
                return current_page + 1

        if mailboxes and len(mailboxes) >= limit:
            return current_page + 1

        return None

    def _find_domain_uid(self, data: Any, domain: str) -> Optional[str]:
        """Locate a domain UID for the provided domain name inside the payload."""
        target_domain = (domain or "").strip().lower()
        if not target_domain:
            return None

        def match_domain(entry: Dict[str, Any]) -> Optional[str]:
            if not isinstance(entry, dict):
                return None
            domain_values: List[str] = []
            for key in ("domain_name", "domain", "name"):
                value = entry.get(key)
                if isinstance(value, str):
                    domain_values.append(value.strip().lower())
            for value in domain_values:
                if value == target_domain:
                    uid = entry.get("uid") or entry.get("domain_uid")
                    if isinstance(uid, str) and uid:
                        return uid
            return None

        def walk(payload: Any) -> Optional[str]:
            if payload is None:
                return None
            if isinstance(payload, dict):
                matched = match_domain(payload)
                if matched:
                    return matched
                for key in ("domains", "items", "data", "results", "records"):
                    if key in payload:
                        found = walk(payload[key])
                        if found:
                            return found
                for value in payload.values():
                    found = walk(value)
                    if found:
                        return found
            elif isinstance(payload, list):
                for item in payload:
                    found = walk(item)
                    if found:
                        return found
            return None

        return walk(data)

    def find_uid_by_email(self, email: str, username: str, domain: str) -> Tuple[Optional[str], Optional[str], Optional[int]]:
        """
        Attempt to find a mailbox UID by trying a few probable endpoints.
        Returns (uid, error_message, status_code).
        """
        tried: List[Tuple[str, str, Optional[int]]] = []  # (path, error, status)
        modes = [self.uid_lookup_mode] if self.uid_lookup_mode != "auto" else ["email", "search", "list"]
        for mode in modes:
            try:
                if mode == "email":
                    # Hypothetical endpoint
                    resp = self._request("GET", "/v1/api/mailboxes/find", params={"email": email})
                elif mode == "search":
                    # Hypothetical search endpoint
                    resp = self._request("GET", "/v1/api/mailboxes/search", params={"keyword": username, "domain": domain})
                elif mode == "list":
                    page = 1
                    limit = self.mailbox_list_limit
                    last_status = None
                    while True:
                        payload = {"page": page, "limit": limit, "keyword": username, "domain": domain}
                        resp = self._request("POST", "/v1/api/mailboxes/list", json=payload)
                        last_status = resp.status_code

                        if resp.status_code == 401:
                            return None, "Unauthorized. Check Bearer token.", resp.status_code
                        if resp.status_code == 404:
                            break
                        if resp.status_code >= 400:
                            tried.append((mode, f"HTTP {resp.status_code}: {resp.text[:200]}", resp.status_code))
                            break

                        data = None
                        try:
                            data = resp.json()
                        except Exception:
                            return None, "Invalid JSON from UID lookup", resp.status_code

                        matched_uid = self._find_uid_in_mailboxes(data, username, domain)
                        if matched_uid:
                            return matched_uid, None, resp.status_code

                        mailboxes = self._extract_mailboxes(data)
                        next_page = self._determine_next_page(page, data, mailboxes, limit)
                        if not next_page or next_page <= page:
                            break
                        page = next_page

                    tried.append((mode, f"No mailbox matching {email} in list response", last_status))
                    continue
                else:
                    return None, f"Invalid UID lookup mode: {mode}", None

                if resp.status_code == 401:
                    return None, "Unauthorized. Check Bearer token.", resp.status_code
                if resp.status_code == 404:
                    tried.append((mode, "Not found", resp.status_code))
                    continue
                if resp.status_code >= 400:
                    tried.append((mode, f"HTTP {resp.status_code}: {resp.text[:200]}", resp.status_code))
                    continue

                data = None
                try:
                    data = resp.json()
                except Exception:
                    return None, "Invalid JSON from UID lookup", resp.status_code

                uid = self._extract_uid(data)
                if uid:
                    return uid, None, resp.status_code
                tried.append((mode, "UID not present in response", resp.status_code))
            except requests.RequestException as e:
                tried.append((mode, f"Network error: {str(e)}", None))
                continue

        err_summary = "; ".join([f"{m}: {e}" for m, e, _ in tried])
        return None, f"UID lookup failed after trying modes: {err_summary}", None

    def update_mailbox(self, uid: str, first_name: Optional[str] = None, last_name: Optional[str] = None, user_name: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[int]]:
        payload: Dict[str, Any] = {"uid": uid}
        if first_name:
            payload["first_name"] = first_name
        if last_name:
            payload["last_name"] = last_name
        if user_name:
            payload["user_name"] = user_name

        resp = self._request("POST", "/v1/api/mailboxes/update", json=payload)
        if resp.status_code == 401:
            return False, "Unauthorized. Check Bearer token.", resp.status_code
        if resp.status_code == 404:
            return False, "Mailbox not found", resp.status_code
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except Exception:
                body = {"message": resp.text[:200]}
            msg = body.get("message") or body.get("error") or str(body)
            return False, f"HTTP {resp.status_code}: {msg}", resp.status_code
        return True, None, resp.status_code

    def get_domain_uid(self, domain: str) -> Tuple[Optional[str], Optional[str], Optional[int]]:
        """Resolve a domain UID via /v1/api/domains/list with simple caching."""
        normalized = (domain or "").strip().lower()
        if not normalized:
            return None, "Domain name is required", None
        cached = self._domain_uid_cache.get(normalized)
        if cached:
            return cached, None, None

        payload = {"page": 1, "limit": 1, "keyword": domain}
        try:
            resp = self._request("POST", "/v1/api/domains/list", json=payload)
        except requests.RequestException as e:
            return None, f"Network error: {str(e)}", None

        if resp.status_code == 401:
            return None, "Unauthorized. Check Bearer token.", resp.status_code
        if resp.status_code == 404:
            return None, "Domain not found", resp.status_code
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except Exception:
                body = {"message": resp.text[:200]}
            msg = body.get("message") or body.get("error") or str(body)
            return None, f"HTTP {resp.status_code}: {msg}", resp.status_code

        try:
            data = resp.json()
        except Exception:
            return None, "Invalid JSON from domain lookup", resp.status_code

        uid = self._find_domain_uid(data, normalized)
        if uid:
            self._domain_uid_cache[normalized] = uid
            return uid, None, resp.status_code
        return None, f"Domain {domain} not found in response", resp.status_code

    def update_domain_forwarding(self, domain_uid: Any, forwarding: Dict[str, Any]) -> Tuple[bool, Optional[str], Optional[int]]:
        """Update domain forwarding settings via /v1/api/domains/forwarding."""
        if not isinstance(forwarding, dict):
            return False, "Forwarding payload must be a dictionary", None

        # Normalise domain UID(s) into a list of unique, non-empty strings.
        domain_uid_values: List[str] = []
        domain_uid_iterable: Iterable[Any]
        if isinstance(domain_uid, (list, tuple, set)):
            domain_uid_iterable = domain_uid
        else:
            domain_uid_iterable = (domain_uid,) if domain_uid is not None else tuple()

        for raw in domain_uid_iterable:
            value = "" if raw is None else str(raw).strip()
            if value and value not in domain_uid_values:
                domain_uid_values.append(value)

        if not domain_uid_values:
            return False, "Domain UID is required", None

        forwarding_copy: Dict[str, Any] = dict(forwarding)
        forwarding_copy.pop("domain_uid", None)
        forwarding_copy.pop("uids", None)

        forwarding_url = str(forwarding_copy.get("forwarding_url", "")).strip()
        if not forwarding_url:
            return False, "Forwarding URL is required", None

        forwarding_copy["forwarding_url"] = forwarding_url
        forwarding_copy["uids"] = domain_uid_values

        try:
            resp = self._request("POST", "/v1/api/domains/forwarding", json=forwarding_copy)
        except requests.RequestException as e:
            return False, f"Network error: {str(e)}", None

        if resp.status_code == 401:
            return False, "Unauthorized. Check Bearer token.", resp.status_code
        if resp.status_code == 404:
            return False, "Domain not found", resp.status_code
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except Exception:
                body = {"message": resp.text[:200]}
            msg = body.get("message") or body.get("error") or str(body)
            return False, f"HTTP {resp.status_code}: {msg}", resp.status_code
        return True, None, resp.status_code

    def export_inboxes_to_smartlead(self, mailbox_uids: Sequence[Any]) -> Tuple[bool, Optional[str], Optional[int]]:
        """Trigger export of provided mailbox UIDs to the Smartlead sequencer."""
        if mailbox_uids is None:
            return False, "Mailbox UIDs are required", None

        unique_uids: List[str] = []
        for raw in mailbox_uids:
            uid = "" if raw is None else str(raw).strip()
            if uid and uid not in unique_uids:
                unique_uids.append(uid)

        if not unique_uids:
            return False, "At least one mailbox UID is required", None

        payload = {
            "sequencer_uid": self.SMARTLEAD_SEQUENCER_UID,
            "mailbox_uids": unique_uids,
        }

        self._logger.info(
            "Exporting %s mailbox(es) to Smartlead sequencer %s", len(unique_uids), self.SMARTLEAD_SEQUENCER_UID
        )

        try:
            resp = self._request("POST", "/v1/api/sequencers/export", json=payload)
        except requests.RequestException as exc:
            error_message = f"Network error: {exc}"
            self._logger.error("Smartlead export failed: %s", error_message)
            return False, error_message, None

        if resp.status_code == 401:
            message = "Unauthorized. Check Bearer token."
            self._logger.error("Smartlead export failed: %s", message)
            return False, message, resp.status_code

        if resp.status_code == 404:
            message = "Sequencer not found"
            self._logger.error("Smartlead export failed: %s", message)
            return False, message, resp.status_code

        if resp.status_code >= 400:
            try:
                body = resp.json()
            except Exception:
                body = {"message": resp.text[:200]}
            msg = body.get("message") or body.get("error") or str(body)
            error_message = f"HTTP {resp.status_code}: {msg}"
            self._logger.error("Smartlead export failed: %s", error_message)
            return False, error_message, resp.status_code

        self._logger.info(
            "Smartlead export succeeded for %s mailbox(es) (HTTP %s)", len(unique_uids), resp.status_code
        )
        return True, None, resp.status_code
