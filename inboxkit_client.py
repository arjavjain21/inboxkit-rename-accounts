from typing import Any, Dict, Optional, Tuple, List
import os
import requests
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

class InboxKitError(Exception):
    pass

class InboxKitClient:
    """
    Minimal client for InboxKit API with resilient calls.
    """
    def __init__(self, base_url: Optional[str] = None, bearer: Optional[str] = None, workspace_id: Optional[str] = None, uid_lookup_mode: Optional[str] = None):
        self.base_url = (base_url or os.getenv("INBOXKIT_BASE_URL") or "https://api.inboxkit.com").rstrip("/")
        self.bearer = bearer or os.getenv("INBOXKIT_BEARER")
        self.workspace_id = workspace_id or os.getenv("INBOXKIT_WORKSPACE_ID")
        self.uid_lookup_mode = (uid_lookup_mode or os.getenv("INBOXKIT_UID_LOOKUP_MODE") or "auto").lower()
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

    def _find_uid_in_mailboxes(self, data: Any, username: str, domain: str) -> Optional[str]:
        """Attempt to locate the UID for the given username/domain within a mailboxes array."""
        target_username = (username or "").strip().lower()
        target_domain = (domain or "").strip().lower()

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
            return None

        for mailbox in mailboxes:
            if not isinstance(mailbox, dict):
                continue
            entry_username = str(mailbox.get("username", "")).strip().lower()
            entry_domain = str(mailbox.get("domain_name", "")).strip().lower()
            if entry_username == target_username and entry_domain == target_domain:
                uid = mailbox.get("uid")
                if isinstance(uid, str) and uid:
                    return uid
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
                    payload = {"page": 1, "limit": 1, "keyword": username, "domain": domain}
                    resp = self._request("POST", "/v1/api/mailboxes/list", json=payload)
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
                if mode == "list":
                    matched_uid = self._find_uid_in_mailboxes(data, username, domain)
                    if matched_uid:
                        return matched_uid, None, resp.status_code
                    tried.append((mode, f"No mailbox matching {email} in list response", resp.status_code))
                    continue

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

    def update_domain_forwarding(self, domain_uid: str, forwarding: Dict[str, Any]) -> Tuple[bool, Optional[str], Optional[int]]:
        """Update domain forwarding settings via /v1/api/domains/forwarding."""
        if not domain_uid or not isinstance(domain_uid, str):
            return False, "Domain UID is required", None
        if not isinstance(forwarding, dict):
            return False, "Forwarding payload must be a dictionary", None

        forwarding_copy: Dict[str, Any] = dict(forwarding)
        raw_uids = forwarding_copy.get("uids")
        if raw_uids is None:
            return False, "Forwarding payload must include mailbox UIDs", None
        if not isinstance(raw_uids, list):
            return False, "UIDs must be provided as a list", None
        cleaned_uids = [str(uid).strip() for uid in raw_uids if str(uid).strip()]
        if not cleaned_uids:
            return False, "At least one mailbox UID is required", None
        forwarding_copy["uids"] = cleaned_uids

        payload: Dict[str, Any] = {"uid": domain_uid}
        payload.update(forwarding_copy)

        try:
            resp = self._request("POST", "/v1/api/domains/forwarding", json=payload)
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
