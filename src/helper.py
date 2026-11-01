# Copyright (c) 2021-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""HTTP and response helpers for the Zoom API."""

import time
from html.parser import HTMLParser
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from .consts import (
    DEFAULT_TIMEOUT,
    GET_TOKEN_URL,
    INVALID_TOKEN_CODES,
    INVALID_TOKEN_MESSAGES,
)


logger = getLogger()


class _TextExtractor(HTMLParser):
    """Extract readable text while omitting script and navigation content."""

    _SKIP_TAGS = {"script", "style", "footer", "nav"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._SKIP_TAGS:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP_TAGS and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip_depth and data.strip():
            self.parts.append(data.strip())


class ZoomHelper:
    """Make authenticated requests to the Zoom REST API."""

    def __init__(self, asset) -> None:
        self.asset = asset
        self.base_url = asset.base_url.rstrip("/")
        self._token: str | None = None

    @staticmethod
    def encode_path_segment(value: str, parameter_name: str) -> str:
        value = str(value)
        if not value or value == "." or ".." in value or any(character in value for character in ("/", "\\", "?", "#")):
            raise ActionFailure(f"{parameter_name} contains invalid path characters")
        return quote(value, safe="")

    @staticmethod
    def without_secret_parameters(params, *secret_names: str) -> dict:
        safe_params = dict(params)
        for secret_name in secret_names:
            safe_params.pop(secret_name, None)
        return safe_params

    @staticmethod
    def without_meeting_credentials(response: dict) -> dict:
        safe_response = dict(response)
        for field_name in ("password", "h323_password", "pstn_password", "encrypted_password"):
            safe_response.pop(field_name, None)
        for field_name in ("join_url", "start_url"):
            value = safe_response.get(field_name)
            if not value:
                continue
            parsed = urlsplit(value)
            query = urlencode([(key, query_value) for key, query_value in parse_qsl(parsed.query) if key.lower() != "pwd"])
            safe_response[field_name] = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))
        return safe_response

    @staticmethod
    def _error_message(response) -> str:

        try:
            payload = response.json()
        except ValueError:
            payload = None
        if isinstance(payload, dict):
            return (
                f"Error from server. Status Code: {response.status_code} Data from server: {response.text.replace('{', '{{').replace('}', '}}')}"
            )
        content_type = response.headers.get("Content-Type", "").lower()
        if "html" in content_type:
            parser = _TextExtractor()
            try:
                parser.feed(response.text)
                message = "\n".join(parser.parts) or "Cannot parse error details"
            except Exception:
                message = "Cannot parse error details"
            return f"Status Code: {response.status_code}. Data from server:\n{message}\n"
        if response.text:
            return f"Can't process response from server. Status Code: {response.status_code} Data from server: {response.text.replace('{', '{{').replace('}', '}}')}"
        return f"Status code: {response.status_code}. Empty response and no information in the header"

    def _get_token(self, force_renew: bool = False) -> str:
        import httpx

        state = dict(self.asset.auth_state.get_all())
        cached_token = state.get("zoom_access_token")
        expires_at = state.get("zoom_access_token_expires_at", 0)
        if not force_renew and cached_token and expires_at > time.time() + 30:
            self._token = cached_token
            return cached_token
        try:
            response = httpx.post(
                GET_TOKEN_URL,
                auth=(self.asset.client_id, self.asset.client_secret),
                params={"grant_type": "account_credentials", "account_id": self.asset.account_id},
                timeout=DEFAULT_TIMEOUT,
            )
        except httpx.HTTPError as exc:
            raise ActionFailure(f"Error connecting to server. Error Message: {exc}") from exc
        try:
            payload = response.json()
        except ValueError as exc:
            raise ActionFailure(f"Unable to parse JSON response. Error Message: {exc}") from exc
        if response.status_code >= 399:
            raise ActionFailure(self._error_message(response))
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not token:
            raise ActionFailure("Zoom OAuth response did not contain an access token")
        self._token = token
        expires_in = payload.get("expires_in", 3600)
        try:
            expires_at = time.time() + max(int(expires_in), 0)
        except (TypeError, ValueError):
            expires_at = time.time() + 3600
        state["zoom_access_token"] = token
        state["zoom_access_token_expires_at"] = expires_at
        self.asset.auth_state.put_all(state)
        return token

    def _request(self, endpoint: str, method: str, params=None, json=None, force_renew: bool = False) -> dict:
        import httpx

        token = self._get_token(force_renew=force_renew)
        url = f"{self.base_url}{endpoint}"
        for attempt in range(2):
            try:
                response = httpx.request(
                    method.upper(),
                    url,
                    params=params,
                    json=json,
                    headers={"Authorization": f"Bearer {token}", "content-type": "application/json"},
                    timeout=DEFAULT_TIMEOUT,
                )
            except httpx.HTTPError as exc:
                raise ActionFailure(f"Error connecting to server. Error Message: {exc}") from exc
            if response.status_code == 204:
                return {}
            try:
                payload = response.json()
            except ValueError as exc:
                if response.status_code >= 399:
                    raise ActionFailure(self._error_message(response)) from exc
                raise ActionFailure(f"Unable to parse JSON response. Error Message: {exc}") from exc
            if (
                attempt == 0
                and isinstance(payload, dict)
                and payload.get("code") in INVALID_TOKEN_CODES
                and payload.get("message", "") in INVALID_TOKEN_MESSAGES
            ):
                logger.debug("Zoom access token expired; requesting a new token")
                token = self._get_token()
                continue
            if response.status_code >= 399:
                raise ActionFailure(self._error_message(response))
            if not isinstance(payload, dict):
                raise ActionFailure("Zoom API returned an unexpected response")
            return payload
        raise ActionFailure("Zoom API access token remained invalid after refresh")

    def make_rest_call(self, endpoint: str, method: str = "get", params=None, data=None, force_renew: bool = False) -> dict:
        return self._request(endpoint, method=method, params=params, json=data, force_renew=force_renew)


def _get_password(password: str | None, generate_password: bool | None) -> str | None:
    if generate_password:
        from password_generator import PasswordGenerator

        generator = PasswordGenerator()
        generator.maxlen = 10
        return generator.generate()
    return password


def _is_setting_selected(value: str | None) -> bool:
    return value is not None and value != "None"
