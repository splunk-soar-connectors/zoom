# Copyright (c) 2026 Splunk Inc.
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
from src.helper import ZoomHelper
from soar_sdk.exceptions import ActionFailure


def test_encode_path_segment_encodes_reserved_characters():
    assert ZoomHelper.encode_path_segment("user@example.com", "user_id") == "user%40example.com"


def test_encode_path_segment_rejects_path_injection():
    for value in ("", ".", "..", "a/b", "a\\b", "a?b", "a#b"):
        try:
            ZoomHelper.encode_path_segment(value, "user_id")
        except ActionFailure as exc:
            assert "invalid path characters" in str(exc)
        else:
            raise AssertionError(f"Expected invalid path segment to be rejected: {value!r}")


def test_without_meeting_credentials_removes_passwords_and_pwd_query():
    response = {
        "password": "secret",
        "h323_password": "secret",
        "join_url": "https://zoom.us/j/123?pwd=secret&source=soar",
        "topic": "Review",
    }

    safe = ZoomHelper.without_meeting_credentials(response)

    assert "password" not in safe
    assert "h323_password" not in safe
    assert safe["join_url"] == "https://zoom.us/j/123?source=soar"
    assert response["password"] == "secret"
