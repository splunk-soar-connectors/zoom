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

"""Get Meeting Invitation action."""

from soar_sdk.abstract import SOARClient
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import ZoomHelper
from ..output_models import GetMeetingInvitationOutput


logger = getLogger()


class GetMeetingInvitationParams(Params):
    meeting_id: str = Param(description="Zoom meeting ID", required=True, primary=True, cef_types=["zoom meeting id"])


@app.action(description="Get zoom meeting invitation", action_type="investigate", read_only=True, render_as="table")
def get_meeting_invitation(params: GetMeetingInvitationParams, soar: SOARClient, asset: Asset) -> GetMeetingInvitationOutput:
    logger.progress("Getting Zoom meeting invitation")
    meeting_id = params.meeting_id
    meeting_id_path = ZoomHelper.encode_path_segment(meeting_id, "meeting_id")
    response = ZoomHelper(asset).make_rest_call(f"/meetings/{meeting_id_path}/invitation")
    parsed_fields = {}
    try:
        invitation = str(response.get("invitation", ""))
        for kv_pair in invitation.replace("Join Zoom Meeting\r\n", "invitation_link:").split("\r\n"):
            if kv_pair:
                parts = kv_pair.split(":")
                second_part = ":".join(parts[1:]).strip()
                if second_part:
                    parsed_fields[parts[0].lower().replace(" ", "_")] = second_part
        if parsed_fields.get("meeting_id"):
            parsed_fields["meeting_id"] = parsed_fields["meeting_id"].replace(" ", "")
    except Exception as exc:
        logger.debug(f"Error parsing invitation fields: {exc}")
        logger.progress("Could not parse invitation fields")
    response["parsed_fields"] = parsed_fields
    soar.set_message(f"Meeting invitation for id {meeting_id} successfully retrieved")
    return GetMeetingInvitationOutput(**response)
