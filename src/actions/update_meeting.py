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

"""Update Meeting action."""

from soar_sdk.abstract import SOARClient
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import ZoomHelper, _get_password
from ..output_models import UpdateMeetingOutput, UpdateMeetingSummary


logger = getLogger()


class UpdateMeetingParams(Params):
    meeting_id: str = Param(description="Zoom meeting ID", required=True, primary=True, cef_types=["zoom meeting id"], column_name="Meeting ID")
    password: str | None = Param(description="Meeting password", required=False, sensitive=True, default=None)
    gen_password: bool | None = Param(description="Auto generate meeting password", required=False, default=None)
    waiting_room: str = Param(description="Enable waiting room", required=True, value_list=["None", "True", "False"], default="None")


@app.action(
    description="Update zoom meeting",
    action_type="generic",
    read_only=False,
    render_as="table",
    summary_type=UpdateMeetingSummary,
)
def update_meeting(params: UpdateMeetingParams, soar: SOARClient[UpdateMeetingSummary], asset: Asset) -> UpdateMeetingOutput:
    logger.progress("Updating Zoom meeting")
    meeting_id_path = ZoomHelper.encode_path_segment(params.meeting_id, "meeting_id")
    password = _get_password(params.password, params.gen_password)
    if not (password or params.waiting_room != "None"):
        raise ActionFailure("Either password or waiting room must be updated")
    data = {}
    if password:
        data["password"] = password
    if params.waiting_room != "None":
        data["settings"] = {"waiting_room": params.waiting_room == "True"}
    ZoomHelper(asset).make_rest_call(f"/meetings/{meeting_id_path}", method="patch", data=data)
    soar.set_summary(
        UpdateMeetingSummary(
            meeting_updated=True,
            waiting_room="Not Updated" if params.waiting_room == "None" else params.waiting_room,
        )
    )
    soar.set_message(f"Meeting {params.meeting_id} successfully updated")
    return UpdateMeetingOutput(action_status="success")
