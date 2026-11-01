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

"""Create Meeting action."""

from soar_sdk.abstract import SOARClient
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import ZoomHelper, _get_password
from ..output_models import CreateMeetingOutput, CreateMeetingSummary


logger = getLogger()


class CreateMeetingParams(Params):
    user_id: str = Param(description="User id", required=True, primary=True, cef_types=["zoom user id", "email"], default="me")
    password: str | None = Param(description="Meeting password", required=False, sensitive=True, default=None)
    gen_password: bool | None = Param(description="Auto generate meeting password", required=False, default=None)
    waiting_room: str = Param(description="Enable waiting room", required=True, value_list=["None", "True", "False"], default="None")
    topic: str | None = Param(description="Topic of meeting", required=False, default=None)
    agenda: str | None = Param(description="Agenda of meeting", required=False, default=None)
    alternative_hosts: str | None = Param(
        description=("Comma-separated list of the meeting's alternative hosts' email addresses or IDs"), required=False, default=None
    )
    continuous_meeting_chat: bool = Param(description="Whether to enable the continuous meeting chat setting", required=False, default=False)
    auto_recording: str = Param(
        description="The automatic recording settings", required=False, value_list=["none", "cloud", "local"], default="none"
    )
    meeting_invitees: str | None = Param(description="Comma-separated list of the meeting's invitees", required=False, default=None)


@app.action(
    description="Create zoom meeting",
    action_type="generic",
    read_only=False,
    render_as="table",
    verbose="In user_id, use a user ID, email, or `me` for the current user. auto_recording sets the meeting recording destination.",
    summary_type=CreateMeetingSummary,
)
def create_meeting(params: CreateMeetingParams, soar: SOARClient[CreateMeetingSummary], asset: Asset) -> CreateMeetingOutput:
    logger.progress("Creating Zoom meeting")
    user_id_path = ZoomHelper.encode_path_segment(params.user_id, "user_id")
    password = _get_password(params.password, params.gen_password)
    data = {}
    for key, value in {"password": password, "topic": params.topic, "agenda": params.agenda}.items():
        if value:
            data[key] = value
    data["settings"] = {}
    if params.waiting_room != "None":
        data["settings"]["waiting_room"] = params.waiting_room == "True"
    if params.alternative_hosts:
        hosts = [host.strip() for host in params.alternative_hosts.split(",") if host.strip()]
        if hosts:
            data["settings"].update({"alternative_hosts": ";".join(hosts), "alternative_hosts_email_notification": True})
    data["settings"]["continuous_meeting_chat"] = {"enable": params.continuous_meeting_chat}
    if params.auto_recording:
        if params.auto_recording.lower() not in ["cloud", "none", "native"]:
            raise ActionFailure("Please enter a valid value for auto_recording from [cloud, native, none]")
        data["settings"]["auto_recording"] = params.auto_recording.lower()
    if params.meeting_invitees:
        attendees = [email.strip() for email in params.meeting_invitees.split(",") if email.strip()]
        if attendees:
            data["settings"]["meeting_invitees"] = [{"email": email} for email in attendees]
    response = ZoomHelper(asset).make_rest_call(f"/users/{user_id_path}/meetings", method="post", data=data)
    safe_response = ZoomHelper.without_meeting_credentials(response)
    summary = CreateMeetingSummary(
        meeting_id=str(response["id"]),
        meeting_created=True,
        waiting_room="Not Added" if params.waiting_room == "None" else params.waiting_room,
        alternative_hosts="Not Added" if not params.alternative_hosts else params.alternative_hosts,
        continuous_meeting_chat="Not Added" if not params.continuous_meeting_chat else str(params.continuous_meeting_chat),
        auto_recording="Not Added" if params.auto_recording and params.auto_recording.lower() == "none" else params.auto_recording,
        meeting_invitees="Not Added" if not params.meeting_invitees else params.meeting_invitees,
    )
    soar.set_summary(summary)
    soar.set_message(f"Meeting {response['id']} successfully created")
    return CreateMeetingOutput(
        meeting_id=str(response["id"]),
        action_gen_password=params.gen_password,
        action_waiting_room=params.waiting_room,
        action_topic=params.topic,
        action_agenda=params.agenda,
        action_alternative_hosts=params.alternative_hosts,
        action_continuous_meeting_chat=params.continuous_meeting_chat,
        action_auto_recording=params.auto_recording,
        action_meeting_invitees=params.meeting_invitees,
        action_status="success",
        **safe_response,
    )
