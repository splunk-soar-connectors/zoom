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

"""Update User Settings action."""

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params
from ..app import Asset, app
from ..helper import ZoomHelper
from ..helper import _get_password
from ..helper import _is_setting_selected
from ..output_models import UpdateUserSettingsOutput, UpdateUserSettingsSummary

logger = getLogger()

class UpdateUserSettingsParams(Params):
    user_id: str = Param(description='Zoom user ID', required=True, primary=True, cef_types=['zoom user id'], column_name="User ID")
    req_password_pmi: str = Param(description='Require password for PMI', required=True, value_list=['None', 'True', 'False'], default='None')
    pmi_password: str | None = Param(description='User pmi password', required=False, sensitive=True, default=None)
    gen_pmi_password: bool | None = Param(description='Auto generate pmi password', required=False, default=None)
    waiting_room: str = Param(description='Enable waiting room', required=True, value_list=['None', 'True', 'False'], default='None')
    req_password_sched: str = Param(description='Require password for scheduling meetings', required=True, value_list=['None', 'True', 'False'], default='None')
    req_password_inst: str = Param(description='Require password for instant meetings', required=True, value_list=['None', 'True', 'False'], default='None')

@app.action(
    description="Update zoom user settings",
    action_type="generic",
    read_only=False,
    render_as="table",
    summary_type=UpdateUserSettingsSummary,
)
def update_user_settings(
    params: UpdateUserSettingsParams, soar: SOARClient[UpdateUserSettingsSummary], asset: Asset
) -> UpdateUserSettingsOutput:
    logger.progress("Updating Zoom user settings")
    user_id_path = ZoomHelper.encode_path_segment(params.user_id, "user_id")
    pmi_password = _get_password(params.pmi_password, params.gen_pmi_password)
    is_waiting_room_updated = _is_setting_selected(params.waiting_room)
    is_req_password_sched_updated = _is_setting_selected(params.req_password_sched)
    is_req_password_inst_updated = _is_setting_selected(params.req_password_inst)
    is_req_password_pmi_updated = _is_setting_selected(params.req_password_pmi)
    if not (pmi_password or is_waiting_room_updated or is_req_password_sched_updated or is_req_password_inst_updated or is_req_password_pmi_updated):
        raise ActionFailure("No settings were selected for update")
    data = {}
    if pmi_password or is_req_password_sched_updated or is_req_password_inst_updated or is_req_password_pmi_updated:
        data["schedule_meeting"] = {}
        if pmi_password:
            data["schedule_meeting"]["pmi_password"] = pmi_password
        if is_req_password_sched_updated:
            data["schedule_meeting"]["require_password_for_scheduling_new_meetings"] = params.req_password_sched == "True"
        if is_req_password_inst_updated:
            data["schedule_meeting"]["require_password_for_instant_meetings"] = params.req_password_inst == "True"
        if is_req_password_pmi_updated:
            data["schedule_meeting"]["require_password_for_pmi_meetings"] = "all" if params.req_password_pmi == "True" else "none"
    if is_waiting_room_updated:
        data["in_meeting"] = {"waiting_room": params.waiting_room == "True"}
    ZoomHelper(asset).make_rest_call(f"/users/{user_id_path}/settings", method="patch", data=data)
    soar.set_summary(
        UpdateUserSettingsSummary(
            waiting_room="Not Updated" if not is_waiting_room_updated else params.waiting_room,
            require_password_for_instant_meetings="Not Updated" if not is_req_password_inst_updated else params.req_password_inst,
            require_password_for_scheduling_new_meetings="Not Updated" if not is_req_password_sched_updated else params.req_password_sched,
            require_password_for_personal_meeting_instance="Not Updated" if not is_req_password_pmi_updated else params.req_password_pmi,
        )
    )
    soar.set_message(f"User {params.user_id} successfully updated")
    return UpdateUserSettingsOutput(action_status="success")
