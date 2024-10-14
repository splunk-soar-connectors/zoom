[comment]: # "Auto-generated SOAR connector documentation"
# Zoom

Publisher: Splunk  
Connector Version: 3.1.0  
Product Vendor: Zoom  
Product Name: Zoom Meetings  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.2.1  

The app integrates with Zoom Meetings API to perform investigative and generic actions

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2021-2024 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
### SDK and SDK Licensing details for the app

#### PyJWT

This app uses the PyJWT module, which is licensed under the MIT License (MIT), Copyright (c) Jose
Padilla.

#### random-password-generator

This app uses the random-password-generator module, which is licensed under the MIT License (MIT),
Copyright (c) Surya Teja Reddy Valluri.

### Objective

This app was created in response to a marked increase in work from home employees, which has
inevitably led to a significant rise in Zoom usage. This app provides important additional context
about meetings (e.g., was the meeting password protected, was the waiting room turned on). This app
provides security practitioners a way to ensure that security best practices are being followed with
regard to Zoom meetings.

### JWT Authentication removal details

In app v3.0.0, We have removed JWT authentication support as per [JWT deprecation guide](https://developers.zoom.us/blog/jwt-deprecation-guide/). Make sure to create zoom app based on [App configuration](#app-configurations-zoom-side) provided below.

### App Configurations (Zoom Side)

#### Server-to-Server OAuth Authentication

For the Zoom app for SOAR to be configured correctly, you must first create a Server-to-Server OAuth
app in your Zoom App Marketplace account. A Server-to-Server OAuth App can be created by going
[here](https://developers.zoom.us/docs/internal-apps/) and clicking the "Create" button under the
"Server-to-Server OAuth" app type. Once you've created your Server-to-Server OAuth app you'll be
provided with an account id, client id and client secret, keep track of these. They will be
necessary for the configuration on the SOAR side. To ensure that all actions are executed properly,
you must include the following scopes in the Server-to-Server OAuth app.

-   user:read:admin
-   user:write:admin
-   meeting:read:admin
-   meeting:write:admin

### App Configuration (Splunk> SOAR Side)

For Server-to-Server OAuth configuration of the Zoom App for Splunk> SOAR requires three fields
account id, client id and client secret which are provided by Zoom.

The last field is the "Base URL" field which is simply the base URL for the Zoom REST API. The
default value provided, "https://api.zoom/us/v2" should not need to be changed.

### Actions

Actions are all fairly simple and documented with the normal app documentation process. That said,
one of the main purposes of this app was to provide additional context about meetings that can only
be provided via the Zoom API, most notably whether or not the meetings are being password protected.

The two actions that provide information on the configuration of passwords on meetings are "get
meeting" and "get meeting invitation". These two actions will give you data that can be used to gain
insight into who is running unprotected meetings, how often, and what are the topics of those
meetings.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Zoom Meetings asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** |  required  | string | Base URL (e.g. https://api.zoom.us/v2)
**account_id** |  required  | string | Account ID (Server-to-Server OAuth)
**client_id** |  required  | string | Client ID (Server-to-Server OAuth)
**client_secret** |  required  | password | Client Secret (Server-to-Server OAuth)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[get meeting invitation](#action-get-meeting-invitation) - Get zoom meeting invitation  
[get user settings](#action-get-user-settings) - Get zoom user settings  
[get user](#action-get-user) - Get zoom user info  
[create meeting](#action-create-meeting) - Create zoom meeting  
[get meeting](#action-get-meeting) - Get zoom meeting details  
[update meeting](#action-update-meeting) - Update zoom meeting  
[delete meeting](#action-delete-meeting) - Delete zoom meeting  
[update user settings](#action-update-user-settings) - Update zoom user settings  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get meeting invitation'
Get zoom meeting invitation

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**meeting_id** |  required  | Zoom meeting ID | string |  `zoom meeting id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.meeting_id | string |  `zoom meeting id`  |   92512345678 
action_result.data.\*.invitation | string |  |  
action_result.data.\*.parsed_fields.invitation_link | string |  `url`  |  
action_result.data.\*.parsed_fields.meeting_id | string |  |  
action_result.data.\*.parsed_fields.passcode | string |  |  
action_result.data.\*.parsed_fields.time | string |  |  
action_result.data.\*.parsed_fields.topic | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get user settings'
Get zoom user settings

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** |  required  | Zoom user ID | string |  `zoom user id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.user_id | string |  `zoom user id`  |   A0BiCtoDEFGHIzYaZcLdsA 
action_result.data.\*.audio_conferencing.toll_free_and_fee_based_toll_call.enable | boolean |  |  
action_result.data.\*.email_notification.alternative_host_reminder | boolean |  |  
action_result.data.\*.email_notification.cancel_meeting_reminder | boolean |  |  
action_result.data.\*.email_notification.jbh_reminder | boolean |  |  
action_result.data.\*.email_notification.schedule_for_reminder | boolean |  |  
action_result.data.\*.feature.cn_meeting | boolean |  |  
action_result.data.\*.feature.in_meeting | boolean |  |  
action_result.data.\*.feature.large_meeting | boolean |  |  
action_result.data.\*.feature.large_meeting_capacity | numeric |  |  
action_result.data.\*.feature.meeting_capacity | numeric |  |  
action_result.data.\*.feature.webinar | boolean |  |  
action_result.data.\*.feature.webinar_capacity | numeric |  |  
action_result.data.\*.feature.zoom_customer_managed_key | boolean |  |   True  False 
action_result.data.\*.feature.zoom_events | boolean |  |  
action_result.data.\*.feature.zoom_events_consumption | string |  |   None 
action_result.data.\*.feature.zoom_events_saas | boolean |  |   True  False 
action_result.data.\*.feature.zoom_huddles | boolean |  |   True  False 
action_result.data.\*.feature.zoom_iq_for_sales | boolean |  |  
action_result.data.\*.feature.zoom_phone | boolean |  |  
action_result.data.\*.feature.zoom_quality_management | boolean |  |   True  False 
action_result.data.\*.feature.zoom_spots | boolean |  |   True  False 
action_result.data.\*.feature.zoom_translated_captions | boolean |  |   True  False 
action_result.data.\*.feature.zoom_whiteboard | boolean |  |   True  False 
action_result.data.\*.feature.zoom_whiteboard_plus | boolean |  |   True  False 
action_result.data.\*.feature.zoom_workforce_management | boolean |  |   True  False 
action_result.data.\*.in_meeting.allow_live_streaming | boolean |  |  
action_result.data.\*.in_meeting.allow_participants_chat_with | numeric |  |  
action_result.data.\*.in_meeting.allow_participants_to_rename | boolean |  |  
action_result.data.\*.in_meeting.allow_show_zoom_windows | boolean |  |  
action_result.data.\*.in_meeting.allow_users_save_chats | numeric |  |  
action_result.data.\*.in_meeting.allow_users_to_delete_messages_in_meeting_chat | boolean |  |   True  False 
action_result.data.\*.in_meeting.annotation | boolean |  |  
action_result.data.\*.in_meeting.attendee_on_hold | boolean |  |  
action_result.data.\*.in_meeting.attention_mode_focus_mode | boolean |  |  
action_result.data.\*.in_meeting.auto_answer | boolean |  |  
action_result.data.\*.in_meeting.auto_saving_chat | boolean |  |  
action_result.data.\*.in_meeting.breakout_room | boolean |  |  
action_result.data.\*.in_meeting.chat | boolean |  |  
action_result.data.\*.in_meeting.closed_caption | boolean |  |  
action_result.data.\*.in_meeting.closed_captioning.auto_transcribing | boolean |  |   True  False 
action_result.data.\*.in_meeting.closed_captioning.enable | boolean |  |  
action_result.data.\*.in_meeting.closed_captioning.save_caption | boolean |  |  
action_result.data.\*.in_meeting.closed_captioning.third_party_captioning_service | boolean |  |   True  False 
action_result.data.\*.in_meeting.closed_captioning.view_full_transcript | boolean |  |   True  False 
action_result.data.\*.in_meeting.co_host | boolean |  |  
action_result.data.\*.in_meeting.custom_live_streaming_service | boolean |  |  
action_result.data.\*.in_meeting.custom_service_instructions | string |  |  
action_result.data.\*.in_meeting.disable_screen_sharing_for_host_meetings | boolean |  |  
action_result.data.\*.in_meeting.disable_screen_sharing_for_in_meeting_guests | boolean |  |  
action_result.data.\*.in_meeting.e2e_encryption | boolean |  |  
action_result.data.\*.in_meeting.entry_exit_chime | string |  |  
action_result.data.\*.in_meeting.far_end_camera_control | boolean |  |  
action_result.data.\*.in_meeting.feedback | boolean |  |  
action_result.data.\*.in_meeting.file_transfer | boolean |  |  
action_result.data.\*.in_meeting.group_hd | boolean |  |  
action_result.data.\*.in_meeting.manual_captioning.auto_generated_captions | boolean |  |  
action_result.data.\*.in_meeting.manual_captioning.full_transcript | boolean |  |  
action_result.data.\*.in_meeting.manual_captioning.manual_captions | boolean |  |  
action_result.data.\*.in_meeting.manual_captioning.save_captions | boolean |  |  
action_result.data.\*.in_meeting.manual_captioning.third_party_captioning_service | boolean |  |   True  False 
action_result.data.\*.in_meeting.meeting_polling.enable | boolean |  |  
action_result.data.\*.in_meeting.meeting_reactions | boolean |  |  
action_result.data.\*.in_meeting.meeting_reactions_emojis | string |  |   all 
action_result.data.\*.in_meeting.non_verbal_feedback | boolean |  |  
action_result.data.\*.in_meeting.participants_share_simultaneously | string |  |   one 
action_result.data.\*.in_meeting.participants_to_place_in_waiting_room | numeric |  |  
action_result.data.\*.in_meeting.polling | boolean |  |  
action_result.data.\*.in_meeting.post_meeting_feedback | boolean |  |   True  False 
action_result.data.\*.in_meeting.private_chat | boolean |  |  
action_result.data.\*.in_meeting.record_play_voice | boolean |  |  
action_result.data.\*.in_meeting.remote_control | boolean |  |  
action_result.data.\*.in_meeting.remote_support | boolean |  |  
action_result.data.\*.in_meeting.request_permission_to_unmute_participants | boolean |  |  
action_result.data.\*.in_meeting.screen_sharing | boolean |  |  
action_result.data.\*.in_meeting.share_dual_camera | boolean |  |  
action_result.data.\*.in_meeting.show_a_join_from_your_browser_link | boolean |  |  
action_result.data.\*.in_meeting.show_meeting_control_toolbar | boolean |  |  
action_result.data.\*.in_meeting.sign_language_interpretation.enable | boolean |  |   True  False 
action_result.data.\*.in_meeting.slide_control | boolean |  |  
action_result.data.\*.in_meeting.transfer_meetings_between_devices | boolean |  |   True  False 
action_result.data.\*.in_meeting.virtual_background | boolean |  |  
action_result.data.\*.in_meeting.virtual_background_settings.allow_upload_custom | boolean |  |  
action_result.data.\*.in_meeting.virtual_background_settings.allow_videos | boolean |  |  
action_result.data.\*.in_meeting.virtual_background_settings.enable | boolean |  |  
action_result.data.\*.in_meeting.waiting_room | boolean |  |  
action_result.data.\*.in_meeting.webinar_polling.enable | boolean |  |  
action_result.data.\*.in_meeting.whiteboard | boolean |  |   True  False 
action_result.data.\*.in_meeting.who_can_share_screen | string |  |  
action_result.data.\*.in_meeting.who_can_share_screen_when_someone_is_sharing | string |  |  
action_result.data.\*.in_meeting.workplace_by_facebook | boolean |  |  
action_result.data.\*.integration.linkedin_sales_navigator | boolean |  |  
action_result.data.\*.recording.auto_delete_cmr | boolean |  |  
action_result.data.\*.recording.auto_delete_cmr_days | numeric |  |  
action_result.data.\*.recording.auto_recording | string |  |  
action_result.data.\*.recording.cloud_recording | boolean |  |  
action_result.data.\*.recording.host_pause_stop_recording | boolean |  |  
action_result.data.\*.recording.local_recording | boolean |  |  
action_result.data.\*.recording.record_audio_file | boolean |  |  
action_result.data.\*.recording.record_gallery_view | boolean |  |  
action_result.data.\*.recording.record_speaker_view | boolean |  |  
action_result.data.\*.recording.recording_audio_transcript | boolean |  |  
action_result.data.\*.recording.recording_disclaimer | boolean |  |  
action_result.data.\*.recording.recording_password_requirement.have_letter | boolean |  |  
action_result.data.\*.recording.recording_password_requirement.have_number | boolean |  |  
action_result.data.\*.recording.recording_password_requirement.have_special_character | boolean |  |  
action_result.data.\*.recording.recording_password_requirement.length | numeric |  |  
action_result.data.\*.recording.recording_password_requirement.only_allow_numeric | boolean |  |  
action_result.data.\*.recording.save_chat_text | boolean |  |  
action_result.data.\*.recording.show_timestamp | boolean |  |  
action_result.data.\*.schedule_meeting.audio_type | string |  |  
action_result.data.\*.schedule_meeting.default_password_for_scheduled_meetings | string |  |  
action_result.data.\*.schedule_meeting.embed_password_in_join_link | boolean |  |  
action_result.data.\*.schedule_meeting.force_pmi_jbh_password | boolean |  |  
action_result.data.\*.schedule_meeting.host_video | boolean |  |  
action_result.data.\*.schedule_meeting.join_before_host | boolean |  |  
action_result.data.\*.schedule_meeting.meeting_password_requirement.consecutive_characters_length | numeric |  |  
action_result.data.\*.schedule_meeting.meeting_password_requirement.have_letter | boolean |  |  
action_result.data.\*.schedule_meeting.meeting_password_requirement.have_number | boolean |  |  
action_result.data.\*.schedule_meeting.meeting_password_requirement.have_special_character | boolean |  |  
action_result.data.\*.schedule_meeting.meeting_password_requirement.have_upper_and_lower_characters | boolean |  |  
action_result.data.\*.schedule_meeting.meeting_password_requirement.length | numeric |  |  
action_result.data.\*.schedule_meeting.meeting_password_requirement.only_allow_numeric | boolean |  |  
action_result.data.\*.schedule_meeting.meeting_password_requirement.weak_enhance_detection | boolean |  |  
action_result.data.\*.schedule_meeting.mute_upon_entry | boolean |  |  
action_result.data.\*.schedule_meeting.participants_video | boolean |  |  
action_result.data.\*.schedule_meeting.personal_meeting | boolean |  |  
action_result.data.\*.schedule_meeting.pmi_password | string |  |  
action_result.data.\*.schedule_meeting.pstn_password_protected | boolean |  |  
action_result.data.\*.schedule_meeting.require_password_for_instant_meetings | boolean |  |  
action_result.data.\*.schedule_meeting.require_password_for_pmi_meetings | string |  |  
action_result.data.\*.schedule_meeting.require_password_for_scheduled_meetings | boolean |  |  
action_result.data.\*.schedule_meeting.require_password_for_scheduling_new_meetings | boolean |  |  
action_result.data.\*.schedule_meeting.use_pmi_for_instant_meetings | boolean |  |  
action_result.data.\*.schedule_meeting.use_pmi_for_scheduled_meetings | boolean |  |  
action_result.data.\*.telephony.audio_conference_info | string |  |  
action_result.data.\*.telephony.show_international_numbers_link | boolean |  |  
action_result.data.\*.telephony.third_party_audio | boolean |  |  
action_result.data.\*.tsp.call_out | boolean |  |  
action_result.data.\*.tsp.call_out_countries | string |  |  
action_result.data.\*.tsp.show_international_numbers_link | boolean |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'get user'
Get zoom user info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** |  required  | Zoom user ID | string |  `zoom user id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.user_id | string |  `zoom user id`  |  
action_result.data.\*.account_id | string |  |  
action_result.data.\*.account_number | numeric |  |  
action_result.data.\*.cluster | string |  |   us05 
action_result.data.\*.cms_user_id | string |  |  
action_result.data.\*.company | string |  |  
action_result.data.\*.created_at | string |  |  
action_result.data.\*.custom_attributes.\*.key | string |  |   examplecbf_{0}&&&&cbf_p9y_qhefsveacfrdepuvzw 
action_result.data.\*.custom_attributes.\*.name | string |  |   id 
action_result.data.\*.custom_attributes.\*.value | string |  |  
action_result.data.\*.dept | string |  |  
action_result.data.\*.display_name | string |  |   Herman Edwards 
action_result.data.\*.email | string |  `email`  |  
action_result.data.\*.first_name | string |  |  
action_result.data.\*.group_ids | string |  |  
action_result.data.\*.host_key | string |  |  
action_result.data.\*.id | string |  `zoom user id`  |   A0BiCtoDEFGHIzYaZcLdsA 
action_result.data.\*.im_group_ids | string |  |  
action_result.data.\*.jid | string |  |  
action_result.data.\*.job_title | string |  |  
action_result.data.\*.language | string |  |  
action_result.data.\*.last_client_version | string |  |  
action_result.data.\*.last_login_time | string |  |  
action_result.data.\*.last_name | string |  |  
action_result.data.\*.location | string |  |  
action_result.data.\*.personal_meeting_url | string |  |  
action_result.data.\*.phone_country | string |  |  
action_result.data.\*.phone_number | string |  |  
action_result.data.\*.pic_url | string |  |  
action_result.data.\*.pmi | numeric |  |  
action_result.data.\*.role_id | string |  |  
action_result.data.\*.role_name | string |  |  
action_result.data.\*.status | string |  |  
action_result.data.\*.timezone | string |  |  
action_result.data.\*.type | numeric |  |  
action_result.data.\*.use_pmi | boolean |  |  
action_result.data.\*.user_created_at | string |  |   2023-03-01T07:08:51Z 
action_result.data.\*.vanity_url | string |  |  
action_result.data.\*.verified | numeric |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'create meeting'
Create zoom meeting

Type: **generic**  
Read only: **False**

In <b>user_id</b> parameter, user ID or user's email can be used. Also, we can pass the <b>me</b> value for current user. The parameter auto_recording would set the place to save the meeting recording: local - Record the meeting locally, cloud - Record the meeting to the cloud, none - Auto-recording disabled.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** |  required  | User id | string |  `zoom user id`  `email` 
**password** |  optional  | Meeting password | string | 
**gen_password** |  optional  | Auto generate meeting password | boolean | 
**waiting_room** |  required  | Enable waiting room | string | 
**topic** |  optional  | Topic of meeting | string | 
**agenda** |  optional  | Agenda of meeting | string | 
**alternative_hosts** |  optional  | Comma-separated list of the meeting's alternative hosts' email addresses or IDs | string | 
**continuous_meeting_chat** |  optional  | Whether to enable the continuous meeting chat setting | boolean | 
**auto_recording** |  optional  | The automatic recording settings | string | 
**meeting_invitees** |  optional  | Comma-separated list of the meeting's invitees | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.user_id | string |  `zoom user id`  `email`  |  
action_result.parameter.password | string |  |  
action_result.parameter.gen_password | boolean |  |  
action_result.parameter.waiting_room | string |  |  
action_result.parameter.topic | string |  |  
action_result.parameter.agenda | string |  |  
action_result.parameter.alternative_hosts | string |  |  
action_result.parameter.continuous_meeting_chat | boolean |  |  
action_result.parameter.auto_recording | string |  |  
action_result.parameter.meeting_invitees | string |  |  
action_result.data.\*.host_id | string |  `zoom user id`  |   22test-TeSTiNgZg8NTeST 
action_result.summary.meeting_id | string |  `zoom meeting id`  |   97648930957 
action_result.data.\*.join_url | string |  |   https://zoom.us/T/99999999999 
action_result.data.\*.password | string |  |   I2q8w&DSw 
action_result.data.\*.id | numeric |  |   99999999999 
action_result.data.\*.type | numeric |  |   2 
action_result.data.\*.uuid | string |  |   ztest22test/testWwC6VA== 
action_result.data.\*.topic | string |  |   Zoom Meeting 
action_result.data.\*.status | string |  |   waiting 
action_result.data.\*.agenda | string |  |   This is test agenda for create meeting action. This is test agenda for create meeting action. This is test agenda for create meeting action. 
action_result.data.\*.h323_password | string |  |   800645960 
action_result.data.\*.pstn_password | string |  |   800645960 
action_result.data.\*.encrypted_password | string |  |   uGBNumrMF6BPFw85hBNTApbDBeO7aI.1 
action_result.data.\*.duration | numeric |  |   60 
action_result.data.\*.settings.audio | string |  |   both 
action_result.data.\*.settings.use_pmi | boolean |  |   True  False 
action_result.data.\*.settings.jbh_time | numeric |  |  
action_result.data.\*.settings.watermark | boolean |  |   True  False 
action_result.data.\*.settings.cn_meeting | boolean |  |   True  False 
action_result.data.\*.settings.focus_mode | boolean |  |   True  False 
action_result.data.\*.settings.host_video | boolean |  |   True  False 
action_result.data.\*.settings.in_meeting | boolean |  |   True  False 
action_result.data.\*.settings.waiting_room | boolean |  |   True  False 
action_result.data.\*.settings.approval_type | numeric |  |   2 
action_result.data.\*.settings.breakout_room.enable | boolean |  |   True  False 
action_result.data.\*.settings.enforce_login | boolean |  |   True  False 
action_result.data.\*.settings.auto_recording | string |  |   cloud 
action_result.data.\*.settings.device_testing | boolean |  |   True  False 
action_result.data.\*.settings.show_join_info | boolean |  |   True  False 
action_result.data.\*.settings.encryption_type | string |  |   enhanced_encryption 
action_result.data.\*.settings.mute_upon_entry | boolean |  |   True  False 
action_result.data.\*.settings.private_meeting | boolean |  |   True  False 
action_result.data.\*.settings.internal_meeting | boolean |  |   True  False 
action_result.data.\*.settings.join_before_host | boolean |  |   True  False 
action_result.data.\*.settings.alternative_hosts | string |  |   test@test.com 
action_result.data.\*.settings.participant_video | boolean |  |   True  False 
action_result.data.\*.settings.show_share_button | boolean |  |   True  False 
action_result.data.\*.settings.close_registration | boolean |  |   True  False 
action_result.data.\*.settings.email_notification | boolean |  |   True  False 
action_result.data.\*.settings.question_and_answer.enable | boolean |  |   True  False 
action_result.data.\*.settings.enforce_login_domains | string |  |  
action_result.data.\*.settings.host_save_video_order | boolean |  |   True  False 
action_result.data.\*.settings.allow_multiple_devices | boolean |  |   True  False 
action_result.data.\*.settings.global_dial_in_numbers.\*.city | string |  |   San Jose 
action_result.data.\*.settings.global_dial_in_numbers.\*.type | string |  |   toll 
action_result.data.\*.settings.global_dial_in_numbers.\*.number | string |  |   +1 000 000 0000 
action_result.data.\*.settings.global_dial_in_numbers.\*.country | string |  |   US 
action_result.data.\*.settings.global_dial_in_numbers.\*.country_name | string |  |   US 
action_result.data.\*.settings.meeting_authentication | boolean |  |   True  False 
action_result.data.\*.settings.continuous_meeting_chat.enable | boolean |  |   True  False 
action_result.data.\*.settings.continuous_meeting_chat.channel_id | string |  |   web_sch_47c967faa78b49fc992eb081f698e3e5 
action_result.data.\*.settings.continuous_meeting_chat.auto_add_invited_external_users | boolean |  |   True  False 
action_result.data.\*.settings.push_change_to_calendar | boolean |  |   True  False 
action_result.data.\*.settings.email_in_attendee_report | boolean |  |   True  False 
action_result.data.\*.settings.auto_start_meeting_summary | boolean |  |   True  False 
action_result.data.\*.settings.enable_dedicated_group_chat | boolean |  |   True  False 
action_result.data.\*.settings.participant_focused_meeting | boolean |  |   True  False 
action_result.data.\*.settings.sign_language_interpretation.enable | boolean |  |   True  False 
action_result.data.\*.settings.alternative_host_update_polls | boolean |  |   True  False 
action_result.data.\*.settings.registrants_confirmation_email | boolean |  |   True  False 
action_result.data.\*.settings.registrants_email_notification | boolean |  |   True  False 
action_result.data.\*.settings.auto_start_ai_companion_questions | boolean |  |   True  False 
action_result.data.\*.settings.alternative_hosts_email_notification | boolean |  |   True  False 
action_result.data.\*.settings.approved_or_denied_countries_or_regions.enable | boolean |  |   True  False 
action_result.data.\*.settings.request_permission_to_unmute_participants | boolean |  |   True  False 
action_result.data.\*.timezone | string |  |   Asia/Kolkata 
action_result.data.\*.start_url | string |  |   https://zoom.us/s/9999999999?inv=eyTeST23tEStKV1QiLCJzdiI6TeStMDAwTestInptestrbSITEsTt22TeSttEstFs23TeIkhTMjU2In0.eyJpc3MiOiJ3ZWIiLCJjbHQiOjAsIm1udW0iOiI5NzY0ODkzMDk1NyIsImF1ZCI6ImNsaWVudHNtIiwidWlkIjoiNFo5TestLVZRbnVIamxaZzhOY1FTQSIsTestZCI6ImVlNDRiOTgwNDA2OTRhODY4YjFhNjQzZGJmYmY3ZDk5ITestsiOiIwITest3R5IjoxMDAsIndjZCI6ImTestIsImV4cCI6MTTestk3NjEwMSwiaWF0IjoxTestOTY4OTAxLCJhTestOiJXdUFCQnJ3TestZXNRbGlXT3VYU3TestwiY2lkITestn0.VWdUODAJ_TestTxIO21m1n8xTestoZX2Ho8biVm_WBU 
action_result.data.\*.created_at | string |  |   2024-09-10T11:48:20Z 
action_result.data.\*.host_email | string |  |   test@test.in 
action_result.data.\*.start_time | string |  |   2024-09-10T11:48:20Z 
action_result.data.\*.pre_schedule | boolean |  |   True  False 
action_result.summary.password | string |  |   Not Added 
action_result.summary.waiting_room | string |  |   Not Added 
action_result.summary.auto_recording | string |  |   cloud 
action_result.summary.meeting_created | boolean |  |   True  False 
action_result.summary.meeting_invitees | string |  |  
action_result.summary.alternative_hosts | string |  |   test@test.com 
action_result.summary.continuous_meeting_chat | string |  |   Not Added 
action_result.data.\*.settings.meeting_invitees.\*.email | string |  |   test@test.com 
action_result.status | string |  |   success  failed 
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |    

## action: 'get meeting'
Get zoom meeting details

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**meeting_id** |  required  | Zoom meeting ID | string |  `zoom meeting id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.meeting_id | string |  `zoom meeting id`  |   92512345678 
action_result.data.\*.agenda | string |  |  
action_result.data.\*.assistant_id | string |  |  
action_result.data.\*.created_at | string |  |  
action_result.data.\*.duration | numeric |  |  
action_result.data.\*.encrypted_password | string |  |  
action_result.data.\*.h323_password | string |  |  
action_result.data.\*.host_email | string |  |  
action_result.data.\*.host_id | string |  |  
action_result.data.\*.id | numeric |  |  
action_result.data.\*.join_url | string |  `url`  |  
action_result.data.\*.occurrences.\*.duration | numeric |  |  
action_result.data.\*.occurrences.\*.occurrence_id | string |  |  
action_result.data.\*.occurrences.\*.start_time | string |  |  
action_result.data.\*.occurrences.\*.status | string |  |  
action_result.data.\*.password | string |  |  
action_result.data.\*.pmi | numeric |  |  
action_result.data.\*.pre_schedule | boolean |  |  
action_result.data.\*.pstn_password | string |  |  
action_result.data.\*.recurrence.end_date_time | string |  |  
action_result.data.\*.recurrence.end_times | numeric |  |  
action_result.data.\*.recurrence.monthly_day | numeric |  |  
action_result.data.\*.recurrence.monthly_week | numeric |  |  
action_result.data.\*.recurrence.monthly_week_day | numeric |  |  
action_result.data.\*.recurrence.repeat_interval | numeric |  |  
action_result.data.\*.recurrence.type | numeric |  |  
action_result.data.\*.recurrence.weekly_days | string |  |  
action_result.data.\*.settings.allow_multiple_devices | boolean |  |  
action_result.data.\*.settings.alternative_host_update_polls | boolean |  |  
action_result.data.\*.settings.alternative_hosts | string |  |  
action_result.data.\*.settings.alternative_hosts_email_notification | boolean |  |  
action_result.data.\*.settings.approval_type | numeric |  |  
action_result.data.\*.settings.approved_or_denied_countries_or_regions.enable | boolean |  |  
action_result.data.\*.settings.audio | string |  |  
action_result.data.\*.settings.authentication_domains | string |  |  
action_result.data.\*.settings.authentication_name | string |  |  
action_result.data.\*.settings.authentication_option | string |  |  
action_result.data.\*.settings.auto_recording | string |  |  
action_result.data.\*.settings.breakout_room.enable | boolean |  |  
action_result.data.\*.settings.close_registration | boolean |  |  
action_result.data.\*.settings.cn_meeting | boolean |  |  
action_result.data.\*.settings.contact_email | string |  |  
action_result.data.\*.settings.contact_name | string |  |  
action_result.data.\*.settings.device_testing | boolean |  |  
action_result.data.\*.settings.email_notification | boolean |  |  
action_result.data.\*.settings.enable_dedicated_group_chat | boolean |  |   True  False 
action_result.data.\*.settings.encryption_type | string |  |  
action_result.data.\*.settings.enforce_login | boolean |  |  
action_result.data.\*.settings.enforce_login_domains | string |  |  
action_result.data.\*.settings.focus_mode | boolean |  |  
action_result.data.\*.settings.global_dial_in_countries | string |  |  
action_result.data.\*.settings.global_dial_in_numbers.\*.city | string |  |  
action_result.data.\*.settings.global_dial_in_numbers.\*.country | string |  |  
action_result.data.\*.settings.global_dial_in_numbers.\*.country_name | string |  |  
action_result.data.\*.settings.global_dial_in_numbers.\*.number | string |  |  
action_result.data.\*.settings.global_dial_in_numbers.\*.type | string |  |  
action_result.data.\*.settings.host_save_video_order | boolean |  |  
action_result.data.\*.settings.host_video | boolean |  |  
action_result.data.\*.settings.in_meeting | boolean |  |  
action_result.data.\*.settings.jbh_time | numeric |  |  
action_result.data.\*.settings.join_before_host | boolean |  |  
action_result.data.\*.settings.meeting_authentication | boolean |  |  
action_result.data.\*.settings.mute_upon_entry | boolean |  |  
action_result.data.\*.settings.participant_video | boolean |  |  
action_result.data.\*.settings.private_meeting | boolean |  |  
action_result.data.\*.settings.registrants_confirmation_email | boolean |  |  
action_result.data.\*.settings.registrants_email_notification | boolean |  |  
action_result.data.\*.settings.registration_type | numeric |  |  
action_result.data.\*.settings.request_permission_to_unmute_participants | boolean |  |  
action_result.data.\*.settings.show_join_info | boolean |  |   True  False 
action_result.data.\*.settings.show_share_button | boolean |  |  
action_result.data.\*.settings.use_pmi | boolean |  |  
action_result.data.\*.settings.waiting_room | boolean |  |  
action_result.data.\*.settings.watermark | boolean |  |  
action_result.data.\*.start_time | string |  |  
action_result.data.\*.start_url | string |  |  
action_result.data.\*.status | string |  |  
action_result.data.\*.timezone | string |  |  
action_result.data.\*.topic | string |  |  
action_result.data.\*.tracking_fields.\*.field | string |  |  
action_result.data.\*.tracking_fields.\*.value | string |  |  
action_result.data.\*.type | numeric |  |  
action_result.data.\*.uuid | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'update meeting'
Update zoom meeting

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**meeting_id** |  required  | Zoom meeting ID | string |  `zoom meeting id` 
**password** |  optional  | Meeting password | string | 
**gen_password** |  optional  | Auto generate meeting password | boolean | 
**waiting_room** |  required  | Enable waiting room | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.gen_password | boolean |  |   None  True  False 
action_result.parameter.meeting_id | string |  `zoom meeting id`  |   92512345678 
action_result.parameter.password | string |  |   testPass1 
action_result.parameter.waiting_room | string |  |   None 
action_result.data | string |  |  
action_result.summary.meeting_updated | boolean |  |   True  False 
action_result.summary.password | string |  |   testxFghbsuHndTYGF 
action_result.summary.waiting_room | string |  |   Not Updated 
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'delete meeting'
Delete zoom meeting

Type: **generic**  
Read only: **False**

Deletes previous and future zoom meetings.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**meeting_id** |  required  | Zoom meeting ID | string |  `zoom meeting id` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.meeting_id | string |  `zoom meeting id`  |   92512345678 
action_result.data | string |  |  
action_result.summary.meeting_deleted | boolean |  |   True  False 
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'update user settings'
Update zoom user settings

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user_id** |  required  | Zoom user ID | string |  `zoom user id` 
**req_password_pmi** |  required  | Require password for PMI | string | 
**pmi_password** |  optional  | User pmi password | string | 
**gen_pmi_password** |  optional  | Auto generate pmi password | boolean | 
**waiting_room** |  required  | Enable waiting room | string | 
**req_password_sched** |  required  | Require password for scheduling meetings | string | 
**req_password_inst** |  required  | Require password for instant meetings | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.gen_pmi_password | boolean |  |   None  True  False 
action_result.parameter.pmi_password | string |  |   test@123 
action_result.parameter.req_password_inst | string |  |   None 
action_result.parameter.req_password_pmi | string |  |   None 
action_result.parameter.req_password_sched | string |  |   None 
action_result.parameter.user_id | string |  `zoom user id`  |   A0BiCtoDEFGHIzYaZcLdsA 
action_result.parameter.user_id | string |  `zoom user id`  |   A0BiCtoDEFGHIzYaZcLdsA 
action_result.parameter.waiting_room | string |  |   None 
action_result.data | string |  |  
action_result.summary.pmi_password | string |  |   Not Updated 
action_result.summary.require_password_for_instant_meetings | string |  |   Not Updated 
action_result.summary.require_password_for_personal_meeting_instance | string |  |   Not Updated 
action_result.summary.require_password_for_scheduling_new_meetings | string |  |   Not Updated 
action_result.summary.waiting_room | string |  |   Not Updated 
action_result.message | string |  |  
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 