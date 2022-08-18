[comment]: # "Auto-generated SOAR connector documentation"
# Zoom

Publisher: Splunk  
Connector Version: 2\.0\.2  
Product Vendor: Zoom  
Product Name: Zoom Meetings  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.3\.0  

The app integrates with Zoom Meetings API to perform investigative and generic actions

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2021-2022 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
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

### App Configurations (Zoom Side)

For the Zoom app for Phantom to be configured correctly, you must first create a JWT App in your
Zoom App Marketplace account. A JWT App can be created by going
[here](https://marketplace.zoom.us/develop/create) and clicking the "Create" button under the "JWT"
app type. Once you've created your JWT app you'll be provided with an API Key and an API Secret,
keep track of these. They will be necessary for the configuration on the Phantom side.

### App Configuration (Splunk> Phantom Side)

The configuration of the Zoom App for Splunk> Phantom requires three fields API Key and API Secret
which are provided by Zoom. The third field is the "Base URL" field which is simply the base URL for
the Zoom REST API. The default value provided, "https://api.zoom/us/v2" should not need to be
changed.

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
**base\_url** |  required  | string | Base URL \(e\.g\. https\://api\.zoom\.us/v2\)
**api\_key** |  required  | password | API Key
**api\_secret** |  required  | password | API Secret

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
**meeting\_id** |  required  | Zoom meeting ID | string |  `zoom meeting id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.meeting\_id | string |  `zoom meeting id` 
action\_result\.data\.\*\.invitation | string | 
action\_result\.data\.\*\.parsed\_fields\.invitation\_link | string | 
action\_result\.data\.\*\.parsed\_fields\.meeting\_id | string | 
action\_result\.data\.\*\.parsed\_fields\.passcode | string | 
action\_result\.data\.\*\.parsed\_fields\.time | string | 
action\_result\.data\.\*\.parsed\_fields\.topic | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get user settings'
Get zoom user settings

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_id** |  required  | Zoom user ID | string |  `zoom user id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.user\_id | string |  `zoom user id` 
action\_result\.data\.\*\.audio\_conferencing\.toll\_free\_and\_fee\_based\_toll\_call\.enable | boolean | 
action\_result\.data\.\*\.email\_notification\.alternative\_host\_reminder | boolean | 
action\_result\.data\.\*\.email\_notification\.cancel\_meeting\_reminder | boolean | 
action\_result\.data\.\*\.email\_notification\.jbh\_reminder | boolean | 
action\_result\.data\.\*\.email\_notification\.schedule\_for\_reminder | boolean | 
action\_result\.data\.\*\.feature\.cn\_meeting | boolean | 
action\_result\.data\.\*\.feature\.in\_meeting | boolean | 
action\_result\.data\.\*\.feature\.large\_meeting | boolean | 
action\_result\.data\.\*\.feature\.large\_meeting\_capacity | numeric | 
action\_result\.data\.\*\.feature\.meeting\_capacity | numeric | 
action\_result\.data\.\*\.feature\.webinar | boolean | 
action\_result\.data\.\*\.feature\.webinar\_capacity | numeric | 
action\_result\.data\.\*\.feature\.zoom\_events | boolean | 
action\_result\.data\.\*\.feature\.zoom\_iq\_for\_sales | boolean | 
action\_result\.data\.\*\.feature\.zoom\_phone | boolean | 
action\_result\.data\.\*\.in\_meeting\.allow\_live\_streaming | boolean | 
action\_result\.data\.\*\.in\_meeting\.allow\_participants\_chat\_with | numeric | 
action\_result\.data\.\*\.in\_meeting\.allow\_participants\_to\_rename | boolean | 
action\_result\.data\.\*\.in\_meeting\.allow\_show\_zoom\_windows | boolean | 
action\_result\.data\.\*\.in\_meeting\.allow\_users\_save\_chats | numeric | 
action\_result\.data\.\*\.in\_meeting\.annotation | boolean | 
action\_result\.data\.\*\.in\_meeting\.attendee\_on\_hold | boolean | 
action\_result\.data\.\*\.in\_meeting\.attention\_mode\_focus\_mode | boolean | 
action\_result\.data\.\*\.in\_meeting\.auto\_answer | boolean | 
action\_result\.data\.\*\.in\_meeting\.auto\_saving\_chat | boolean | 
action\_result\.data\.\*\.in\_meeting\.breakout\_room | boolean | 
action\_result\.data\.\*\.in\_meeting\.chat | boolean | 
action\_result\.data\.\*\.in\_meeting\.closed\_caption | boolean | 
action\_result\.data\.\*\.in\_meeting\.closed\_captioning\.enable | boolean | 
action\_result\.data\.\*\.in\_meeting\.closed\_captioning\.save\_caption | boolean | 
action\_result\.data\.\*\.in\_meeting\.co\_host | boolean | 
action\_result\.data\.\*\.in\_meeting\.custom\_live\_streaming\_service | boolean | 
action\_result\.data\.\*\.in\_meeting\.custom\_service\_instructions | string | 
action\_result\.data\.\*\.in\_meeting\.disable\_screen\_sharing\_for\_host\_meetings | boolean | 
action\_result\.data\.\*\.in\_meeting\.disable\_screen\_sharing\_for\_in\_meeting\_guests | boolean | 
action\_result\.data\.\*\.in\_meeting\.e2e\_encryption | boolean | 
action\_result\.data\.\*\.in\_meeting\.entry\_exit\_chime | string | 
action\_result\.data\.\*\.in\_meeting\.far\_end\_camera\_control | boolean | 
action\_result\.data\.\*\.in\_meeting\.feedback | boolean | 
action\_result\.data\.\*\.in\_meeting\.file\_transfer | boolean | 
action\_result\.data\.\*\.in\_meeting\.group\_hd | boolean | 
action\_result\.data\.\*\.in\_meeting\.manual\_captioning\.auto\_generated\_captions | boolean | 
action\_result\.data\.\*\.in\_meeting\.manual\_captioning\.full\_transcript | boolean | 
action\_result\.data\.\*\.in\_meeting\.manual\_captioning\.manual\_captions | boolean | 
action\_result\.data\.\*\.in\_meeting\.manual\_captioning\.save\_captions | boolean | 
action\_result\.data\.\*\.in\_meeting\.meeting\_polling\.enable | boolean | 
action\_result\.data\.\*\.in\_meeting\.meeting\_reactions | boolean | 
action\_result\.data\.\*\.in\_meeting\.non\_verbal\_feedback | boolean | 
action\_result\.data\.\*\.in\_meeting\.polling | boolean | 
action\_result\.data\.\*\.in\_meeting\.private\_chat | boolean | 
action\_result\.data\.\*\.in\_meeting\.record\_play\_voice | boolean | 
action\_result\.data\.\*\.in\_meeting\.remote\_control | boolean | 
action\_result\.data\.\*\.in\_meeting\.remote\_support | boolean | 
action\_result\.data\.\*\.in\_meeting\.request\_permission\_to\_unmute\_participants | boolean | 
action\_result\.data\.\*\.in\_meeting\.screen\_sharing | boolean | 
action\_result\.data\.\*\.in\_meeting\.share\_dual\_camera | boolean | 
action\_result\.data\.\*\.in\_meeting\.show\_a\_join\_from\_your\_browser\_link | boolean | 
action\_result\.data\.\*\.in\_meeting\.show\_meeting\_control\_toolbar | boolean | 
action\_result\.data\.\*\.in\_meeting\.slide\_control | boolean | 
action\_result\.data\.\*\.in\_meeting\.virtual\_background | boolean | 
action\_result\.data\.\*\.in\_meeting\.virtual\_background\_settings\.allow\_upload\_custom | boolean | 
action\_result\.data\.\*\.in\_meeting\.virtual\_background\_settings\.allow\_videos | boolean | 
action\_result\.data\.\*\.in\_meeting\.virtual\_background\_settings\.enable | boolean | 
action\_result\.data\.\*\.in\_meeting\.waiting\_room | boolean | 
action\_result\.data\.\*\.in\_meeting\.webinar\_polling\.enable | boolean | 
action\_result\.data\.\*\.in\_meeting\.who\_can\_share\_screen | string | 
action\_result\.data\.\*\.in\_meeting\.who\_can\_share\_screen\_when\_someone\_is\_sharing | string | 
action\_result\.data\.\*\.in\_meeting\.workplace\_by\_facebook | boolean | 
action\_result\.data\.\*\.integration\.linkedin\_sales\_navigator | boolean | 
action\_result\.data\.\*\.recording\.auto\_delete\_cmr | boolean | 
action\_result\.data\.\*\.recording\.auto\_delete\_cmr\_days | numeric | 
action\_result\.data\.\*\.recording\.auto\_recording | string | 
action\_result\.data\.\*\.recording\.cloud\_recording | boolean | 
action\_result\.data\.\*\.recording\.host\_pause\_stop\_recording | boolean | 
action\_result\.data\.\*\.recording\.local\_recording | boolean | 
action\_result\.data\.\*\.recording\.record\_audio\_file | boolean | 
action\_result\.data\.\*\.recording\.record\_gallery\_view | boolean | 
action\_result\.data\.\*\.recording\.record\_speaker\_view | boolean | 
action\_result\.data\.\*\.recording\.recording\_audio\_transcript | boolean | 
action\_result\.data\.\*\.recording\.recording\_disclaimer | boolean | 
action\_result\.data\.\*\.recording\.recording\_password\_requirement\.have\_letter | boolean | 
action\_result\.data\.\*\.recording\.recording\_password\_requirement\.have\_number | boolean | 
action\_result\.data\.\*\.recording\.recording\_password\_requirement\.have\_special\_character | boolean | 
action\_result\.data\.\*\.recording\.recording\_password\_requirement\.length | numeric | 
action\_result\.data\.\*\.recording\.recording\_password\_requirement\.only\_allow\_numeric | boolean | 
action\_result\.data\.\*\.recording\.save\_chat\_text | boolean | 
action\_result\.data\.\*\.recording\.show\_timestamp | boolean | 
action\_result\.data\.\*\.schedule\_meeting\.audio\_type | string | 
action\_result\.data\.\*\.schedule\_meeting\.default\_password\_for\_scheduled\_meetings | string | 
action\_result\.data\.\*\.schedule\_meeting\.embed\_password\_in\_join\_link | boolean | 
action\_result\.data\.\*\.schedule\_meeting\.force\_pmi\_jbh\_password | boolean | 
action\_result\.data\.\*\.schedule\_meeting\.host\_video | boolean | 
action\_result\.data\.\*\.schedule\_meeting\.join\_before\_host | boolean | 
action\_result\.data\.\*\.schedule\_meeting\.meeting\_password\_requirement\.consecutive\_characters\_length | numeric | 
action\_result\.data\.\*\.schedule\_meeting\.meeting\_password\_requirement\.have\_letter | boolean | 
action\_result\.data\.\*\.schedule\_meeting\.meeting\_password\_requirement\.have\_number | boolean | 
action\_result\.data\.\*\.schedule\_meeting\.meeting\_password\_requirement\.have\_special\_character | boolean | 
action\_result\.data\.\*\.schedule\_meeting\.meeting\_password\_requirement\.have\_upper\_and\_lower\_characters | boolean | 
action\_result\.data\.\*\.schedule\_meeting\.meeting\_password\_requirement\.length | numeric | 
action\_result\.data\.\*\.schedule\_meeting\.meeting\_password\_requirement\.only\_allow\_numeric | boolean | 
action\_result\.data\.\*\.schedule\_meeting\.meeting\_password\_requirement\.weak\_enhance\_detection | boolean | 
action\_result\.data\.\*\.schedule\_meeting\.mute\_upon\_entry | boolean | 
action\_result\.data\.\*\.schedule\_meeting\.participants\_video | boolean | 
action\_result\.data\.\*\.schedule\_meeting\.personal\_meeting | boolean | 
action\_result\.data\.\*\.schedule\_meeting\.pmi\_password | string | 
action\_result\.data\.\*\.schedule\_meeting\.pstn\_password\_protected | boolean | 
action\_result\.data\.\*\.schedule\_meeting\.require\_password\_for\_instant\_meetings | boolean | 
action\_result\.data\.\*\.schedule\_meeting\.require\_password\_for\_pmi\_meetings | string | 
action\_result\.data\.\*\.schedule\_meeting\.require\_password\_for\_scheduled\_meetings | boolean | 
action\_result\.data\.\*\.schedule\_meeting\.require\_password\_for\_scheduling\_new\_meetings | boolean | 
action\_result\.data\.\*\.schedule\_meeting\.use\_pmi\_for\_instant\_meetings | boolean | 
action\_result\.data\.\*\.schedule\_meeting\.use\_pmi\_for\_scheduled\_meetings | boolean | 
action\_result\.data\.\*\.telephony\.audio\_conference\_info | string | 
action\_result\.data\.\*\.telephony\.show\_international\_numbers\_link | boolean | 
action\_result\.data\.\*\.telephony\.third\_party\_audio | boolean | 
action\_result\.data\.\*\.tsp\.call\_out | boolean | 
action\_result\.data\.\*\.tsp\.call\_out\_countries | string | 
action\_result\.data\.\*\.tsp\.show\_international\_numbers\_link | boolean | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get user'
Get zoom user info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_id** |  required  | Zoom user ID | string |  `zoom user id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.user\_id | string |  `zoom user id` 
action\_result\.data\.\*\.account\_id | string | 
action\_result\.data\.\*\.account\_number | numeric | 
action\_result\.data\.\*\.cms\_user\_id | string | 
action\_result\.data\.\*\.company | string | 
action\_result\.data\.\*\.created\_at | string | 
action\_result\.data\.\*\.dept | string | 
action\_result\.data\.\*\.email | string | 
action\_result\.data\.\*\.first\_name | string | 
action\_result\.data\.\*\.group\_ids | string | 
action\_result\.data\.\*\.host\_key | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.im\_group\_ids | string | 
action\_result\.data\.\*\.jid | string | 
action\_result\.data\.\*\.job\_title | string | 
action\_result\.data\.\*\.language | string | 
action\_result\.data\.\*\.last\_client\_version | string | 
action\_result\.data\.\*\.last\_login\_time | string | 
action\_result\.data\.\*\.last\_name | string | 
action\_result\.data\.\*\.location | string | 
action\_result\.data\.\*\.personal\_meeting\_url | string | 
action\_result\.data\.\*\.phone\_country | string | 
action\_result\.data\.\*\.phone\_number | string | 
action\_result\.data\.\*\.pic\_url | string | 
action\_result\.data\.\*\.pmi | numeric | 
action\_result\.data\.\*\.role\_id | string | 
action\_result\.data\.\*\.role\_name | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.timezone | string | 
action\_result\.data\.\*\.type | numeric | 
action\_result\.data\.\*\.use\_pmi | boolean | 
action\_result\.data\.\*\.vanity\_url | string | 
action\_result\.data\.\*\.verified | numeric | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create meeting'
Create zoom meeting

Type: **generic**  
Read only: **False**

In <b>user\_id</b> parameter, user ID or user's email can be used\. Also, we can pass the <b>me</b> value for current user\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_id** |  required  | User id | string |  `zoom user id`  `email` 
**password** |  optional  | Meeting password | string | 
**gen\_password** |  optional  | Auto generate meeting password | boolean | 
**waiting\_room** |  required  | Enable waiting room | string | 
**topic** |  optional  | Topic of meeting | string | 
**agenda** |  optional  | Agenda of meeting | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.agenda | string | 
action\_result\.parameter\.gen\_password | boolean | 
action\_result\.parameter\.password | string | 
action\_result\.parameter\.topic | string | 
action\_result\.parameter\.user\_id | string |  `zoom user id`  `email` 
action\_result\.parameter\.waiting\_room | string | 
action\_result\.data\.\*\.agenda | string | 
action\_result\.data\.\*\.created\_at | string | 
action\_result\.data\.\*\.duration | numeric | 
action\_result\.data\.\*\.encrypted\_password | string | 
action\_result\.data\.\*\.h323\_password | string | 
action\_result\.data\.\*\.host\_email | string | 
action\_result\.data\.\*\.host\_id | string | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.join\_url | string |  `url` 
action\_result\.data\.\*\.password | string | 
action\_result\.data\.\*\.pre\_schedule | boolean | 
action\_result\.data\.\*\.pstn\_password | string | 
action\_result\.data\.\*\.settings\.allow\_multiple\_devices | boolean | 
action\_result\.data\.\*\.settings\.alternative\_host\_update\_polls | boolean | 
action\_result\.data\.\*\.settings\.alternative\_hosts | string | 
action\_result\.data\.\*\.settings\.alternative\_hosts\_email\_notification | boolean | 
action\_result\.data\.\*\.settings\.approval\_type | numeric | 
action\_result\.data\.\*\.settings\.approved\_or\_denied\_countries\_or\_regions\.enable | boolean | 
action\_result\.data\.\*\.settings\.audio | string | 
action\_result\.data\.\*\.settings\.auto\_recording | string | 
action\_result\.data\.\*\.settings\.breakout\_room\.enable | boolean | 
action\_result\.data\.\*\.settings\.close\_registration | boolean | 
action\_result\.data\.\*\.settings\.cn\_meeting | boolean | 
action\_result\.data\.\*\.settings\.device\_testing | boolean | 
action\_result\.data\.\*\.settings\.email\_notification | boolean | 
action\_result\.data\.\*\.settings\.encryption\_type | string | 
action\_result\.data\.\*\.settings\.enforce\_login | boolean | 
action\_result\.data\.\*\.settings\.enforce\_login\_domains | string | 
action\_result\.data\.\*\.settings\.focus\_mode | boolean | 
action\_result\.data\.\*\.settings\.host\_save\_video\_order | boolean | 
action\_result\.data\.\*\.settings\.host\_video | boolean | 
action\_result\.data\.\*\.settings\.in\_meeting | boolean | 
action\_result\.data\.\*\.settings\.jbh\_time | numeric | 
action\_result\.data\.\*\.settings\.join\_before\_host | boolean | 
action\_result\.data\.\*\.settings\.meeting\_authentication | boolean | 
action\_result\.data\.\*\.settings\.mute\_upon\_entry | boolean | 
action\_result\.data\.\*\.settings\.participant\_video | boolean | 
action\_result\.data\.\*\.settings\.private\_meeting | boolean | 
action\_result\.data\.\*\.settings\.registrants\_confirmation\_email | boolean | 
action\_result\.data\.\*\.settings\.registrants\_email\_notification | boolean | 
action\_result\.data\.\*\.settings\.request\_permission\_to\_unmute\_participants | boolean | 
action\_result\.data\.\*\.settings\.show\_share\_button | boolean | 
action\_result\.data\.\*\.settings\.use\_pmi | boolean | 
action\_result\.data\.\*\.settings\.waiting\_room | boolean | 
action\_result\.data\.\*\.settings\.watermark | boolean | 
action\_result\.data\.\*\.start\_time | string | 
action\_result\.data\.\*\.start\_url | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.timezone | string | 
action\_result\.data\.\*\.topic | string | 
action\_result\.data\.\*\.type | numeric | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.summary\.meeting\_created | boolean | 
action\_result\.summary\.meeting\_id | string |  `zoom meeting id` 
action\_result\.summary\.password | string | 
action\_result\.summary\.waiting\_room | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get meeting'
Get zoom meeting details

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**meeting\_id** |  required  | Zoom meeting ID | string |  `zoom meeting id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.meeting\_id | string |  `zoom meeting id` 
action\_result\.data\.\*\.agenda | string | 
action\_result\.data\.\*\.assistant\_id | string | 
action\_result\.data\.\*\.created\_at | string | 
action\_result\.data\.\*\.duration | numeric | 
action\_result\.data\.\*\.encrypted\_password | string | 
action\_result\.data\.\*\.h323\_password | string | 
action\_result\.data\.\*\.host\_email | string | 
action\_result\.data\.\*\.host\_id | string | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.join\_url | string |  `url` 
action\_result\.data\.\*\.occurrences\.\*\.duration | numeric | 
action\_result\.data\.\*\.occurrences\.\*\.occurrence\_id | string | 
action\_result\.data\.\*\.occurrences\.\*\.start\_time | string | 
action\_result\.data\.\*\.occurrences\.\*\.status | string | 
action\_result\.data\.\*\.password | string | 
action\_result\.data\.\*\.pmi | numeric | 
action\_result\.data\.\*\.pre\_schedule | boolean | 
action\_result\.data\.\*\.pstn\_password | string | 
action\_result\.data\.\*\.recurrence\.end\_date\_time | string | 
action\_result\.data\.\*\.recurrence\.end\_times | numeric | 
action\_result\.data\.\*\.recurrence\.monthly\_day | numeric | 
action\_result\.data\.\*\.recurrence\.monthly\_week | numeric | 
action\_result\.data\.\*\.recurrence\.monthly\_week\_day | numeric | 
action\_result\.data\.\*\.recurrence\.repeat\_interval | numeric | 
action\_result\.data\.\*\.recurrence\.type | numeric | 
action\_result\.data\.\*\.recurrence\.weekly\_days | string | 
action\_result\.data\.\*\.settings\.allow\_multiple\_devices | boolean | 
action\_result\.data\.\*\.settings\.alternative\_host\_update\_polls | boolean | 
action\_result\.data\.\*\.settings\.alternative\_hosts | string | 
action\_result\.data\.\*\.settings\.alternative\_hosts\_email\_notification | boolean | 
action\_result\.data\.\*\.settings\.approval\_type | numeric | 
action\_result\.data\.\*\.settings\.approved\_or\_denied\_countries\_or\_regions\.enable | boolean | 
action\_result\.data\.\*\.settings\.audio | string | 
action\_result\.data\.\*\.settings\.authentication\_domains | string | 
action\_result\.data\.\*\.settings\.authentication\_name | string | 
action\_result\.data\.\*\.settings\.authentication\_option | string | 
action\_result\.data\.\*\.settings\.auto\_recording | string | 
action\_result\.data\.\*\.settings\.breakout\_room\.enable | boolean | 
action\_result\.data\.\*\.settings\.close\_registration | boolean | 
action\_result\.data\.\*\.settings\.cn\_meeting | boolean | 
action\_result\.data\.\*\.settings\.contact\_email | string | 
action\_result\.data\.\*\.settings\.contact\_name | string | 
action\_result\.data\.\*\.settings\.device\_testing | boolean | 
action\_result\.data\.\*\.settings\.email\_notification | boolean | 
action\_result\.data\.\*\.settings\.encryption\_type | string | 
action\_result\.data\.\*\.settings\.enforce\_login | boolean | 
action\_result\.data\.\*\.settings\.enforce\_login\_domains | string | 
action\_result\.data\.\*\.settings\.focus\_mode | boolean | 
action\_result\.data\.\*\.settings\.global\_dial\_in\_countries | string | 
action\_result\.data\.\*\.settings\.global\_dial\_in\_numbers\.\*\.city | string | 
action\_result\.data\.\*\.settings\.global\_dial\_in\_numbers\.\*\.country | string | 
action\_result\.data\.\*\.settings\.global\_dial\_in\_numbers\.\*\.country\_name | string | 
action\_result\.data\.\*\.settings\.global\_dial\_in\_numbers\.\*\.number | string | 
action\_result\.data\.\*\.settings\.global\_dial\_in\_numbers\.\*\.type | string | 
action\_result\.data\.\*\.settings\.host\_save\_video\_order | boolean | 
action\_result\.data\.\*\.settings\.host\_video | boolean | 
action\_result\.data\.\*\.settings\.in\_meeting | boolean | 
action\_result\.data\.\*\.settings\.jbh\_time | numeric | 
action\_result\.data\.\*\.settings\.join\_before\_host | boolean | 
action\_result\.data\.\*\.settings\.meeting\_authentication | boolean | 
action\_result\.data\.\*\.settings\.mute\_upon\_entry | boolean | 
action\_result\.data\.\*\.settings\.participant\_video | boolean | 
action\_result\.data\.\*\.settings\.private\_meeting | boolean | 
action\_result\.data\.\*\.settings\.registrants\_confirmation\_email | boolean | 
action\_result\.data\.\*\.settings\.registrants\_email\_notification | boolean | 
action\_result\.data\.\*\.settings\.registration\_type | numeric | 
action\_result\.data\.\*\.settings\.request\_permission\_to\_unmute\_participants | boolean | 
action\_result\.data\.\*\.settings\.show\_share\_button | boolean | 
action\_result\.data\.\*\.settings\.use\_pmi | boolean | 
action\_result\.data\.\*\.settings\.waiting\_room | boolean | 
action\_result\.data\.\*\.settings\.watermark | boolean | 
action\_result\.data\.\*\.start\_time | string | 
action\_result\.data\.\*\.start\_url | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.timezone | string | 
action\_result\.data\.\*\.topic | string | 
action\_result\.data\.\*\.tracking\_fields\.\*\.field | string | 
action\_result\.data\.\*\.tracking\_fields\.\*\.value | string | 
action\_result\.data\.\*\.type | numeric | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update meeting'
Update zoom meeting

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**meeting\_id** |  required  | Zoom meeting ID | string |  `zoom meeting id` 
**password** |  optional  | Meeting password | string | 
**gen\_password** |  optional  | Auto generate meeting password | boolean | 
**waiting\_room** |  required  | Enable waiting room | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.gen\_password | boolean | 
action\_result\.parameter\.meeting\_id | string |  `zoom meeting id` 
action\_result\.parameter\.password | string | 
action\_result\.parameter\.waiting\_room | string | 
action\_result\.data | string | 
action\_result\.summary\.meeting\_updated | boolean | 
action\_result\.summary\.password | string | 
action\_result\.summary\.waiting\_room | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete meeting'
Delete zoom meeting

Type: **generic**  
Read only: **False**

Deletes previous and future zoom meetings\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**meeting\_id** |  required  | Zoom meeting ID | string |  `zoom meeting id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.meeting\_id | string |  `zoom meeting id` 
action\_result\.data | string | 
action\_result\.summary\.meeting\_deleted | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update user settings'
Update zoom user settings

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_id** |  required  | Zoom user ID | string |  `zoom user id` 
**req\_password\_pmi** |  required  | Require password for PMI | string | 
**pmi\_password** |  optional  | User pmi password | string | 
**gen\_pmi\_password** |  optional  | Auto generate pmi password | boolean | 
**waiting\_room** |  required  | Enable waiting room | string | 
**req\_password\_sched** |  required  | Require password for scheduling meetings | string | 
**req\_password\_inst** |  required  | Require password for instant meetings | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.gen\_pmi\_password | boolean | 
action\_result\.parameter\.pmi\_password | string | 
action\_result\.parameter\.req\_password\_inst | string | 
action\_result\.parameter\.req\_password\_pmi | string | 
action\_result\.parameter\.req\_password\_sched | string | 
action\_result\.parameter\.user\_id | string |  `zoom user id` 
action\_result\.parameter\.waiting\_room | string | 
action\_result\.data | string | 
action\_result\.summary\.pmi\_password | string | 
action\_result\.summary\.require\_password\_for\_instant\_meetings | string | 
action\_result\.summary\.require\_password\_for\_personal\_meeting\_instance | string | 
action\_result\.summary\.require\_password\_for\_scheduling\_new\_meetings | string | 
action\_result\.summary\.waiting\_room | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 