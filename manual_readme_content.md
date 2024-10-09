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
