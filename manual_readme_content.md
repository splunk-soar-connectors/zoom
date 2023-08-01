[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2021-2023 Splunk Inc."
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

#### For JWT Authentication

For the Zoom app for Splunk SOAR to be configured correctly, you must first create a JWT App in your
Zoom App Marketplace account. A JWT App can be created by going
[here](https://marketplace.zoom.us/develop/create) and clicking the "Create" button under the "JWT"
app type. Once you've created your JWT app you'll be provided with an API Key and an API Secret,
keep track of these. They will be necessary for the configuration on the Splunk SOAR side.

#### For Server-to-Server OAuth Authentication

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

We recommend you to use the Server-to-Server OAuth authentication because in short time JWT
authentication will be deprecated from
[zoom](https://developers.zoom.us/docs/internal-apps/jwt-faq/) platform.

### App Configuration (Splunk> SOAR Side)

For Server-to-Server OAuth configuration of the Zoom App for Splunk> SOAR requires three fields
account id, client id and client secret which are provided by Zoom.

For JWT authentication configuration of the Zoom App for Splunk> SOAR requires two fields API Key
and API Secret which are provided by Zoom.

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
