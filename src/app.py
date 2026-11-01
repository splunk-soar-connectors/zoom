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

"""Zoom SOAR SDK application."""

from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset, FieldCategory


class Asset(BaseAsset):
    base_url: str = AssetField(
        required=True,
        default="https://api.zoom.us/v2",
        description="Base URL (e.g. https://api.zoom.us/v2)",
        category=FieldCategory.CONNECTIVITY,
    )
    account_id: str = AssetField(
        required=True,
        description="Account ID (Server-to-Server OAuth)",
        category=FieldCategory.CONNECTIVITY,
    )
    client_id: str = AssetField(
        required=True,
        description="Client ID (Server-to-Server OAuth)",
        category=FieldCategory.CONNECTIVITY,
    )
    client_secret: str = AssetField(
        required=True,
        description="Client Secret (Server-to-Server OAuth)",
        sensitive=True,
        category=FieldCategory.CONNECTIVITY,
    )


app = App(
    name="Zoom",
    app_type="identity management",
    logo="logo_zoom.svg",
    logo_dark="logo_zoom_dark.svg",
    product_vendor="Zoom",
    product_name="Zoom Meetings",
    publisher="Splunk",
    appid="b64f4942-cb0f-4f15-b8aa-47435a0849db",
    python_version="3.13",
    min_phantom_version="8.6.0",
    fips_compliant=True,
    asset_cls=Asset,
)

from . import actions  # noqa: F401


if __name__ == "__main__":
    app.cli()
