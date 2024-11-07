# SPDX-FileCopyrightText: Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import logging
import os

import aiohttp

from ...data_models.cve_intel import CveIntelGhsa
from ...utils.url_utils import url_join
from .intel_client import IntelClient

logger = logging.getLogger(f"morpheus.{__name__}")


class GHSAClient(IntelClient):
    """
    Async client for GitHub Security Advisory API

    While not strictly required, obtaining an API key is recommended, to obtain one refer:
    https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens
    """

    def __init__(self,
                 *,
                 base_url: str | None = None,
                 api_key: str | None = None,
                 session: aiohttp.ClientSession | None = None,
                 retry_count: int = 10,
                 sleep_time: float = 0.1,
                 respect_retry_after_header: bool = True):
        super().__init__(session=session,
                         base_url=base_url or os.environ.get('GHSA_BASE_URL'),
                         retry_count=retry_count,
                         sleep_time=sleep_time,
                         respect_retry_after_header=respect_retry_after_header)

        self._api_key = api_key or os.environ.get('GHSA_API_KEY', None)

        self._headers = {'Accept': 'application/vnd.github+json', "X-GitHub-Api-Version": "2022-11-28"}

        if self._api_key is not None:
            self._headers['Authorization'] = f"Bearer {self._api_key}"

    @classmethod
    def default_base_url(cls) -> str:
        return "https://api.github.com"

    async def get_intel_dict(self, vuln_id: str) -> dict:

        params = {}

        if (vuln_id.startswith("GHSA-")):
            params["ghsa_id"] = vuln_id
        else:
            params["cve_id"] = vuln_id

        response_json = await self.request(method="GET",
                                           url=url_join(self.base_url, "advisories"),
                                           params=params,
                                           headers=self._headers)

        if (isinstance(response_json, list)):

            if (len(response_json) != 1):
                raise ValueError(f"Expected 1 GHSA entry for {vuln_id}, got {len(response_json)}")

            return response_json[0]

        elif (isinstance(response_json, dict)):

            return response_json

        raise ValueError(f"Unexpected response type {type(response_json)}")

    async def get_intel(self, vuln_id: str) -> CveIntelGhsa:

        intel_dict = await self.get_intel_dict(vuln_id)

        return CveIntelGhsa.model_validate(intel_dict)
