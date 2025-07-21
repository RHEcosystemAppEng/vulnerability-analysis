# SPDX-FileCopyrightText: Copyright (c) 2024-2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

from vuln_analysis.data_models.cve_intel import CveIntelEpss
from vuln_analysis.utils.clients.intel_client import IntelClient
from vuln_analysis.utils.url_utils import url_join

logger = logging.getLogger(__name__)


class FirstClient(IntelClient):
    """
    Async client for First EPSS API
    """

    def __init__(self,
                 *,
                 base_url: str | None = None,
                 session: aiohttp.ClientSession | None = None,
                 retry_count: int = 10,
                 sleep_time: float = 0.1,
                 respect_retry_after_header: bool = True,
                 retry_on_client_errors: bool = True):

        super().__init__(session=session,
                         base_url=base_url or os.environ.get('FIRST_BASE_URL'),
                         retry_count=retry_count,
                         sleep_time=sleep_time,
                         respect_retry_after_header=respect_retry_after_header,
                         retry_on_client_errors=retry_on_client_errors)

        self._headers = {'Accept': 'application/json'}

    @classmethod
    def default_base_url(cls) -> str:
        return "https://api.first.org/data/v1"

    async def get_intel_dict(self, cve_id: str, date: None | str) -> dict:
        params = {'cve': cve_id, 'date': date} if date else {'cve': cve_id}
        response_json = await self.request(method='GET',
                                           url=url_join(self.base_url, "epss"),
                                           params=params,
                                           headers=self._headers)

        data = response_json.get('data', [])

        if (len(data) > 0):
            return data[0]

        return {}

    async def get_intel(self, cve_id: str, date: None | str = None) -> CveIntelEpss:
        intel_dict = await self.get_intel_dict(cve_id, date)

        return CveIntelEpss.model_validate(intel_dict)
