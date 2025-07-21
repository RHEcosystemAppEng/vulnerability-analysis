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

from vuln_analysis.data_models.cve_intel import CveIntelRhsa
from vuln_analysis.utils.clients.intel_client import IntelClient
from vuln_analysis.utils.url_utils import url_join

logger = logging.getLogger(__name__)


class RHSAClient(IntelClient):
    """
    Async client for Red Hat Security Advisory API
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
                         base_url=base_url or os.environ.get('RHSA_BASE_URL'),
                         retry_count=retry_count,
                         sleep_time=sleep_time,
                         respect_retry_after_header=respect_retry_after_header,
                         retry_on_client_errors=retry_on_client_errors)

    @classmethod
    def default_base_url(cls) -> str:
        return "https://access.redhat.com/hydra/rest"

    async def get_intel_dict(self, cve_id: str) -> dict:
        response = await self.request(method='GET',
                                      url=url_join(self.base_url, "securitydata", "cve.json"),
                                      params={"ids": cve_id})

        vulns = response

        if (len(vulns) == 0):
            logger.info(f"No Red Hat CVE entry found for {cve_id}")
            return {}

        if (len(vulns) > 1):
            logger.warning(f"Found multiple Red Hat CVE entries for {cve_id}, using the first one")

        response_full = await self.request(method='GET',
                                           url=url_join(self.base_url, "securitydata", f"cve/{cve_id}.json"))

        return response_full

    async def get_intel(self, cve_id: str) -> CveIntelRhsa:
        intel_dict = await self.get_intel_dict(cve_id)

        return CveIntelRhsa.model_validate(intel_dict)
