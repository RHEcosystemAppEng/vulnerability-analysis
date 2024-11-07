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


import typing
from abc import abstractmethod

import aiohttp

from ...utils.async_http_utils import request_with_retry


class IntelClient:

    def __init__(self,
                 *,
                 session: aiohttp.ClientSession | None,
                 base_url: str | None = None,
                 retry_count: int = 10,
                 sleep_time: float = 0.1,
                 respect_retry_after_header: bool = True):

        if (session is None):
            session = aiohttp.ClientSession()

        if (base_url is None):
            base_url = self.default_base_url()

        self._session = session

        self._base_url = base_url
        self._retry_count = retry_count
        self._sleep_time = sleep_time
        self._respect_retry_after_header = respect_retry_after_header

    @classmethod
    @abstractmethod
    def default_base_url(cls) -> str:
        raise NotImplementedError

    @property
    def base_url(self) -> str:
        return self._base_url

    def is_default_base_url(self) -> bool:
        """
        Check if the base URL is the default one

        Returns
        -------
        bool
            True if the base URL is the default one
        """
        return self.base_url == self.default_base_url()

    async def request(self,
                      method: typing.Literal["GET", "POST", "PUT", "PATCH"],
                      url: str,
                      params: dict[str, str] | None = None,
                      headers: dict[str, str] | None = None,
                      log_on_error=True,
                      **kwargs):

        async with request_with_retry(session=self._session,
                                      request_kwargs={
                                          'method': method, 'url': url, "params": params, "headers": headers, **kwargs
                                      },
                                      max_retries=self._retry_count,
                                      sleep_time=self._sleep_time,
                                      respect_retry_after_header=self._respect_retry_after_header,
                                      log_on_error=log_on_error) as response:

            return await response.json()
