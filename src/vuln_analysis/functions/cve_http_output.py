# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

from nat.builder.builder import Builder
from nat.builder.function_info import FunctionInfo
from nat.cli.register_workflow import register_function
from nat.data_models.function import FunctionBaseConfig
from pydantic import Field

logger = logging.getLogger(__name__)


class CVEHttpOutputConfig(FunctionBaseConfig, name="cve_http_output"):
    """
    Defines a function that sends CVE workflow output to HTTP endpoint.
    """
    url: str = Field(description="URL to send CVE workflow output")
    endpoint: str = Field(description="Endpoint to send CVE workflow output")


@register_function(config_type=CVEHttpOutputConfig)
async def output_to_http(config: CVEHttpOutputConfig, builder: Builder):  # pylint: disable=unused-argument

    from vuln_analysis.data_models.output import AgentMorpheusOutput
    from vuln_analysis.utils import http_utils

    async def _arun(message: AgentMorpheusOutput) -> AgentMorpheusOutput:

        model_json = message.model_dump_json(by_alias=True)
        url = config.url + config.endpoint
        headers = {'Content-type': 'application/json'}
        try:
            http_utils.request_with_retry(request_kwargs={
                "url": url, "method": "POST", "data": model_json.encode('utf-8'), "headers": headers
            })
        except Exception as e:
            logger.error('Unable to send output response to %s. Error: %s', url, e)
        else:
            logger.info('Successfully sent output to %s', url)

        return message

    yield FunctionInfo.from_fn(_arun,
                               input_schema=AgentMorpheusOutput,
                               description=("Sends CVE workflow output to HTTP endpoint."))
