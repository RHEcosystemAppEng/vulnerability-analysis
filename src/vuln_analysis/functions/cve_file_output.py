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


class CVEFileOutputConfig(FunctionBaseConfig, name="cve_file_output"):
    """
    Defines a function that outputs workflow results to a file.
    """
    file_path: str | None = Field(default="./.tmp/output.json",
                                  description="Defines the path to the file where the output will be saved.")
    markdown_dir: str | None = Field(
        default="./.tmp/vulnerability_markdown_reports",
        description=
        "Defines the path to the directory where the output will be saved in individual navigable markdown files "
        "per CVE-ID.")
    overwrite: bool = Field(
        default=False,
        description=
        "Indicates whether the output file should be overwritten when the pipeline starts if it already exists.")


@register_function(config_type=CVEFileOutputConfig)
async def output_to_file(config: CVEFileOutputConfig, builder: Builder):  # pylint: disable=unused-argument

    import os
    from pathlib import Path

    from vuln_analysis.data_models.output import AgentMorpheusOutput
    from vuln_analysis.utils.output_formatter import generate_vulnerability_reports

    if (os.path.exists(config.file_path)):
        if (config.overwrite):
            logger.warning("Overwriting existing file: %s", config.file_path)
            os.remove(config.file_path)
        else:
            logger.info("Appending to existing file: %s", config.file_path)
    else:
        # Ensure our directory exists
        os.makedirs(os.path.realpath(os.path.dirname(config.file_path)), exist_ok=True)

    async def _arun(message: AgentMorpheusOutput) -> AgentMorpheusOutput:

        file_path = Path(config.file_path)

        # Write file depending on setting for overwrite
        model_json = message.model_dump_json(by_alias=True)

        file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, 'a', encoding='utf-8') as f:
            f.write(model_json)
            f.write("\n")

        if config.markdown_dir is not None:
            generate_vulnerability_reports(message, config.markdown_dir)

        return message

    yield FunctionInfo.from_fn(_arun,
                               input_schema=AgentMorpheusOutput,
                               description=("Outputs workflow results to a file."))
