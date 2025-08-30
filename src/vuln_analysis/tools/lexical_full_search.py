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
from nat.builder.framework_enum import LLMFrameworkEnum
from nat.builder.function_info import FunctionInfo
from nat.cli.register_workflow import register_function
from nat.data_models.function import FunctionBaseConfig
from pydantic import Field

logger = logging.getLogger(__name__)


class LexicalSearchToolConfig(FunctionBaseConfig, name="lexical_code_search"):
    """
    Lexical search tool used to search source code.
    """
    top_k: int = Field(default=5, description="Top K to use for the lexical search")


@register_function(config_type=LexicalSearchToolConfig, framework_wrappers=[LLMFrameworkEnum.LANGCHAIN])
async def lexical_search(config: LexicalSearchToolConfig, builder: Builder):  # pylint: disable=unused-argument
    from vuln_analysis.functions.cve_agent import ctx_state
    from vuln_analysis.utils.full_text_search import FullTextSearch

    async def _arun(query: str) -> list:

        workflow_state = ctx_state.get()
        code_index_path = workflow_state.code_index_path
        full_text_search = FullTextSearch(cache_path=code_index_path)

        if full_text_search.is_empty():
            raise ValueError(f"Invalid code index at: {code_index_path}, index is empty")

        result = full_text_search.search_index(query, config.top_k)

        return result

    yield FunctionInfo.from_fn(
        _arun,
        description=("Useful for when you need to check if an application or any dependency "
                     "within the container image uses a function or a component of a library "
                     "using keyword search. This tool uses keyword to search code index, and "
                     "the argument should be a string keyword. You should use this search "
                     "tool for searching codes before trying other container search related tools."))
