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

import pytest

from vuln_analysis.utils.js_extended_parser import ExtendedJavaScriptSegmenter

TEST_CASES = [
    {
        "name":
            "regular_script",
        "code":
            """
function hello() {
    console.log('Hello');
}

class MyClass {
    constructor() {
        this.value = 42;
    }
}
""",
        "expected_functions":
            2,  # One function and one class
        "should_parse":
            True,
    },
    {
        "name":
            "es_module",
        "code":
            """
import { something } from './module';
export function exportedFunc() {
    return 'exported';
}
export class ExportedClass {
    method() {}
}
""",
        "expected_functions":
            2,  # One exported function and one exported class
        "should_parse":
            True,
    },
    {
        "name":
            "optional_chaining",
        "code":
            """
function processUser(user) {
    return user?.profile?.name;
}
class UserManager {
    getAddress() {
        return this.user?.address?.street;
    }
}
""",
        "expected_functions":
            2,
        "should_parse":
            True,
    },
    {
        "name": "shebang_file",
        "code": """#!/usr/bin/env node
function main() {
    console.log('Main');
}
""",
        "expected_functions": 0,  # Should skip due to shebang
        "should_parse": False,
    }
]


@pytest.mark.parametrize("test_case", TEST_CASES, ids=lambda x: x["name"])
def test_function_extraction(test_case):
    """Test that functions and classes are correctly extracted."""
    segmenter = ExtendedJavaScriptSegmenter(test_case["code"])
    functions = segmenter.extract_functions_classes()
    assert len(functions) == test_case["expected_functions"]
    if not test_case["should_parse"]:
        assert segmenter.skip_file


@pytest.mark.parametrize("test_case", TEST_CASES, ids=lambda x: x["name"])
def test_code_simplification(test_case):
    """Test that code is correctly simplified."""
    segmenter = ExtendedJavaScriptSegmenter(test_case["code"])
    simplified = segmenter.simplify_code()

    # Basic checks
    assert isinstance(simplified, str)
    if not test_case["should_parse"]:
        assert segmenter.skip_file
        assert simplified == test_case["code"]  # Return original code for unparseable files
    else:
        # Should have fewer or equal lines than original
        assert len(simplified.splitlines()) <= len(test_case["code"].splitlines())
        # Should contain "// Code for:" for each function/class
        if test_case["expected_functions"] > 0:
            assert "// Code for:" in simplified


def test_optional_chaining_replacement():
    """Test that optional chaining is correctly replaced."""
    code = "const name = user?.profile?.name;"
    segmenter = ExtendedJavaScriptSegmenter(code)
    assert not segmenter.skip_file
    assert "?." not in segmenter.code
    assert "." in segmenter.code


def test_invalid_js():
    """Test handling of invalid JavaScript code."""
    code = "this is not valid javascript"
    segmenter = ExtendedJavaScriptSegmenter(code)
    assert not segmenter.skip_file  # Should attempt to parse

    # Should handle errors gracefully
    functions = segmenter.extract_functions_classes()
    assert functions == []

    simplified = segmenter.simplify_code()
    assert simplified == code  # Return original code for invalid JS
