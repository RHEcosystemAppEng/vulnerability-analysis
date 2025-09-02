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

import re

# Find all substrings that start and end with quotes, allowing for spaces before a comma or closing bracket
re_quote_capture = re.compile(
    r"""
        (['"])                    # Opening quote
        (                         # Start capturing the quoted content
            (?:\\.|[^\\])*?       # Non-greedy match for any escaped character or non-backslash character
        )                         # End capturing the quoted content
        \1                        # Matching closing quote
        (?=\s*,|\s*\])            # Lookahead for whitespace followed by a comma or closing bracket, without including it in the match
    """,
    re.VERBOSE)

# Using the ASCII flag to stricly match numbers 0-9 and not on unicode numbers which include characters like ٤.
# https://cve.mitre.org/cve/identifiers/syntaxchange.html
CVE_RE = re.compile(r'^CVE-[0-9]{4}-[0-9]{4,}$', re.ASCII)
# https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database#about-ghsa-ids
GHSA_RE = re.compile(r'^GHSA(-[23456789cfghjmpqrvwx]{4}){3}', re.ASCII)


def is_valid_ghsa_id(ghsa_id):
    return False if ghsa_id is None else GHSA_RE.match(ghsa_id) is not None


def is_valid_cve_id(cve_id):
    return False if cve_id is None else CVE_RE.match(cve_id) is not None


def attempt_fix_list_string(s: str) -> str:
    """
    Attempt to fix unescaped quotes in a string that represents a list to make it parsable.

    Parameters
    ----------
    s : str
        A string representation of a list that potentially contains unescaped quotes.

    Returns
    -------
    str
        The corrected string where internal quotes are properly escaped, ensuring it can be parsed as a list.

    Notes
    -----
    This function is useful for preparing strings to be parsed by `ast.literal_eval` by ensuring that quotes inside
    the string elements of the list are properly escaped. It adds brackets at the beginning and end if they are missing.
    """
    # Check if the input starts with '[' and ends with ']'
    s = s.strip()
    if (not s.startswith('[')):
        s = "[" + s
    if (not s.endswith(']')):
        s = s + "]"

    def fix_quotes(match):
        # Extract the captured groups
        quote_char, content = match.group(1), match.group(2)
        # Escape quotes inside the string content
        fixed_content = re.sub(r"(?<!\\)(%s)" % re.escape(quote_char), r'\\\1', content)
        # Reconstruct the string with escaped quotes and the same quote type as the delimiters
        return f"{quote_char}{fixed_content}{quote_char}"

    # Fix the quotes inside the strings
    fixed_s = re_quote_capture.sub(fix_quotes, s)

    return fixed_s


def remove_number_prefix(text: str) -> str:
    """
    Removes number prefix, e.g. '1.' from a string and returns the modified string.
    """
    # Regular expression pattern to match 'number.' at the beginning of the string
    pattern = r'^\d+\.'

    # Strip any leading whitespace that could interfere with regex
    text = text.lstrip()
    # Remove the matching pattern (if found)
    text = re.sub(pattern, '', text)
    # Strip any remaining whitespace
    text = text.strip()
    return text


def get_checklist_item_string(item_num: int, item: dict) -> str:
    """
    Formats and returns a string containing the checklist item number, question, and answer.
    """
    question = remove_number_prefix(item['input'])
    answer = remove_number_prefix(item['output'])
    return f"- Checklist Item {item_num}: {question}\n  - Answer: {answer}"


def package_names_match(pkg1: str, pkg2: str) -> bool:
    """
    Compares two package names to determine if they represent the same package,
    ignoring version numbers and the optional 'g' suffix at the end.

    Package names that follow the GNU versioning convention (e.g., 'zlib1g')
    will have the version-like part (numbers and 'g') removed before comparison.
    """
    # Regex pattern to match version numbers and optional 'g' at the end of the package name
    version_pattern = r'([0-9]+(\.[0-9]+)*g?)$'

    # Convert both package names to lowercase and remove version and 'g' suffix
    cleaned_pkg1 = re.sub(version_pattern, '', pkg1.lower())
    cleaned_pkg2 = re.sub(version_pattern, '', pkg2.lower())

    return cleaned_pkg1 == cleaned_pkg2
