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

# Some examples to be optionally passed along in the agent prompt.
from abc import ABC
from abc import abstractmethod
from textwrap import dedent

# pylint: disable=line-too-long

SUMMARY_PROMPT = """Summarize the exploitability investigation results of a Common Vulnerabilities and Exposures (CVE) \
based on the provided Checklist and Findings. Write a concise paragraph focusing only on checklist items with \
definitive answers. Begin your response by clearly stating whether the CVE is exploitable. Disregard any ambiguous \
checklist items.
Checklist and Findings:
{response}"""

# Define a system prompt that sets the context for the language model's task. This prompt positions the assistant
# as a powerful entity capable of investigating CVE impacts on container images.
AGENT_SYS_PROMPT = (
    "You are a very powerful assistant who helps investigate the impact of reported Common Vulnerabilities and "
    "Exposures (CVE) on container images. Information about the container image under investigation is "
    "stored in vector databases available to you via tools.")

# Based on original prompt: https://github.com/langchain-ai/langchain/blob/master/libs/langchain/langchain/agents/mrkl/prompt.py
AGENT_PROMPT_TEMPLATE = """If the input is not a question, formulate it into a question first. Include intermediate thought in the final answer. You have access to the following tools:

{tools}

Use the following format (start each response with one of the following prefixes: [Question, Thought, Action, Action Input, Final Answer]):

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question

Begin!

Question: {input}
Thought:{agent_scratchpad}"""

AGENT_EXAMPLES_FOR_PROMPT = """Example 1:

    Question: 1. Identify the version of Python: Check which version(s) of Python are installed in the container image. The vulnerability affects versions up to and including 3.11.3.
    Thought: I should check if Python is installed. I will check the Software Bill of Materials.
    Action: SBOM Package Checker
    Action Input: Python
    Observation: 3.10.0
    Thought: Python 3.10.0 is installed, I need to check if the installed version is vulnerable. To do this I'll compare the installed version to the vulnerable version.
    Action: container software version comparator
    Action Input: 3.10.0, 3.11.3
    Observation: True
    Thought: The installed software is vulnerable. I now know the answer.
    Final Answer: Python version 3.10.0 is installed and is vulnerable to the CVE.

    Example 2:

    Question: Assess the threat that CVE-20xx-xxxxx poses to the container.
    Thought: I should search for more information on CVE-20xx-xxxxx.
    Action: Internet Search
    Action Input: What is CVE-20xx-xxxxx?
    Observation: CVE-20xx-xxxxx causes memory leaks and possible denial of service attack vectors when using urllib.parse
    Thought: I should check the code base of the container for instances of urllib.parse
    Action: Container Image QA System
    Action Input: Is urllib.parse present in the code?
    Observation:
    Question: Is urllib.parse present in the code?
    Helpful answer: No, that function is not called in the code.
    Thought: Since the function is not called in the code, the container is not vulnerable. I know the final answer.
    Final Answer: The function urllib.parse is not present in the code, so the container is not vulnerable.

    Example 3:

    Question: Check if the container is using Java Runtime Environment (JRE). If it is not using JRE, then it is not vulnerable to CVE-xxxx-xxxxx.
    Thought: I should check if JRE is installed. I will check the Software Bill of Materials.
    Action: SBOM Package Checker
    Action Input: JRE
    Observation: False
    Thought: JRE is not present in the container.  I now know the answer.
    Final Answer: JRE is not installed in the container. Therefore, it is not vulnerable to CVE-20xx-xxxxx.

    Example 4:

    Question: Check if the container is using Apache. If it is not using Apache, then it is not vulnerable to CVE-xxxx-xxxxx.
    Thought: I should check if Apache is installed. I will check the Software Bill of Materials.
    Action: SBOM Package Checker
    Action Input: Apache
    Observation: 1.0.1
    Thought: Apache is present in the container.  I now know the answer.
    Final Answer: Apache is installed in the container. Therefore, it is potentially vulnerable to CVE-20xx-xxxxx.

    """


def get_agent_prompt(sys_prompt: str | None = None, prompt_examples: bool = False) -> str:
    """
    Get the agent prompt based on the system prompt and whether to include examples.
    """
    sys_prompt = sys_prompt or AGENT_SYS_PROMPT

    if prompt_examples:
        prompt_template = AGENT_PROMPT_TEMPLATE.replace("Begin!\n\n", AGENT_EXAMPLES_FOR_PROMPT + "Begin!\n\n")
    else:
        prompt_template = AGENT_PROMPT_TEMPLATE

    return f'{sys_prompt} {prompt_template}'


class PromptBuilder(ABC):

    @abstractmethod
    def build_prompt(self) -> str:
        pass


class IfPromptBuilder(PromptBuilder):

    def __init__(self, prop_name: str, description: str) -> None:

        self.prop_name = prop_name
        self.description = description

    def build_prompt(self) -> str:

        f_string = dedent(f"""
        {{% if {self.prop_name} %}}
        - {self.description}{{{{{self.prop_name} | string() | truncate(1024)}}}}
        {{% endif %}}
        """).strip()

        return f_string


class IfElsePromptBuilder(PromptBuilder):

    def __init__(self, first_prop_name: str, second_prop_name: str, description: str) -> None:

        self.first_prop_name = first_prop_name
        self.second_prop_name = second_prop_name
        self.description = description

    def build_prompt(self) -> str:

        f_string = dedent(f"""
        {{% if {self.first_prop_name} %}}
        - {self.description}{{{{{self.first_prop_name} | string() | truncate(1024)}}}}
        {{% elif {self.second_prop_name} %}}
        - {self.description}{{{{{self.second_prop_name} | string() | truncate(1024)}}}}
        {{% endif %}}
        """).strip()

        return f_string


# Add additional intel fields for the checklist prompt here (field name, description)
additional_intel_fields: list[PromptBuilder] = [
    # Keep these at the top
    IfPromptBuilder('cve_id', 'CVE ID: '),
    IfElsePromptBuilder('nvd_cve_description', "ghsa_description", 'CVE Description: '),

    # Sort these alphabetically
    IfElsePromptBuilder('nvd_cvss_vector', "ghsa_cvss_vector_string", 'CVSS Vector: '),
    IfElsePromptBuilder('nvd_cwe_name', "ghsa_cwes", 'CWE Name: '),
    IfPromptBuilder('ghsa_vulnerabilities', 'GHSA Details: '),
    IfPromptBuilder('nvd_configurations', 'Known Affected Software: '),
    IfPromptBuilder('nvd_cwe_description', 'CWE Description: '),
    IfPromptBuilder('nvd_cwe_extended_description', ''),
    IfPromptBuilder('nvd_vendor_names', 'Notable Vulnerable Software Vendors: '),
    IfPromptBuilder('rhsa_bugzilla_description', 'RHSA Description: '),
    IfPromptBuilder('rhsa_details', 'RHSA Details: '),
    IfPromptBuilder('rhsa_package_state', 'RHSA Affected Packages: '),
    IfPromptBuilder('rhsa_statement', 'RHSA Statement: '),
    # IfPromptBuilder('ubuntu_notices', 'Ubuntu Priority Reason: '), # Disabling for now since its very long
    IfPromptBuilder('ubuntu_ubuntu_description', 'Ubuntu Security Note: '),
    IfPromptBuilder('vulnerable_dependencies', 'Identified Vulnerable Dependencies: '),
]

additional_intel_prompting = '\n'.join([pb.build_prompt() for pb in additional_intel_fields])

ex_questions = [
    'Example {idx}: CVE Details:\n- CVE ID: CVE-2023-24329\n- CVE description: An issue in the urllib.parse component of Python before 3.11.4 allows attackers to bypass blocklisting methods by supplying a URL that starts with blank characters.\n- CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N\n- CWE Name: CWE-20: Improper Input Validation (4.14)\n- CWE Description: The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.\nInput validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with other components. When software does not validate input properly, an attacker is able to craft the input in a form that is not expected by the rest of the application. This will lead to parts of the system receiving unintended input, which may result in altered control flow, arbitrary control of a resource, or arbitrary code execution. Input validation is not the only technique for processing input, however. Other techniques attempt to transform potentially-dangerous input into something safe, such as filtering (CWE-790) - which attempts to remove dangerous inputs - or encoding/escaping (CWE-116), which attempts to ensure that the input is not misinterpreted when it is included in output to another component. Other techniques exist as well (see CWE-138 for more examples.) Input validation can be applied to: raw data - strings, numbers, parameters, file contents, etc. metadata - information about the raw data, such as headers or size Data can be simple or structured. Structured data can be composed of many nested layers, composed of combinations of metadata and raw data, with other simple or structured data. Many properties of raw data or metadata may need to be validated upon entry into the code, such as: specified quantities such as size, length, frequency, price, rate, number of operations, time, etc. implied or derived quantities, such as the actual size of a file instead of a specified size indexes, offsets, or positions into more complex data structures symbolic keys or other elements into hash tables, associative arrays, etc. well-formedness, i.e. syntactic correctness - compliance with expected syntax lexical token correctness - compliance with rules for what is treated as a token specified or derived type - the actual type of the input (or what the input appears to be) consistency - between individual data elements, between raw data and metadata, between references, etc. conformance to domain-specific rules, e.g. business logic equivalence - ensuring that equivalent inputs are treated the same authenticity, ownership, or other attestations about the input, e.g. a cryptographic signature to prove the source of the data Implied or derived properties of data must often be calculated or inferred by the code itself. Errors in deriving properties may be considered a contributing factor to improper input validation. Note that "input validation" has very different meanings to different people, or within different classification schemes. Caution must be used when referencing this CWE entry or mapping to it. For example, some weaknesses might involve inadvertently giving control to an attacker over an input when they should not be able to provide an input at all, but sometimes this is referred to as input validation. Finally, it is important to emphasize that the distinctions between input validation and output escaping are often blurred, and developers must be careful to understand the difference, including how input validation is not always sufficient to prevent vulnerabilities, especially when less stringent data types must be supported, such as free-form text. Consider a SQL injection scenario in which a person\'s last name is inserted into a query. The name "O\'Reilly" would likely pass the validation step since it is a common last name in the English language. However, this valid name cannot be directly inserted into the database because it contains the "\'" apostrophe character, which would need to be escaped or otherwise transformed. In this case, removing the apostrophe might reduce the risk of SQL injection, but it would produce incorrect behavior because the wrong name would be recorded.\n- Notable Vulnerable Software Vendors: [\'Fedoraproject\', \'Netapp\', \'Python\']\n\nExample {idx}: Checklist:\n[\n\t"Review Python Usage: Is the Python installation actively used by applications within the container? Check for scripts or applications that rely on Python, particularly those that might parse URLs using `urllib.parse`.",\n\t"Inspect URL Parsing Logic: Does the codebase contain any usage of `urllib.parse` or similar URL parsing mechanisms? Focus on how URLs are handled and whether there is a reliance on blocklisting methods to filter out potentially harmful URLs. This is crucial since the CVE describes a bypass of blocklisting methods via URLs starting with blank characters.",\n\t"Evaluate Input Validation Practices: Assess the robustness of input validation practices within the application. Since the CVE involves improper input validation, are inputs, especially URLs, properly sanitized and validated against unexpected or malicious data?"\n]',
    'Example {idx}: CVE Details:\n- CVE ID: CVE-2023-36632\n- CVE description: The legacy email.utils.parseaddr function in Python through 3.11.4 allows attackers to trigger "RecursionError: maximum recursion depth exceeded while calling a Python object" via a crafted argument. This argument is plausibly an untrusted value from an application\'s input data that was supposed to contain a name and an e-mail address. NOTE: email.utils.parseaddr is categorized as a Legacy API in the documentation of the Python email package. Applications should instead use the email.parser.BytesParser or email.parser.Parser class. NOTE: the vendor\'s perspective is that this is neither a vulnerability nor a bug. The email package is intended to have size limits and to throw an exception when limits are exceeded; they were exceeded by the example demonstration code.\n- CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H\n- CWE Name: CWE-674: Uncontrolled Recursion (4.14)\n- CWE Description: The product does not properly control the amount of recursion that takes place, consuming excessive resources, such as allocated memory or the program stack.\n- Notable Vulnerable Software Vendors: [\'Python\']\n\nExample {idx}: Checklist:\n[\n\t"Identify Usage of `email.utils.parseaddr`: Review the application code within the container image to check if the `email.utils.parseaddr` function is being used. This function is the specific target of the vulnerability. Does the codebase contain the string \'email.utils.parseaddr\'?",\n\t"Assess Input Data Handling: Does the application using `email.utils.parseaddr` process potentially untrusted input data that could include crafted arguments designed to exploit this vulnerability? Evaluate how the application handles exceptions like `RecursionError`, as the exploit triggers this specific error.",\n\t"Review Alternative Implementations: Has the application already migrated to recommended alternatives such as `email.parser.BytesParser` or `email.parser.Parser` in the code base? If not, recommend transitioning away from the legacy `email.utils.parseaddr` to these safer alternatives."\n]',
    "Example {idx}: CVE Details:\n- CVE ID: CVE-2023-50447\n- CVE description: Pillow through 10.1.0 allows PIL.ImageMath.eval Arbitrary Code Execution via the environment parameter, a different vulnerability than CVE-2022-22817 (which was about the expression parameter).\n- CVSS Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H\n- CWE Name: CWE-94: Improper Control of Generation of Code ('Code Injection') (4.14)\n- CWE Description: The product constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.\nWhen a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product. Such an alteration could lead to arbitrary code execution. Injection problems encompass a wide variety of issues -- all mitigated in very different ways. For this reason, the most effective way to discuss these weaknesses is to note the distinct features which classify them as injection weaknesses. The most important issue to note is that all injection problems share one thing in common -- i.e., they allow for the injection of control plane data into the user-controlled data plane. This means that the execution of the process may be altered by sending code in through legitimate data channels, using no other mechanism. While buffer overflows, and many other flaws, involve the use of some further issue to gain execution, injection problems need only for the data to be parsed. The most classic instantiations of this category of weakness are SQL injection and format string vulnerabilities.\n- Notable Vulnerable Software Vendors: ['Debian', 'Python']\n\nExample {idx}: Checklist:\n[\n\t\"Evaluate Use of PIL.ImageMath.eval: Does any application within the container use the PIL.ImageMath.eval function with user-supplied input in the environment parameter? This is the method and parameter where the vulnerability exists.\",\n\t\"Assess Data Input Sources: Do the applications using Pillow receive input directly from untrusted sources (e.g., user uploads, external APIs)? This will help in understanding the risk exposure and potential for exploitation.\",\n\t\"Security Controls and Sanitization: Review the application's input validation and sanitization measures. Since the vulnerability allows for arbitrary code execution via code injection, is the input properly sanitized before being processed?\"\n]",
    'Example {idx}: CVE Details:\n- CVE ID: CVE-2023-5363\n- CVE description: Issue summary: A bug has been identified in the processing of key and initialisation vector (IV) lengths. This can lead to potential truncation or overruns during the initialisation of some symmetric ciphers. Impact summary: A truncation in the IV can result in non-uniqueness, which could result in loss of confidentiality for some cipher modes. When calling EVP_EncryptInit_ex2(), EVP_DecryptInit_ex2() or EVP_CipherInit_ex2() the provided OSSL_PARAM array is processed after the key and IV have been established. Any alterations to the key length, via the "keylen" parameter or the IV length, via the "ivlen" parameter, within the OSSL_PARAM array will not take effect as intended, potentially causing truncation or overreading of these values. The following ciphers and cipher modes are impacted: RC2, RC4, RC5, CCM, GCM and OCB. For the CCM, GCM and OCB cipher modes, truncation of the IV can result in loss of confidentiality. For example, when following NIST\'s SP 800-38D section 8.2.1 guidance for constructing a deterministic IV for AES in GCM mode, truncation of the counter portion could lead to IV reuse. Both truncations and overruns of the key and overruns of the IV will produce incorrect results and could, in some cases, trigger a memory exception. However, these issues are not currently assessed as security critical.\nChanging the key and/or IV lengths is not considered to be a common operation and the vulnerable API was recently introduced. Furthermore it is likely that application developers will have spotted this problem during testing since decryption would fail unless both peers in the communication were similarly vulnerable. For these reasons we expect the probability of an application being vulnerable to this to be quite low. However if an application is vulnerable then this issue is considered very serious. For these reasons we have assessed this issue as Moderate severity overall.\nThe OpenSSL SSL/TLS implementation is not affected by this issue. The OpenSSL 3.0 and 3.1 FIPS providers are not affected by this because the issue lies outside of the FIPS provider boundary. OpenSSL 3.1 and 3.0 are vulnerable to this issue.\n- CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N\n- Notable Vulnerable Software Vendors: [\'Debian\', \'Netapp\', \'Openssl\']\n\nExample {idx}: Checklist:\n[\n\t"Check OpenSSL Version: What version of OpenSSL is running in the container image? The vulnerability specifically affects OpenSSL versions 3.0 and 3.1. Is the version running in the container within the vulnerability range? If the container is running these versions, it may be vulnerable.",\n\t"Identify Affected Cipher Modes: Does the application within the container image use any of the affected cipher modes: RC2, RC4, RC5, CCM, GCM, or OCB? Special attention should be given to applications using CCM, GCM, and OCB modes as these are particularly noted for potential loss of confidentiality due to IV truncation.",\n\t"Review Cryptographic Operations: Does the code or configuration of applications using OpenSSL have any instances where `EVP_EncryptInit_ex2()`, `EVP_DecryptInit_ex2()`, or `EVP_CipherInit_ex2()` are called? Are there any modifications to the `keylen` or `ivlen` parameters after initialization which might not be taking effect as intended?",\n\t"Check for Custom Cryptographic Implementations: Since changing the key and/or IV lengths is not a common operation and the issue is in a recently introduced API, it\'s crucial to identify if any custom cryptographic implementations might be performing such operations. This is less likely but should be checked especially in bespoke or highly customized applications. Are there any custom cryptographic implemenations changing the key and/or IV lengths?"\n]',
    'Example {idx}: CVE Details:\n- CVE ID: CVE-2024-2961\n- CVE description: The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.\n- CWE Name: CWE-787: Out-of-bounds Write (4.14)\n- CWE Description: The product writes data past the end, or before the beginning, of the intended buffer.\nTypically, this can result in corruption of data, a crash, or code execution. The product may modify an index or perform pointer arithmetic that references a memory location that is outside of the boundaries of the buffer. A subsequent write operation then produces undefined or unexpected results.\n- Notable Vulnerable Software Vendors: [\'GNU\']\n\nExample {idx}: Checklist:\n[\n\t"Identify Usage of `iconv()` Function: Review the application code or dependencies. Is the `iconv()` function used? Look particularly for conversions involving the ISO-2022-CN-EXT character set. This function is the specific target of the vulnerability.",\n\t"Assess Data Handling and Boundary Conditions: Since the vulnerability involves an out-of-bounds write, it\'s crucial to analyze how data boundaries are handled in the code. Are there any custom implementations or patches that might mitigate boundary issues around buffer sizes?",\n\t"Review Application\'s Character Encoding Needs: Does the application specifically need to handle the ISO-2022-CN-EXT character set? If not, consider disabling this character set or using alternative safe functions or libraries for character set conversions.",\n\t"Evaluate Network Exposure and Attack Surface: Are the affected services exposed to the network? If so, this could increase the risk of exploitation. Additionally, if the application using the `iconv()` function is accessible externally, the risk is higher."\n]',
    "Example {idx}: CVE Details:\n- CVE ID: GHSA-8ghj-p4vj-mr35\n- CVE description: An issue was discovered in Pillow before 10.0.0. It is a Denial of Service that uncontrollably allocates memory to process a given task, potentially causing a service to crash by having it run out of memory. This occurs for truetype in ImageFont when textlength in an ImageDraw instance operates on a long text argument.\n- CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H\n- CWE Name: CWE-770: Allocation of Resources Without Limits or Throttling (4.14)\n- CWE Description: The product allocates a reusable resource or group of resources on behalf of an actor without imposing any restrictions on the size or number of resources that can be allocated, in violation of the intended security policy for that actor.\n- Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily. Without use of quotas, resource limits, or other protection mechanisms, it can be easy for an attacker to consume many resources by rapidly making many requests, or causing larger resources to be used than is needed. When too many resources are allocated, or if a single resource is too large, then it can prevent the code from working correctly, possibly leading to a denial of service.\n- Notable Vulnerable Software Vendors: ['Fedoraproject', 'Python']\n- GHSA Summary: Pillow Denial of Service vulnerability\n- GHSA Details: [<'first_patched_version': '10.0.0', 'package': <'ecosystem': 'pip', 'name': 'pillow'>, 'vulnerable_functions': ['PIL.ImageFont'], 'vulnerable_version_range': '>= 0, < 10.0.0'>]\n- GHSA CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H\n\nExample {idx}: Checklist:\n[\n\t\"Assess Usage of Vulnerable Functions: Specifically, the vulnerability is related to the `PIL.ImageFont` module when processing long text arguments. Does the application code or dependencies use this module and functionality? If your applications use this module to process user-supplied or uncontrolled text inputs, they are likely at risk.\",\n\t\"Evaluate Resource Limits: The vulnerability leads to a denial of service through memory exhaustion. Are there any resource limits set at the container level (e.g., using Docker or Kubernetes settings) that might mitigate the impact of such an attack? Consider setting or reviewing memory limits to prevent a single container from consuming all available system resources.\"\n]",
]

ex_statements = [
    'Example {idx}: CVE Details:\n- CVE ID: CVE-2023-24329\n- CVE description: An issue in the urllib.parse component of Python before 3.11.4 allows attackers to bypass blocklisting methods by supplying a URL that starts with blank characters.\n- CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N\n- CWE Name: CWE-20: Improper Input Validation (4.14)\n- CWE Description: The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.\nInput validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with other components. When software does not validate input properly, an attacker is able to craft the input in a form that is not expected by the rest of the application. This will lead to parts of the system receiving unintended input, which may result in altered control flow, arbitrary control of a resource, or arbitrary code execution. Input validation is not the only technique for processing input, however. Other techniques attempt to transform potentially-dangerous input into something safe, such as filtering (CWE-790) - which attempts to remove dangerous inputs - or encoding/escaping (CWE-116), which attempts to ensure that the input is not misinterpreted when it is included in output to another component. Other techniques exist as well (see CWE-138 for more examples.) Input validation can be applied to: raw data - strings, numbers, parameters, file contents, etc. metadata - information about the raw data, such as headers or size Data can be simple or structured. Structured data can be composed of many nested layers, composed of combinations of metadata and raw data, with other simple or structured data. Many properties of raw data or metadata may need to be validated upon entry into the code, such as: specified quantities such as size, length, frequency, price, rate, number of operations, time, etc. implied or derived quantities, such as the actual size of a file instead of a specified size indexes, offsets, or positions into more complex data structures symbolic keys or other elements into hash tables, associative arrays, etc. well-formedness, i.e. syntactic correctness - compliance with expected syntax lexical token correctness - compliance with rules for what is treated as a token specified or derived type - the actual type of the input (or what the input appears to be) consistency - between individual data elements, between raw data and metadata, between references, etc. conformance to domain-specific rules, e.g. business logic equivalence - ensuring that equivalent inputs are treated the same authenticity, ownership, or other attestations about the input, e.g. a cryptographic signature to prove the source of the data Implied or derived properties of data must often be calculated or inferred by the code itself. Errors in deriving properties may be considered a contributing factor to improper input validation. Note that "input validation" has very different meanings to different people, or within different classification schemes. Caution must be used when referencing this CWE entry or mapping to it. For example, some weaknesses might involve inadvertently giving control to an attacker over an input when they should not be able to provide an input at all, but sometimes this is referred to as input validation. Finally, it is important to emphasize that the distinctions between input validation and output escaping are often blurred, and developers must be careful to understand the difference, including how input validation is not always sufficient to prevent vulnerabilities, especially when less stringent data types must be supported, such as free-form text. Consider a SQL injection scenario in which a person\'s last name is inserted into a query. The name "O\'Reilly" would likely pass the validation step since it is a common last name in the English language. However, this valid name cannot be directly inserted into the database because it contains the "\'" apostrophe character, which would need to be escaped or otherwise transformed. In this case, removing the apostrophe might reduce the risk of SQL injection, but it would produce incorrect behavior because the wrong name would be recorded.\n- Notable Vulnerable Software Vendors: [\'Fedoraproject\', \'Netapp\', \'Python\']\n\nExample {idx}: Checklist:\n[\n\t"Check Python Version: Determine the version of Python installed in the container image. The vulnerability affects Python versions before 3.11.4. Use commands like `python --version` or `python3 --version` to check the installed version. If the version is below 3.11.4, the container may be vulnerable.",\n\t"Review Python Usage: Identify if the Python installation is actively used by applications within the container. Check for scripts or applications that rely on Python, particularly those that might parse URLs using `urllib.parse`.",\n\t"Inspect URL Parsing Logic: Examine the codebase for any usage of `urllib.parse` or similar URL parsing mechanisms. Focus on how URLs are handled and whether there is a reliance on blocklisting methods to filter out potentially harmful URLs. This is crucial since the CVE describes a bypass of blocklisting methods via URLs starting with blank characters.",\n\t"Evaluate Input Validation Practices: Assess the robustness of input validation practices within the application. Since the CVE involves improper input validation, ensure that inputs, especially URLs, are properly sanitized and validated against unexpected or malicious data."\n]',
    'Example {idx}: CVE Details:\n- CVE ID: CVE-2023-36632\n- CVE description: The legacy email.utils.parseaddr function in Python through 3.11.4 allows attackers to trigger "RecursionError: maximum recursion depth exceeded while calling a Python object" via a crafted argument. This argument is plausibly an untrusted value from an application\'s input data that was supposed to contain a name and an e-mail address. NOTE: email.utils.parseaddr is categorized as a Legacy API in the documentation of the Python email package. Applications should instead use the email.parser.BytesParser or email.parser.Parser class. NOTE: the vendor\'s perspective is that this is neither a vulnerability nor a bug. The email package is intended to have size limits and to throw an exception when limits are exceeded; they were exceeded by the example demonstration code.\n- CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H\n- CWE Name: CWE-674: Uncontrolled Recursion (4.14)\n- CWE Description: The product does not properly control the amount of recursion that takes place, consuming excessive resources, such as allocated memory or the program stack.\n- Notable Vulnerable Software Vendors: [\'Python\']\n\nExample {idx}: Checklist:\n[\n\t"Identify Usage of `email.utils.parseaddr`: Review the application code within the container image to check if the `email.utils.parseaddr` function is being used. This function is the specific target of the vulnerability. Consider searching the codebase for the string \'email.utils.parseaddr\' to find direct usages.",\n\t"Assess Input Data Handling: Determine if the application using `email.utils.parseaddr` processes potentially untrusted input data that could include crafted arguments designed to exploit this vulnerability. Evaluate how the application handles exceptions like `RecursionError`, as the exploit triggers this specific error.",\n\t"Review Alternative Implementations: Check if the application has already migrated to recommended alternatives such as `email.parser.BytesParser` or `email.parser.Parser`. If not, recommend transitioning away from the legacy `email.utils.parseaddr` to these safer alternatives."\n]',
    "Example {idx}: CVE Details:\n- CVE ID: CVE-2023-50447\n- CVE description: Pillow through 10.1.0 allows PIL.ImageMath.eval Arbitrary Code Execution via the environment parameter, a different vulnerability than CVE-2022-22817 (which was about the expression parameter).\n- CVSS Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H\n- CWE Name: CWE-94: Improper Control of Generation of Code ('Code Injection') (4.14)\n- CWE Description: The product constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.\nWhen a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product. Such an alteration could lead to arbitrary code execution. Injection problems encompass a wide variety of issues -- all mitigated in very different ways. For this reason, the most effective way to discuss these weaknesses is to note the distinct features which classify them as injection weaknesses. The most important issue to note is that all injection problems share one thing in common -- i.e., they allow for the injection of control plane data into the user-controlled data plane. This means that the execution of the process may be altered by sending code in through legitimate data channels, using no other mechanism. While buffer overflows, and many other flaws, involve the use of some further issue to gain execution, injection problems need only for the data to be parsed. The most classic instantiations of this category of weakness are SQL injection and format string vulnerabilities.\n- Notable Vulnerable Software Vendors: ['Debian', 'Python']\n\nExample {idx}: Checklist:\n[\n\t\"Evaluate Use of PIL.ImageMath.eval: Specifically investigate whether any application within the container uses the PIL.ImageMath.eval function with user-supplied input in the environment parameter. This is the method and parameter where the vulnerability exists.\",\n\t\"Assess Data Input Sources: Determine if the applications using Pillow are receiving input directly from untrusted sources (e.g., user uploads, external APIs). This will help in understanding the risk exposure and potential for exploitation.\",\n\t\"Security Controls and Sanitization: Review the application's input validation and sanitization measures. Since the vulnerability allows for arbitrary code execution via code injection, ensuring that input is properly sanitized before being processed can mitigate potential exploitation.\"\n]",
    'Example {idx}: CVE Details:\n- CVE ID: CVE-2023-5363\n- CVE description: Issue summary: A bug has been identified in the processing of key and initialisation vector (IV) lengths. This can lead to potential truncation or overruns during the initialisation of some symmetric ciphers. Impact summary: A truncation in the IV can result in non-uniqueness, which could result in loss of confidentiality for some cipher modes. When calling EVP_EncryptInit_ex2(), EVP_DecryptInit_ex2() or EVP_CipherInit_ex2() the provided OSSL_PARAM array is processed after the key and IV have been established. Any alterations to the key length, via the "keylen" parameter or the IV length, via the "ivlen" parameter, within the OSSL_PARAM array will not take effect as intended, potentially causing truncation or overreading of these values. The following ciphers and cipher modes are impacted: RC2, RC4, RC5, CCM, GCM and OCB. For the CCM, GCM and OCB cipher modes, truncation of the IV can result in loss of confidentiality. For example, when following NIST\'s SP 800-38D section 8.2.1 guidance for constructing a deterministic IV for AES in GCM mode, truncation of the counter portion could lead to IV reuse. Both truncations and overruns of the key and overruns of the IV will produce incorrect results and could, in some cases, trigger a memory exception. However, these issues are not currently assessed as security critical.\nChanging the key and/or IV lengths is not considered to be a common operation and the vulnerable API was recently introduced. Furthermore it is likely that application developers will have spotted this problem during testing since decryption would fail unless both peers in the communication were similarly vulnerable. For these reasons we expect the probability of an application being vulnerable to this to be quite low. However if an application is vulnerable then this issue is considered very serious. For these reasons we have assessed this issue as Moderate severity overall.\nThe OpenSSL SSL/TLS implementation is not affected by this issue. The OpenSSL 3.0 and 3.1 FIPS providers are not affected by this because the issue lies outside of the FIPS provider boundary. OpenSSL 3.1 and 3.0 are vulnerable to this issue.\n- CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N\n- Notable Vulnerable Software Vendors: [\'Debian\', \'Netapp\', \'Openssl\']\n\nExample {idx}: Checklist:\n[\n\t"Identify Affected Cipher Modes: Determine if the application within the container image uses any of the affected cipher modes: RC2, RC4, RC5, CCM, GCM, or OCB. Special attention should be given to applications using CCM, GCM, and OCB modes as these are particularly noted for potential loss of confidentiality due to IV truncation.",\n\t"Review Cryptographic Operations: Examine the code or configuration of applications using OpenSSL for any instances where `EVP_EncryptInit_ex2()`, `EVP_DecryptInit_ex2()`, or `EVP_CipherInit_ex2()` are called. Check if there are any modifications to the `keylen` or `ivlen` parameters after initialization which might not be taking effect as intended.",\n\t"Check for Custom Cryptographic Implementations: Since changing the key and/or IV lengths is not a common operation and the issue is in a recently introduced API, it\'s crucial to identify if any custom cryptographic implementations might be performing such operations. This is less likely but should be checked especially in bespoke or highly customized applications."\n]',
    'Example {idx}: CVE Details:\n- CVE ID: CVE-2024-2961\n- CVE description: The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to crash an application or overwrite a neighbouring variable.\n- CWE Name: CWE-787: Out-of-bounds Write (4.14)\n- CWE Description: The product writes data past the end, or before the beginning, of the intended buffer.\nTypically, this can result in corruption of data, a crash, or code execution. The product may modify an index or perform pointer arithmetic that references a memory location that is outside of the boundaries of the buffer. A subsequent write operation then produces undefined or unexpected results.\n- Notable Vulnerable Software Vendors: [\'GNU\']\n\nExample {idx}: Checklist:\n[\n\t"Identify Usage of `iconv()` Function: Review the application code or dependencies to check if the `iconv()` function is used, particularly for conversions involving the ISO-2022-CN-EXT character set. This function is the specific target of the vulnerability.",\n\t"Assess Data Handling and Boundary Conditions: Since the vulnerability involves an out-of-bounds write, it\'s crucial to analyze how data boundaries are handled in the code. Look for any custom implementations or patches that might mitigate boundary issues around buffer sizes.",\n\t"Review Application\'s Character Encoding Needs: Determine if the application specifically needs to handle the ISO-2022-CN-EXT character set. If not, consider disabling this character set or using alternative safe functions or libraries for character set conversions.",\n\t"Evaluate Network Exposure and Attack Surface: Consider whether the affected services are exposed to the network, which could increase the risk of exploitation. If the application using the `iconv()` function is accessible externally, the risk is higher."\n]',
    "Example {idx}: CVE Details:\n- CVE ID: GHSA-8ghj-p4vj-mr35\n- CVE description: An issue was discovered in Pillow before 10.0.0. It is a Denial of Service that uncontrollably allocates memory to process a given task, potentially causing a service to crash by having it run out of memory. This occurs for truetype in ImageFont when textlength in an ImageDraw instance operates on a long text argument.\n- CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H\n- CWE Name: CWE-770: Allocation of Resources Without Limits or Throttling (4.14)\n- CWE Description: The product allocates a reusable resource or group of resources on behalf of an actor without imposing any restrictions on the size or number of resources that can be allocated, in violation of the intended security policy for that actor.\n- Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily. Without use of quotas, resource limits, or other protection mechanisms, it can be easy for an attacker to consume many resources by rapidly making many requests, or causing larger resources to be used than is needed. When too many resources are allocated, or if a single resource is too large, then it can prevent the code from working correctly, possibly leading to a denial of service.\n- Notable Vulnerable Software Vendors: ['Fedoraproject', 'Python']\n- GHSA Summary: Pillow Denial of Service vulnerability\n- GHSA Details: [<'first_patched_version': '10.0.0', 'package': <'ecosystem': 'pip', 'name': 'pillow'>, 'vulnerable_functions': ['PIL.ImageFont'], 'vulnerable_version_range': '>= 0, < 10.0.0'>]\n- GHSA CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H\n\nExample {idx}: Checklist:\n[\n\t\"Assess Usage of Vulnerable Functions: Specifically, the vulnerability is related to the `PIL.ImageFont` module when processing long text arguments. Review the application code or dependencies to see if this module and functionality are used. If your applications use this module to process user-supplied or uncontrolled text inputs, they are likely at risk.\",\n\t\"Evaluate Resource Limits: Since the vulnerability leads to a denial of service through memory exhaustion, check if there are any resource limits set at the container level (e.g., using Docker or Kubernetes settings) that might mitigate the impact of such an attack. Consider setting or reviewing memory limits to prevent a single container from consuming all available system resources.\"\n]",
]

FEW_SHOT = """Generate a checklist for a security analyst to use when assessing the exploitability of a specific CVE within a containerized environment. Use the provided examples as a guide to understand how to construct a checklist from a given set of CVE details, then apply this understanding to create a specific checklist for the CVE details provided below. All output should be a comma separated list enclosed in square brackets with each list item enclosed in quotes.

Example 1: CVE Details:
- CVE ID: CVE-2024-23334
- CVE Description: aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. When using aiohttp as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vulnerabilities, resulting in unauthorized access to arbitrary files on the system, even when symlinks are not present. Disabling follow_symlinks and using a reverse proxy are encouraged mitigations. Version 3.9.2 fixes this issue.
- CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
- CWE Name: CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') (4.14)
- CWE Description: The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.
Many file operations are intended to take place within a restricted directory. By using special elements such as ".." and "/" separators, attackers can escape outside of the restricted location to access files or directories that are elsewhere on the system. One of the most common special elements is the "../" sequence, which in most modern operating systems is interpreted as the parent directory of the current location. This is referred to as relative path traversal. Path traversal also covers the use of absolute pathnames such as "/usr/local/bin", which may also be useful in accessing unexpected files. This is referred to as absolute path traversal. In many programming languages, the injection of a null byte (the 0 or NUL) may allow an attacker to truncate a generated filename to widen the scope of attack. For example, the product may add ".txt" to any pathname, thus limiting the attacker to text files, but a null injection may effectively remove this restriction.
- Notable Vulnerable Software Vendors: ['Aiohttp', 'Fedoraproject']

Example 1: Checklist:
[
    "Vulnerable package check. Does the project use the aiohttp library, which is the affected package? If aiohttp is not a dependency in your project, then your code is not vulnerable to this CVE.",
    "Vulnerable version check. Is the version of aiohttp that the project depends on vulnerable? According to the vulnerability details, versions before 3.9.2 are vulnerable.,
    "Review code to check for vulnerability mitigation. Is the 'follow_symlinks' option set to False to mitigate the risk of directory traversal vulnerabilities?"
]

Example 2: CVE Details:
- CVE ID: CVE-2022-2309
- CVE description: NULL Pointer Dereference allows attackers to cause a denial of service (or application crash). This only applies when lxml (version 4.9.0 and earlier) is used together with libxml2 2.9.10 through 2.9.14. libxml2 2.9.9 and earlier are not affected. It allows triggering crashes through forged input data, given a vulnerable code sequence in the application. The vulnerability is caused by the iterwalk function (also used by the canonicalize function). Such code shouldn't be in wide-spread use, given that parsing + iterwalk would usually be replaced with the more efficient iterparse function. However, an XML converter that serialises to C14N would also be vulnerable, for example, and there are legitimate use cases for this code sequence. If untrusted input is received (also remotely) and processed via iterwalk function, a crash can be triggered.
- CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
- CWE Name: CWE-476: NULL Pointer Dereference (4.14)
- CWE Description: A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid, but is NULL, typically causing a crash or exit.
NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.
- Notable Vulnerable Software Vendors: ['Fedoraproject', 'Lxml', 'Xmlsoft']

Example 2: Checklist:
[
    “Vulnerable package check. Does the project use the lxml library, which is the affected package? If lxml is not a dependency in your project, then your code is not vulnerable to this CVE.”,
    “Vulnerable version check. Is the version of lxml that the project depends on vulnerable? According to the vulnerability details, versions 4.9.0 and earlier are vulnerable.”,
    “Vulnerable version check of connected dependency. Is the version of libxml, the connected dependency, that the project depends on vulnerable? The package is only vulnerable if libxml 2.9.10 through 2.9.14 is also present.”,
    “Review code for vulnerable functionality. The library is vulnerable through its `iterwalk` function, which is also utilized by the `canonicalize` function. Are either of these functions used in your code base?”
]

Given CVE Details:
""" + additional_intel_prompting

MOD_FEW_SHOT = """Generate a checklist for a security analyst to use when assessing the exploitability of a specific CVE within a containerized environment. Use the provided examples as a guide to understand how to construct a checklist from a given set of CVE details, then apply this understanding to create a specific checklist for the CVE details provided below. All output should be a comma separated list enclosed in square brackets with each list item enclosed in quotes.

{examples}

Given CVE Details:
"""

investigation_guideline = """1. Is the flagged component in the product? Determine if the container image includes the flagged package version. Verify the presence of the library or software in question by checking the container's software bill of materials (SBOM).
2. Is the vulnerable code of the flagged component in the product? Check if an application or any dependency within the container image uses a function or a component of the library that contains the vulnerability. Check whether a patch has been applied or if the vulnerable code has been removed.
3. Is the vulnerable code of the flagged component executed by the product? Analyze the application's execution paths to confirm whether the vulnerable code is executed during normal operation. Examine the application's dependencies to ensure there are no indirect execution paths that could trigger the vulnerable code.
4. If the vulnerable code is executed, is it exploitable? Investigate whether the exploitability of the issue depends on a specific configuration option and if this configuration is enabled.
5. If the vulnerable code is executed, is it exploitable? Determine if the exploitability relies on a library dependency and verify the existence of this dependency in the product.
6. If the vulnerable code is executed, is it exploitable? Research if the exploitability of the issue depends on a specific environment and verify whether this environment is absent or present in the container.
7. Does other protection exist? Compiler Flags: Assess whether the exploitability hinges on the setting or unsetting of compiler flags.
8. Does other protection exist? Runtime Protections: Investigate the presence of mechanisms that prevent exploits during runtime.
9. Does other protection exist? Perimeter Defenses: Explore protective measures that block attacks at the physical, logical, or network perimeters.
10. Does other protection exist? Mitigating Controls: Identify any mitigating controls in place to prevent exploitability.
"""

ZERO_SHOT = f"""Your task is to create a checklist for a security analyst to help determine if a given CVE is
exploitable in a containerized environment. Use the information provided below, structured within XML tags for both CVE
details and investigation guidelines. The checklist should convert the steps from the investigation guidelines into
actionable steps specific to the CVE. Each step should be self-contained, including details specific to the CVE, and
start with an action verb to clearly state the step the analyst needs to take. Avoid references to the CVE ID, focusing
on providing detailed investigative directions within the steps themselves.
All output should be a comma separated list enclosed in square brackets with each list item enclosed in quotes.\n
{additional_intel_prompting}\n{investigation_guideline}"""

_ONE_SHOT = """This is an example of (1) CVE information, and (2) a checklist produced to determine if a given CVE is exploitable in a containerized environment:
(1) CVE Information:
CVE Description: DISPUTED: In Apache Batik 1.x before 1.10, when deserializing subclass of `AbstractDocument`, the class takes a string from the inputStream as the class name which then use it to call the no-arg constructor of the class. Fix was to check the class type before calling newInstance in deserialization.
CVSS Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
CWE Name: CWE-502: Deserialization of Untrusted Data (4.11)
CWE Description: The product deserializes untrusted data without sufficiently verifying that the resulting data will be valid. It is often convenient to serialize objects for communication or to save them for later use. However, deserialized data or code can often be modified without using the provided accessor functions if it does not use cryptography to protect itself. Furthermore, any cryptography would still be client-side security -- which is a dangerous security assumption. Data that is untrusted can not be trusted to be well-formed. When developers place no restrictions on gadget chains, or series of instances and method invocations that can self-execute during the deserialization process (i.e., before the object is returned to the caller), it is sometimes possible for attackers to leverage them to perform unauthorized actions, like generating a shell.
Notable Vulnerable Software Vendors: ['Oracle', 'Apache', 'Canonical', 'Debian']
(2) Checklist:
Based on the information available, CVE-2018-8013 is a critical vulnerability that involves the deserialization of untrusted data in Apache Batik before version 1.10. The Common Vulnerability Scoring System (CVSS) 3.x score is 9.8, indicating a critical severity.
All output should be a comma separated list enclosed in square brackets with each list item enclosed in quotes.
Here's an example of preliminary checklist similiar to what you should create to determine if a container image is vulnerable to this exploit:
["1. Check the Apache Batik version: The vulnerability affects Apache Batik versions 1.0 to 1.9.1. If your container image is running Apache Batik, verify the version. If it's between 1.0 and 1.9.1, it's vulnerable and you should update to version 1.10 or later.",
"2. Check for any software using vulnerable Apache Batik versions: It's important to note that other applications might use Apache Batik and thus be vulnerable. Check all applications within your container image for dependencies on vulnerable versions of Apache Batik. Some notable software includes certain versions of Ubuntu Linux, Debian Linux, and multiple Oracle applications.",
"3. Evaluate the deserialization risk: Since the vulnerability involves deserialization of untrusted data, you should consider whether your applications are performing such operations. If they are, consider if these deserialization operations are using untrusted, user-supplied data. If so, this is a potential attack vector.",
"4. Network exposure: The vulnerability has a network attack vector. Consider whether your container image has network exposure, especially if the Apache Batik service or any service using it is exposed to the internet.",
"5. Disputed status: CVE-2018-8013 is disputed and may not be a vulnerability."]

Given the following information about {{cve_id}}, make preliminary checklist for a security analyst to follow to determine whether a container image is vulnerable to this exploit.
""" + additional_intel_prompting


def get_mod_examples(type='questions', choices=[0, 1]):
    if type == 'questions':
        ex_list = [q for idx, q in enumerate(ex_questions) if idx in choices]
    else:
        ex_list = [s for idx, s in enumerate(ex_statements) if idx in choices]

    examples = '\n'.join(q.format(idx=idx + 1) for idx, q in enumerate(ex_list))
    return examples
