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

import ast
import html
import os

from dateutil.parser import parse

from vuln_analysis.data_models.output import AgentMorpheusOutput
from vuln_analysis.utils.data_utils import safe_getattr


def generate_vulnerability_reports(model_dict: AgentMorpheusOutput, output_dir):
    """
    Creates a markdown file for each CVE ID in the markdown content dictionary.

    Parameters
    ----------
    model_dict : AgentMorpheusOutput
        JSON data containing vulnerability information.
    output_dir : str
        The directory where the markdown files will be created.

    Returns
    -------
    None
    """
    markdown_content = _transform_to_markdown(model_dict)

    # Get the container directory name based on the image name and tag
    container_dir_name = (model_dict.input.image.name.split("/")[-1].replace(".", "_") + "_" +
                          model_dict.input.image.tag.replace(".", "_"))

    # Create a subdirectory named after the prefixed container ID inside the output_dir
    container_dir = os.path.join(output_dir, f"vulnerability_reports_{container_dir_name}")

    if not os.path.exists(container_dir):
        os.makedirs(container_dir, exist_ok=True)

    for cve_id, content in markdown_content.items():
        file_name = f"{cve_id}.md"
        file_path = os.path.join(container_dir, file_name)
        with open(file_path, "w") as f:
            f.write("\n".join(content))


def _transform_to_markdown(model_dict: AgentMorpheusOutput):
    """
    Convert JSON data to Markdown content.

    Parameters
    ----------
    model_dict : AgentMorpheusOutput
        JSON data containing vulnerability information.

    Returns
    -------
    dict
        Markdown content for each CVE ID.
    """
    cve_ids = [vuln.vuln_id for vuln in model_dict.input.scan.vulns]
    markdown_content = {}
    for cve_id in cve_ids:
        markdown_content[cve_id] = []

    _add_header(markdown_content, model_dict)
    _add_cve_intel(markdown_content, model_dict)
    _add_vulnerability_analysis(markdown_content, model_dict)
    _add_vulnerable_sboms(markdown_content, model_dict)
    _add_table_of_contents(markdown_content, model_dict)
    _add_checklist_info(markdown_content, model_dict)
    _add_references(markdown_content, model_dict)
    return markdown_content


def _add_header(markdown_content, model_dict: AgentMorpheusOutput):
    """
    Add header to Markdown content.

    Parameters
    ----------
    markdown_content : dict
        Markdown content for each CVE ID.
    model_dict : AgentMorpheusOutput
        JSON data containing vulnerability information.

    Returns
    -------
    None
        This function modifies `markdown_content` in place.
    """
    input_image = model_dict.input.image
    # iterate over a list of dict objects, with vuln_id and ghsa being 2 keys in each element
    for output in model_dict.output:
        cve_id = output.vuln_id
        markdown_content[cve_id].append(f"# Vulnerability Analysis Report for {cve_id}")
        markdown_content[cve_id].append(f"> **Container Analyzed:** `{input_image.name}:{input_image.tag}`\n\n")
        # Only add SBOM info if it is a file location
        if input_image.sbom_info.type == "file":
            markdown_content[cve_id].append(f"> **SBOM Info:** `{input_image.sbom_info}`\n\n")
        markdown_content[cve_id].append(f"> **Status:** {_get_expoiltability_text(output.justification.status)}")


def _add_cve_intel(markdown_content, model_dict: AgentMorpheusOutput):
    """
    Add CVE intelligence details to Markdown content.

    Parameters
    ----------
    markdown_content : dict
        Markdown content for each CVE ID.
    model_dict : AgentMorpheusOutput
        JSON data containing vulnerability information.

    Returns
    -------
    None
        This function modifies `markdown_content` in place.
    """
    for intel_obj in model_dict.info.intel:
        cve_id = intel_obj.vuln_id
        cve_description = _normalize_content(_get_cve_description(intel_obj))

        markdown_content[cve_id].append(
            f"## {_process_cve_title(cve_id, intel_obj)} <a name='cve-intro' id='cve-intro'></a>")
        # add a disputed tag if nvd.disputed is true
        safe_getattr(intel_obj, "nvd.disputed", None) and markdown_content[cve_id].append(
            f'\n<span style="color:#ffa500">**`Disputed`**<span><sup>[source](https://nvd.nist.gov/vuln/detail/{cve_id})</sup>'
        )

        cve_description and markdown_content[cve_id].append(f"\n\n {cve_description} <sup>[references](#ref)</sup> \n")

        cve_severity_ratings = _get_cve_severity(intel_obj)
        cve_severity_ratings and markdown_content[cve_id].append(f"\n{cve_severity_ratings} \n")
        markdown_content[cve_id].append(add_epss_score(intel_obj))


def _get_cve_severity(intel_obj):
    """
    Extract CVE severity and construct a markdown table.

    Parameters
    ----------
    intel_obj : object
        An object containing CVE severity details from multiple sources.

    Returns
    -------
    str
        A markdown-formatted table summarizing CVE severity and vector strings.
    """
    # Extracting data from GHSA
    ghsa_severity = safe_getattr(intel_obj, "ghsa.severity", "N/A").upper()
    ghsa_cvss_score = safe_getattr(intel_obj, "ghsa.cvss.score", "N/A")
    ghsa_vector = safe_getattr(intel_obj, "ghsa.cvss.vector_string", "N/A")
    ghsa_published_at = _convert_timestamp_to_human_readable(safe_getattr(intel_obj, "ghsa.published_at", "N/A"))
    ghsa_updated_at = _convert_timestamp_to_human_readable(safe_getattr(intel_obj, "ghsa.updated_at", "N/A"))

    # Extracting data from NVD
    nvd_severity = safe_getattr(intel_obj, "nvd.cvss_severity", "N/A").upper()
    nvd_cvss_score = safe_getattr(intel_obj, "nvd.cvss_base_score", "N/A")
    nvd_vector = safe_getattr(intel_obj, "nvd.cvss_vector", "N/A")
    nvd_published_at = _convert_timestamp_to_human_readable(safe_getattr(intel_obj, "nvd.published_at", "N/A"))
    nvd_updated_at = _convert_timestamp_to_human_readable(safe_getattr(intel_obj, "nvd.updated_at", "N/A"))

    # Extracting data from Red Hat (RHSA)
    rhsa_severity = safe_getattr(intel_obj, "rhsa.threat_severity", "N/A").upper()
    rhsa_cvss_score = safe_getattr(intel_obj, "rhsa.cvss3.cvss3_base_score", "N/A")
    rhsa_vector = safe_getattr(intel_obj, "rhsa.cvss3.cvss3_scoring_vector", "N/A")
    rhsa_published_at = _convert_timestamp_to_human_readable(safe_getattr(intel_obj, "rhsa.public_date", "N/A"))
    rhsa_updated_at = _convert_timestamp_to_human_readable(safe_getattr(intel_obj, "rhsa.updated_at", "N/A"))

    # Extracting data from Ubuntu
    ubuntu_severity = safe_getattr(intel_obj, "ubuntu.impact.baseMetricV3.cvssV3.baseSeverity", "N/A").upper()
    ubuntu_cvss_score = safe_getattr(intel_obj, "ubuntu.impact.baseMetricV3.cvssV3.baseScore", "N/A")
    ubuntu_vector = safe_getattr(intel_obj, "ubuntu.impact.baseMetricV3.cvssV3.vectorString", "N/A")
    ubuntu_published_at = _convert_timestamp_to_human_readable(safe_getattr(intel_obj, "ubuntu.published", "N/A"))
    ubuntu_updated_at = _convert_timestamp_to_human_readable(safe_getattr(intel_obj, "ubuntu.updated_at", "N/A"))

    # Constructing the markdown table
    markdown_table = ["### Severity and CVSS Score\n"]
    markdown_table.append("| Source     | Severity  | CVSS Score | Vector | Published At | Last Updated |\n")
    markdown_table.append("|---|---|---|---|---|---|\n")
    markdown_table.append(
        f"| {_get_source_url('GHSA', intel_obj)} |{ghsa_severity}|{ghsa_cvss_score}|{ghsa_vector}|{ghsa_published_at}|{ghsa_updated_at}\n"
    )
    markdown_table.append(
        f"| {_get_source_url('NVD', intel_obj)} |{nvd_severity}|{nvd_cvss_score}|{nvd_vector}|{nvd_published_at}|{nvd_updated_at}|\n"
    )
    markdown_table.append(
        f"| {_get_source_url('RHSA', intel_obj)} |{rhsa_severity}|{rhsa_cvss_score}|{rhsa_vector}|{rhsa_published_at}|{rhsa_updated_at}|\n"
    )
    markdown_table.append(
        f"| {_get_source_url('Ubuntu', intel_obj)} |{ubuntu_severity}|{ubuntu_cvss_score}|{ubuntu_vector}|{ubuntu_published_at}|{ubuntu_updated_at}|\n"
    )

    return "".join(markdown_table)


def add_epss_score(intel_obj):
    """
    Retrieve EPSS data for the cve.

    Parameters
    ----------
    intel_obj : object
        An object with CVE information from multiple sources.

    Returns
    -------
    str
        A markdown-formatted string with a table for EPSS data
    """
    epss = safe_getattr(intel_obj, "epss.epss", None)
    epss_percentile = safe_getattr(intel_obj, "epss.percentile", None)
    if epss or epss_percentile:
        # Create a markdown table for EPSS data
        table = "### EPSS Score\n"
        table += "| EPSS | Percentile |\n| --- | --- |\n"
        table += f"| {epss} | {epss_percentile} |\n"

        # Append the markdown table to the specified CVE ID
        return table
    return ""


def _get_cve_description(intel_obj):
    """
    Retrieve a description for a CVE from multiple sources.

    Parameters
    ----------
    intel_obj : object
        An object containing CVE details from various sources (e.g., GHSA, NVD).

    Returns
    -------
    str or None
        A string description of the CVE or None if no description is found.
    """
    if intel_obj.ghsa and intel_obj.ghsa.description:
        return intel_obj.ghsa.description
    if intel_obj.rhsa and intel_obj.rhsa.details:
        return intel_obj.rhsa.details
    if intel_obj.ubuntu and intel_obj.ubuntu.description:
        return intel_obj.ubuntu.description
    if intel_obj.nvd and intel_obj.nvd.cve_description:
        return intel_obj.nvd.cve_description

    return None


def _add_table_of_contents(markdown_content, model_dict: AgentMorpheusOutput):
    """
    Add a table of contents for checklists per CVE.

    Parameters
    ----------
    markdown_content : dict
        Markdown content for each CVE ID.
    model_dict : AgentMorpheusOutput
        JSON data containing vulnerability information.

    Returns
    -------
    None
        This function modifies `markdown_content` in place.
    """
    for entry in model_dict.output:
        cve_id = entry.vuln_id
        checklist = entry.checklist
        markdown_content[cve_id].append("### Checklist <a name='checklist-toc' id='checklist-toc'></a>")
        if checklist:
            steps = {
                item.input.split(":")[0]:
                    [intermediate_step.tool_name for intermediate_step in item.intermediate_steps or []]
                for item in checklist
            }
            for i, (step, intermediate_steps) in enumerate(steps.items(), start=1):
                markdown_content[cve_id].append(f"{i}. [{step}](#checklist-step-{i})\n")
                for j, intermediate_step in enumerate(intermediate_steps, start=1):
                    if intermediate_step == "_Exception":
                        continue
                    markdown_content[cve_id].append(f"\t {j}. [{intermediate_step}](#checklist-step-{i}.{j})")


def _add_checklist_info(markdown_content, model_dict: AgentMorpheusOutput):
    """
    Add detailed information for checklists associated with each CVE.

    Parameters
    ----------
    markdown_content : dict
        Markdown content for each CVE ID.
    model_dict : AgentMorpheusOutput
        JSON data containing vulnerability information.

    Returns
    -------
    None
        This function modifies `markdown_content` in place.
    """
    for entry in model_dict.output:
        cve_id = entry.vuln_id
        checklist = entry.checklist
        if checklist:
            markdown_content[cve_id].append(f"\n## Checklist Details <a name='checklist' id='checklist'></a>")
            for i, item in enumerate(checklist, start=1):
                input_text = item.input
                response = item.response
                markdown_content[cve_id].append(
                    f"\n## Step {i} <a name='checklist-step-{i}' id='checklist-step-{i}'></a> : {input_text.split(':')[0]}\n"
                )
                markdown_content[cve_id].append(f"\n> **Input**: *{input_text}*")
                markdown_content[cve_id].append(f"\n> **Response**: *{response}*")
                intermediate_steps = item.intermediate_steps
                if intermediate_steps:
                    for j, step in enumerate(intermediate_steps, start=1):
                        tool_name = step.tool_name
                        if tool_name == "_Exception":
                            continue  # skip intermediate steps with _Exception keyword as the tool_name
                        action_log = step.action_log
                        tool_input = step.tool_input
                        tool_output = step.tool_output
                        markdown_content[cve_id].append(
                            f"\n### Step {i}.{j} : *{tool_name}*<a name='checklist-step-{i}.{j}' id='checklist-step-{i}.{j}'></a>"
                        )
                        markdown_content[cve_id].append(f"\n\n#### Action Log \n<pre>{action_log} </pre>")
                        markdown_content[cve_id].append(f"\n\n#### Tool Input \n<pre>{tool_input} </pre>")
                        markdown_content[cve_id].append(
                            f"\n\n#### Tool Output \n{_process_tool_output(tool_output)}\n\n")
                        if j != len(intermediate_steps):
                            markdown_content[cve_id].append("\n[back to top](#checklist-toc)")
                elif not intermediate_steps and i != len(checklist):
                    markdown_content[cve_id].append("\n[back to top](#checklist-toc)")

            markdown_content[cve_id].append("\n[back to top](#checklist-toc)")


def _process_tool_output(content):
    """
    Process the tool output content and return a renderable markdown object.

    Parameters
    ----------
    content : dict or str
        JSON or string object representing tool output.

    Returns
    -------
    str
        Renderable markdown representation of the tool output.
    """
    if isinstance(content, str):
        try:
            # Check if the string contains a list
            content = ast.literal_eval(content)
            # If not, raise an error to return the content as is
            if not isinstance(content, list):
                raise ValueError(f"Handling for tool output type {type(content)} is not implemented.")
        except Exception:
            return f"<pre>{content}</pre>"
    if isinstance(content, list):
        # Check if the list contains source documents
        if len(content) > 0 and isinstance(content[0], dict) and content[0].get("type", None) == "Document":
            content = {"source_documents": content}
        # If not, format and return the list as is
        else:
            list_md = '\n'.join(f'- {item}' for item in content) or []
            return f"<pre>{list_md}</pre>"

    # Format source documents
    result = content.get("result", "")
    content_markdown = ""
    if result:
        content_markdown += f"<pre>{result}</pre>"
    metadata_keys = set()
    for item in content.get("source_documents", []):
        if "metadata" in item:
            metadata_keys.update(item["metadata"].keys())
    table = ("\n\n Source Documents \n\n | ID | Type | " + " |... ".join(metadata_keys) + " | Page Content |\n")
    table += "| --- " * (len(metadata_keys) + 3) + "|\n"
    for item in content.get("source_documents", []):
        row = [str(item.get("id", "")), str(item.get("type", ""))]
        for key in metadata_keys:
            row.append(str(item.get("metadata", {}).get(key, "")))
        # Retrieve and sanitize page content
        page_content = item.get("page_content", "")
        # # Remove extra whitespace
        page_content = " ".join(page_content.split())
        # Escape special characters
        page_content = html.escape(page_content).replace('|', '\\|').replace('*', '\\*').replace('_', '\\_')
        row.append(f"<details><summary>View Content</summary>{_format_as_markdown(page_content)}</details>")
        table += "| " + " | ".join(row) + " |\n"
    return content_markdown + table


def _add_vulnerability_analysis(markdown_content, model_dict: AgentMorpheusOutput):
    """
    Add vulnerability analysis details to Markdown content.

    Parameters
    ----------
    markdown_content : dict
        Markdown content for each CVE ID.
    model_dict : AgentMorpheusOutput
        JSON data containing vulnerability information.

    Returns
    -------
    None
        This function modifies `markdown_content` in place.
    """
    for entry in model_dict.output:
        cve_id = entry.vuln_id
        summary = entry.summary
        justification = entry.justification
        exploitability = justification.status
        exploitability_text = _get_expoiltability_text(exploitability)
        markdown_content[cve_id].append("## Vulnerability Analysis\n")
        markdown_content[cve_id].append(
            f"### Summary <a name='summary' id='summary'></a>({exploitability_text})\n{summary}")
        markdown_content[cve_id].append(f"\n### Justification <a name='justification' id='justification'></a> \n")
        markdown_content[cve_id].append(f"\n>label: {justification.label}")
        markdown_content[cve_id].append(f"\n{justification.reason}")


def _add_vulnerable_sboms(markdown_content, model_dict: AgentMorpheusOutput):
    """
    Add information about vulnerable SBOM dependencies to Markdown content.

    Parameters
    ----------
    markdown_content : dict
        Markdown content for each CVE ID.
    model_dict : AgentMorpheusOutput
        JSON data containing vulnerability information.

    Returns
    -------
    None
        This function modifies `markdown_content` in place.
    """
    if model_dict.info.vulnerable_dependencies is None:
        return
    
    vulnerable_sboms_per_cve_id = {
        i.vuln_id: i.vulnerable_sbom_packages
        for i in model_dict.info.vulnerable_dependencies
    }

    for cve_id, vulnerable_sboms in vulnerable_sboms_per_cve_id.items():
        if len(vulnerable_sboms) == 0:
            continue
        markdown_content[cve_id].append("\n---\n### Vulnerable SBOM Dependencies <a name='sbom' id='sbom'></a> \n")

        # Add table header
        markdown_content[cve_id].append(
            "\n| SBOM Name | SBOM Version | Dependency Name | Dependency Version | Relation | System |\n| --- | --- | --- | --- | --- | --- |"
        )

        # Create a set to track unique rows
        unique_rows = set()

        # Add rows for each SBOM entry
        for sbom in vulnerable_sboms:
            dependency = sbom.vulnerable_dependency_package
            row = f"| {sbom.name} | {sbom.version} | {dependency.name} | {dependency.version} | {dependency.relation} | {dependency.system} |"
            # Check if the row is unique before adding it
            if row not in unique_rows:
                markdown_content[cve_id].append(row)
                unique_rows.add(row)  # Add the row to the set of unique rows


def _add_references(markdown_content, model_dict: AgentMorpheusOutput):
    """
    Add references for a CVE from all available sources in the intel object.

    Parameters
    ----------
    markdown_content : dict
        Markdown content for each CVE ID.
    model_dict : AgentMorpheusOutput
        JSON data containing references information.

    Returns
    -------
    None
        This function modifies `markdown_content` in place.
    """
    for intel_obj in model_dict.info.intel:
        cve_id = intel_obj.vuln_id
        markdown_content[cve_id].append(
            "\n---\n## References <a name='ref' id='ref'></a>  \nHere are key references for further details on this vulnerability:"
        )
        references = set()
        for source in ["ghsa", "nvd", "rhsa", "ubuntu"]:
            references.update(_get_formatted_references(safe_getattr(intel_obj, f"{source}.references", [])))

        references_content = "\n".join(["- " + reference for reference in list(references)])
        markdown_content[cve_id].append(references_content)
        # Add a back-to-top link after the references
        markdown_content[cve_id].append("\n[back to top](#cve-intro)\n")


def _get_formatted_references(references: list):
    """
    Format and clean up references by splitting multiline strings into individual entries.

    Parameters
    ----------
    references : list
        A list of reference strings or objects.

    Returns
    -------
    list
        A cleaned and formatted list of references.
    """
    for index, element in enumerate(references):
        # Check if the element is a string and contains '\n'
        if isinstance(element, str) and "\n" in element:
            # Split the string by '\n' and replace it in the list
            split_strings = element.split("\n")
            references[index:index + 1] = split_strings
    return references


def _get_expoiltability_text(exploitability: str):
    """
    Get a color-coded text label based on the exploitability status.

    Parameters
    ----------
    exploitability : str
        Exploitability status (e.g., "TRUE", "FALSE", or unknown).

    Returns
    -------
    str
        HTML-formatted string with a color-coded label indicating exploitability.
    """
    color = "#9E9E9E"  # Gray
    exploitability_text = "Exploitability Unknown"
    if exploitability == "TRUE":
        color = "#F44336"  # Red
        exploitability_text = "Exploitable"
    elif exploitability == "FALSE":
        color = "#4CAF50"  # Green
        exploitability_text = "Not Exploitable"
    return f"<span style='color:{color}'>{exploitability_text}</span>"


def _normalize_content(input_data: str | list):
    """
    Normalize input data to handle different formats (string or list).

    Parameters
    ----------
    input_data : str or list
        The input data to normalize, which can be a string or a list of
        strings.

    Returns
    -------
    str
        A string representing the normalized input.
    """
    if isinstance(input_data, list):
        input_data = "\n".join([f"- {item}" for item in input_data])

    return input_data


def _format_as_markdown(content: str | list):
    """
    Format content as Markdown if it contains common Markdown indicators.

    Parameters
    ----------
    content : str or list
        The content to format, which can be a string or a list of strings.

    Returns
    -------
    str
        The formatted content. If Markdown indicators are detected, the content
        is wrapped in triple backticks (code block). Otherwise, it is returned
        as-is.
    """
    content = _normalize_content(content)
    # Simple check for common markdown characters
    markdown_indicators = [
        "\n",  # Newline
        "\n#",  # Header
        ">",  # Blockquote
        "|"  # Table formatting
    ]

    if any(indicator in content for indicator in markdown_indicators):
        # Return the string wrapped in triple backticks (code block)
        return f"```{content}```"

    # If it's just a normal string, return it as-is
    return content


def _convert_timestamp_to_human_readable(timestamp: str | None):
    """
    Convert a timestamp string into a human-readable format.

    Parameters
    ----------
    timestamp : str or None
        The timestamp string in various formats.

    Returns
    -------
    str or None
        The formatted timestamp or None if conversion fails.
    """
    try:
        return parse(timestamp).strftime("%Y-%m-%d")
    except ValueError:
        return timestamp or "N/A"


def _process_cve_title(cve_id, intel_obj):
    """
    Process and generate a title for a CVE entry.

    Parameters
    ----------
    cve_id : str
        The CVE ID or GHSA ID associated with the vulnerability.
    intel_obj : object
        JSON object containing vulnerability details.

    Returns
    -------
    str
        A formatted title string for the CVE entry.
    """
    if "GHSA" in cve_id:
        return f"{cve_id} \n> CVE-ID: {safe_getattr(intel_obj, 'ghsa.cve_id')}"
    elif "CVE" in cve_id:
        ghsa_id = safe_getattr(intel_obj, 'ghsa.ghsa_id')
        return f"{cve_id} \n> GHSA-ID: {safe_getattr(intel_obj, 'ghsa.ghsa_id')}" if ghsa_id else cve_id


def _get_source_url(source, intel_obj):
    """
    Process and generate a title for a CVE entry.

    Parameters
    ----------
    cve_id : str
        The CVE ID or GHSA ID associated with the vulnerability.
    intel_obj : object
        JSON object containing vulnerability details.

    Returns
    -------
    str
        A formatted title string for the CVE entry.
    """
    if source == "GHSA":
        return f"[**GHSA**](https://github.com/advisories/{safe_getattr(intel_obj, 'ghsa.ghsa_id')})"
    elif source == "NVD":
        return f"[**NVD**](https://nvd.nist.gov/vuln/detail/{safe_getattr(intel_obj, 'nvd.cve_id')})"
    elif source == "RHSA":
        return f"[**RHSA**](https://access.redhat.com/security/cve/{safe_getattr(intel_obj, 'rhsa.name')})"
    elif source == "Ubuntu":
        return f"[**Ubuntu**](https://ubuntu.com/security/{safe_getattr(intel_obj, 'ubuntu.id')})"
