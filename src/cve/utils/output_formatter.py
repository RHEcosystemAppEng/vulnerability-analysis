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

import os
import html
from ..data_models.output import AgentMorpheusOutput


def generate_vulnerability_reports(model_dict: AgentMorpheusOutput, output_dir):
    """Creates a markdown file for each CVE ID in the markdown content dictionary.

    Args:
        markdown_content (dict): A dictionary where keys are CVE IDs and values are markdown content.
        output_dir (str): The directory where the markdown files will be created.

    Returns:
        None
    """
    markdown_content = _transform_to_markdown(model_dict)

    # Get the container directory name based on the image name and tag
    container_dir_name = model_dict.input.image.name.split("/")[-1].replace(".", "_") + "_" + model_dict.input.image.tag.replace(".","_")

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
    """Convert JSON data to Markdown content.

    Args:
        model_dict (AgentMorpheusOutput): JSON data containing vulnerability information.

    Returns:
        dict: Markdown content for each CVE ID.
    """
    cve_ids = [vuln.vuln_id for vuln in model_dict.input.scan.vulns]
    markdown_content = {}
    for cve_id in cve_ids:
        markdown_content[cve_id] = []
        _add_header(markdown_content[cve_id], cve_id, model_dict)

    _add_vulnerability_details(markdown_content, model_dict)
    _add_table_of_contents(markdown_content, model_dict)
    _add_checklist_info(markdown_content, model_dict)
    _add_vulnerable_sboms(markdown_content, model_dict)
    return markdown_content


def _add_header(markdown_content, cve_id, model_dict: AgentMorpheusOutput):
    """Add header to Markdown content.

    Args:
        markdown_content (list): Markdown content for a CVE ID.
        cve_id (str): CVE ID.
        model_dict (AgentMorpheusOutput): JSON data containing vulnerability information.
    """
    input_image = model_dict.input.image
    markdown_content.append(f"# Vulnerability Analysis Report for {cve_id}")
    markdown_content.append(
        f"> **Container Analyzed:** `{input_image.name} : {input_image.tag}`\n\n"
    )
    # Only add SBOM info if it is a file location
    if input_image.sbom_info.type == "file":
        markdown_content.append(f"> **SBOM Info:** `{input_image.sbom_info}`")


def _add_table_of_contents(markdown_content, model_dict: AgentMorpheusOutput):
    """Add table of contents for checklists per CVE.

    Args:
        markdown_content (dict): Markdown content for each CVE ID.
        model_dict (AgentMorpheusOutput): JSON data containing vulnerability information.
    """
    for entry in model_dict.output:
        cve_id = entry.vuln_id
        checklist = entry.checklist
        markdown_content[cve_id].append(
            "## Table of Contents <a name='toc' id='toc'></a>\n"
        )
        markdown_content[cve_id].append(
            "#### [Checklist](#checklist) <a name='checklist-toc' id='checklist-toc'></a>"
        )
        if checklist:
            steps = {
                item.input.split(":")[0]: [
                    intermediate_step.tool_name
                    for intermediate_step in item.intermediate_steps or []
                ]
                for item in checklist
            }
            for i, (step, intermediate_steps) in enumerate(steps.items(), start=1):
                markdown_content[cve_id].append(f"{i}. [{step}](#checklist-step-{i})\n")
                for j, intermediate_step in enumerate(intermediate_steps, start=1):
                    markdown_content[cve_id].append(
                        f"\t {j}. [{intermediate_step}](#checklist-step-{i}.{j})"
                    )
        markdown_content[cve_id].append(
            "#### [Vulnerable SBOMS](#sbom) <a name='sbo-toc' id='checklist-toc'></a>"
        )


def _add_checklist_info(markdown_content, model_dict: AgentMorpheusOutput):
    """Add info for checklists per CVE.

    Args:
        markdown_content (dict): Markdown content for each CVE ID.
        model_dict (AgentMorpheusOutput): JSON data containing vulnerability information.
    """
    for entry in model_dict.output:
        cve_id = entry.vuln_id
        checklist = entry.checklist
        if checklist:
            markdown_content[cve_id].append(
                f"\n## Checklist Details <a name='checklist' id='checklist'></a>"
            )
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
                        action_log = step.action_log
                        tool_input = step.tool_input
                        tool_output = step.tool_output
                        markdown_content[cve_id].append(
                            f"\n### Step {i}.{j} : *{tool_name}*<a name='checklist-step-{i}.{j}' id='checklist-step-{i}.{j}'></a>"
                        )
                        markdown_content[cve_id].append(
                            f"\n\n#### Action Log \n<pre>{action_log} </pre>"
                        )
                        markdown_content[cve_id].append(
                            f"\n\n#### Tool Input \n<pre>{tool_input} </pre>"
                        )
                        markdown_content[cve_id].append(
                            f"\n\n#### Tool Output \n{_process_tool_output(tool_output)}\n\n"
                        )
                        if j != len(intermediate_steps):
                            markdown_content[cve_id].append(
                                "\n[back to top](#checklist-toc)"
                            )
                elif not intermediate_steps and i != len(checklist):
                    markdown_content[cve_id].append("\n[back to top](#checklist-toc)")

            markdown_content[cve_id].append("\n[back to top](#checklist-toc)")


def _process_tool_output(content):
    """Process tool_output content and return a renderable markdown object

    Args:
        content (dict, str): JSON or string object
    """
    if isinstance(content, str):
        return f"<pre>{content}</pre>"
    result = content.get("result", "")
    content_markdown = ""
    if result:
        content_markdown += f"> **Response:** {result}"
    metadata_keys = set()
    for item in content.get("source_documents", []):
        if "metadata" in item:
            metadata_keys.update(item["metadata"].keys())
    table = (
        "\n\n Source Documents \n\n | ID | Type | "
        + " |... ".join(metadata_keys)
        + " | Page Content |\n"
    )
    table += "| --- " * (len(metadata_keys) + 3) + "|\n"
    for item in content.get("source_documents", []):
        row = [str(item.get("id", "")), str(item.get("type", ""))]
        for key in metadata_keys:
            row.append(str(item.get("metadata", {}).get(key, "")))
        # Retrieve and sanitize page content
        page_content = item.get("page_content", "")
        # Remove extra whitespace
        page_content = " ".join(page_content.split())
        # Escape special characters
        page_content = html.escape(page_content)
        row.append(
            f"<details><summary>View Content</summary><pre>{page_content}</pre></details>"
        )
        table += "| " + " | ".join(row) + " |\n"
    return content_markdown + table


def _add_vulnerability_details(markdown_content, model_dict: AgentMorpheusOutput):
    """Add vulnerability details to Markdown content.

    Args:
        markdown_content (dict): Markdown content for each CVE ID.
        model_dict (AgentMorpheusOutput): JSON data containing vulnerability information.
    """
    for entry in model_dict.output:
        cve_id = entry.vuln_id
        summary = entry.summary
        justification = entry.justification
        exploitability = justification.status
        exploitability_text = _get_expoiltability_text(exploitability)
        markdown_content[cve_id].append(
            f"## Summary <a name='summary' id='summary'></a>\n{summary}"
        )
        markdown_content[cve_id].append(
            f"\n## Justification <a name='justification' id='justification'></a> ({exploitability_text}) \n"
        )
        markdown_content[cve_id].append(f"\n>label: {justification.label}")
        markdown_content[cve_id].append(f"\n{justification.reason}")


def _add_vulnerable_sboms(markdown_content, model_dict: AgentMorpheusOutput):
    """Add vulnerable SBOMs to Markdown content.

    Args:
        markdown_content (dict): Markdown content for each CVE ID.
        model_dict (AgentMorpheusOutput): JSON data containing vulnerability information.
    """
    vulnerable_sboms_per_cve_id = {
        i.vuln_id: i.vulnerable_sbom_packages
        for i in model_dict.info.vulnerable_dependencies
    }
    for cve_id, vulnerable_sboms in vulnerable_sboms_per_cve_id.items():
        markdown_content[cve_id].append(
            "\n---\n## Vulnerable SBOM Dependencies <a name='sbom' id='sbom'></a> \n"
        )
        for sbom in vulnerable_sboms:
            sbom_name = sbom.name
            sbom_type = sbom.version
            vulnerable_package_dependencies = sbom.vulnerable_dependency_package
            markdown_content[cve_id].append("\n")
            markdown_content[cve_id].append(f"\n### {sbom_name}")
            markdown_content[cve_id].append(f"**Version:** {sbom_type}")
            markdown_content[cve_id].append("\n**Vulnerable Dependencies:**")
            for dependency, value in vulnerable_package_dependencies:
                markdown_content[cve_id].append(f" - {dependency} : {value}")
            markdown_content[cve_id].append("\n[back to top](#toc)")


def _get_expoiltability_text(exploitability):
    """Get color based on exploitability status.

    Args:
        exploitability (str): Exploitability status.

    Returns:
        str: Color code.
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
