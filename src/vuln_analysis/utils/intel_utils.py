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

from packaging.version import InvalidVersion
from packaging.version import parse as parse_version
from pydpkg import Dpkg
from pydpkg.exceptions import DpkgVersionError

from vuln_analysis.data_models.cve_intel import CveIntelNvd


def update_version(incoming_version, current_version, compare):
    """
    Updates the version based on the comparison result.

    Args:
        incoming_version (str): The incoming version from NIST.
        current_version (str): The current version observed.
        compare (str): The comparison operator, either "older" or "newer".

    Returns:
        str: The updated version.
    """

    if compare == "older":
        compare_func = lambda x, y: x < y
        dpkg_compare = lambda x: x == -1
    elif compare == "newer":
        compare_func = lambda x, y: x > y
        dpkg_compare = lambda x: x == 1

    if incoming_version is None:
        return current_version
    if current_version is None:
        return incoming_version
    try:
        if compare_func(parse_version(incoming_version), parse_version(current_version)):
            updated = incoming_version
        else:
            updated = current_version
    except InvalidVersion:
        # Failed PEP440 versioning; moving on to Debian
        try:
            compare_result = Dpkg.compare_versions(incoming_version, current_version)
            updated = (incoming_version if dpkg_compare(compare_result) else current_version)
        except DpkgVersionError:
            # Debian versioning failed; moving on to alpha
            updated = (incoming_version if compare_func(incoming_version, current_version) else current_version)
    return updated


def parse_cpe(cpe):
    """
    Parses a Common Platform Enumeration (CPE) string.

    Args:
        cpe (str): The CPE string.

    Returns:
        tuple: A tuple containing the vendor, package, version, and system information.
    """
    vendor, package, version, system = None, None, None, None
    split_cpe = cpe.split(":")
    if len(split_cpe) > 3:
        vendor = split_cpe[3] if split_cpe[3] != "*" and split_cpe[3] != "-" else None
    if len(split_cpe) > 4:
        package = split_cpe[4] if split_cpe[4] != "*" and split_cpe[4] != "-" else None
    if len(split_cpe) > 5:
        version = split_cpe[5] if split_cpe[5] != "*" and split_cpe[5] != "-" else None
    if len(split_cpe) > 10:
        system = split_cpe[10] if split_cpe[10] != "*" and split_cpe[5] != "-" else None
    return (vendor, package, version, system)


def parse_config_vendors(configurations: list):
    """
    Parses a list of configurations into a sorted list of vendors.

    Args:
        configurations (list): A list of version information inputs.

    Returns:
        list: A list of vendors
    """
    vendors = set()
    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            for cpe_match in node.get("cpeMatch", []):
                vendor, _, _, _ = parse_cpe(cpe_match.get("criteria", "*:*:*:*:*:*:*:*:*:*:*:*:*"))
                if vendor:
                    vendors.add(vendor.replace("_", " ").title())
    return sorted(vendors)


def parse(configurations: list):
    """
    Parses a list of configurations into a list of Configuration
    (version information) objects.

    Args:
        configurations (list): A list of version information inputs.

    Returns:
        list: A list of configurationn objects.
    """
    version_info = []
    cache = set()
    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            for cpe_match in node.get("cpeMatch", []):
                vendor, package, version, system = parse_cpe(cpe_match.get("criteria", "*:*:*:*:*:*:*:*:*:*:*:*:*"))
                ver_start_exclude = cpe_match.get("versionStartExcluding")
                ver_start_include = update_version(version, cpe_match.get("versionStartIncluding"), "older")
                ver_end_include = update_version(version, cpe_match.get("versionEndIncluding"), "newer")
                ver_end_exclude = cpe_match.get("versionEndExcluding")
                info = [
                    vendor,
                    package,
                    system,
                    ver_start_exclude,
                    ver_end_exclude,
                    ver_start_include,
                    ver_end_include,
                ]

                if tuple(info) in cache:
                    continue
                if package:
                    if any(info[2:]):
                        cache.add(tuple(info))
                        obj = CveIntelNvd.Configuration(
                            vendor=vendor,
                            package=package,
                            system=system,
                            versionStartExcluding=ver_start_exclude,
                            versionEndExcluding=ver_end_exclude,
                            versionStartIncluding=ver_start_include,
                            versionEndIncluding=ver_end_include,
                        )
                        version_info.append(obj)

    return version_info
