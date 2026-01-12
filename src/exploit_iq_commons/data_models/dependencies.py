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

import typing

from pydantic import BaseModel


class DependencyPackage(BaseModel):
    """
    Information about a dependency package as obtained from deps.dev API for a given SBOM package.
    """
    system: str | None = None
    name: str | None = None
    version: str | None = None
    relation: typing.Literal["SELF", "DIRECT", "INDIRECT"] | None = None


class VulnerableSBOMPackage(BaseModel):
    """
    Information about a vulnerable SBOM package and its related vulnerable dependency package.

    - name: SBOM package name
    - version: SBOM package version
    - vulnerable_dependency_package: DependencyPackage object with info about the vulnerable dependency package.
      If an SBOM package itself is vulnerable, the vulnerable_dependency_package.relation will be "SELF".
      Otherwise, if it is vulnerable due to its dependency, the vulnerable_dependency_package.relation will be either
      "DIRECT" or "INDIRECT".
    """
    name: str
    version: str
    vulnerable_dependency_package: DependencyPackage


class VulnerableDependencies(BaseModel):
    """
    Information about the vulnerable SBOM packages associated with the vuln_id.

    - vuln_id: vulnerability ID (e.g. CVE ID, GHSA ID) associated with the vulnerable package list.
    - vuln_package_intel_sources: list of sources (e.g. "ghsa", "nvd", "ubuntu", "rhsa") that provided
      the vulnerable package/version intel for the vuln_id.
    - vulnerable_sbom_packages: list of VulnerableSBOMPackage objects, representing the SBOM packages that are
      vulnerable for a given vuln_id.
    """
    vuln_id: str
    vuln_package_intel_sources: list[str]
    vulnerable_sbom_packages: list[VulnerableSBOMPackage]
