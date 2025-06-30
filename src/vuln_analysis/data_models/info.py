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

from pydantic import BaseModel

from .cve_intel import CveIntel
from .dependencies import VulnerableDependencies


class SBOMPackage(BaseModel):
    """
    Information about a single package in the container image's Software Bill of Materials (SBOM).
    """
    name: str
    version: str
    path: str | None = None
    system: str


class AgentMorpheusInfo(BaseModel):
    """
    Information used for decisioning in the Agent Morpheus engine. These information can all be automatically
    generated or retrieved by the pipeline from the input information.

    - vdb: paths to source code and documentation vector databases (VDBs) used to understand whether a vulnerability
      is exploitable in the source code.
    - intel: list of CveIntel objects representing intelligence for each vulnerability pulled from various vulnerability
      databases and APIs.
    - sbom: software bill of materials listing the packages and versions in the container image, used to understand
      whether the vulnerable package exists in the image.
    - vulnerable_dependencies: a list of VulnerableDependencies objects for each vuln_id, representing the SBOM packages
      and transitive dependencies that are vulnerable for the vuln_id.
    """

    class VdbPaths(BaseModel):
        """
        Paths to where the generated VDBs are stored.
        """
        code_vdb_path: str | None = None
        doc_vdb_path: str | None = None
        code_index_path: str | None = None

    class SBOMInfo(BaseModel):
        """
        List of SBOMPackage objects representing the packages found in the input image.
        """
        packages: list[SBOMPackage]

    vdb: VdbPaths | None = None
    intel: list[CveIntel] | None = None
    sbom: SBOMInfo | None = None
    vulnerable_dependencies: list[VulnerableDependencies] | None = None
