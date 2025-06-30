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
from collections import defaultdict
from uuid import uuid4

from pydantic import AliasChoices
from pydantic import AnyHttpUrl
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Discriminator
from pydantic import Field
from pydantic import Tag
from pydantic import field_validator

from ..utils.string_utils import is_valid_cve_id
from ..utils.string_utils import is_valid_ghsa_id
from .common import HashableModel
from .common import TypedBaseModel
from .info import AgentMorpheusInfo
from .info import SBOMPackage


class SourceDocumentsInfo(HashableModel):
    """
    Information about the source documents for the container image.

    - type: document type.
    - git_repo: git repo URL where the source documents can be cloned.
    - ref: git reference, such as tag/branch/commit_id
    - include: file extensions to include when indexing the source documents.
    - exclude: file extensions to exclude when indexing the source documents.
    """

    type: typing.Literal["code", "doc"]

    git_repo: typing.Annotated[str, Field(min_length=1)]
    ref: typing.Annotated[str, Field(min_length=1, validation_alias=AliasChoices(
        "ref", "tag"))]  # Support "tag" as alias for backward compatibility

    include: list[str] = ["*.py", "*.ipynb"]
    exclude: list[str] = []

    @field_validator("include", "exclude")
    @classmethod
    def sort_lists(cls, v: list[str]) -> list[str]:
        return list(sorted(v))


class VulnInfo(HashableModel):
    """
    Information about a vulnerability.
    """

    model_config = ConfigDict(extra="allow")

    vuln_id: str
    description: str | None = None
    score: float | None = None
    severity: str | None = None
    published_date: str | None = None
    last_modified_date: str | None = None
    url: str | None = None
    feed_group: str | None = None

    package: str | None = None
    """
    The full package name, including the version, that is affected by the vulnerability.
    """
    package_version: str | None = None
    """
    The version of the package that is affected by the vulnerability.
    """
    package_name: str | None = None
    """
    The name of the package that is affected by the vulnerability without the version.
    """
    package_type: str | None = None
    """
    The type of the package that is affected by the vulnerability.
    """

    @field_validator("vuln_id")
    @classmethod
    def is_valid_vuln_id(cls, v: str):
        if not (is_valid_cve_id(v) or is_valid_ghsa_id(v)):
            raise ValueError(f"{v} is not a valid CVE ID or GHSA ID.")
        else:
            return v


class ScanInfoInput(HashableModel):
    """
    Information about a unique scan for a container image against a list of vulnerabilies.
    """
    id: str = Field(default_factory=lambda: str(uuid4()))
    type: str | None = None
    started_at: str | None = None
    completed_at: str | None = None

    vulns: typing.Annotated[list[VulnInfo], Field(min_length=1)]


class ManualSBOMInfoInput(TypedBaseModel[typing.Literal["manual"]]):
    """
    Manually provided Software Bill of Materials, consisting of a list of SBOMPackage objects.
    """
    packages: list[SBOMPackage]


class FileSBOMInfoInput(TypedBaseModel[typing.Literal["file"]]):
    """
    A file path pointing to a Software Bill of Materials file.
    """
    file_path: str


class HTTPSBOMInfoInput(TypedBaseModel[typing.Literal["http"]]):
    """
    A URL pointing to a Software Bill of Materials file.
    """
    url: AnyHttpUrl


SBOMInfoInput = typing.Annotated[typing.Annotated[ManualSBOMInfoInput, Tag(ManualSBOMInfoInput.static_type())]
                                 | typing.Annotated[FileSBOMInfoInput, Tag(FileSBOMInfoInput.static_type())]
                                 | typing.Annotated[HTTPSBOMInfoInput, Tag(HTTPSBOMInfoInput.static_type())],
                                 Discriminator(TypedBaseModel.discriminator)]


class ImageInfoInput(HashableModel):
    """
    Information about a container image, including the source information and sbom information.
    """
    name: str | None = None  # The image name
    tag: str | None = None  # i.e. latest
    digest: str | None = None  # i.e. sha256:...
    platform: str | None = None  # i.e. linux/amd64
    feed_group: str | None = None  # i.e. ubuntu:22.04

    source_info: list[SourceDocumentsInfo]
    sbom_info: SBOMInfoInput

    @field_validator('source_info', mode='after')
    @classmethod
    def check_conflicting_refs(cls, source_info: list[SourceDocumentsInfo]) -> list[SourceDocumentsInfo]:
        """Check if any git repos have conflicting refs"""
        repo_refset = defaultdict(set)

        for si in source_info:
            repo_refset[si.git_repo].add(si.ref)

        for repo, refset in repo_refset.items():
            if len(refset) > 1:
                raise ValueError(f"Conflicting refs specified for git repo: {repo}, refs: {refset}")
        return source_info


class AgentMorpheusInput(HashableModel):
    """
    Inputs required by the Agent Morpheus pipeline.
    """
    scan: ScanInfoInput
    image: ImageInfoInput


class AgentMorpheusEngineInput(BaseModel):
    """
    Inputs required by the Agent Morpheus Engine.

    - input: AgentMorpheusInput object that must be provided to the pipeline.
    - info: AgentMorpheusInfo object that is retrieved/generated by the pipeline.
    """
    input: AgentMorpheusInput
    info: AgentMorpheusInfo
