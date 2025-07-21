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

import asyncio
import logging
import os
import re
import urllib.parse

import aiohttp
import aiohttp.client_exceptions
import aiohttp.http_exceptions
import requests
from tqdm import tqdm
from univers import versions

from vuln_analysis.data_models.cve_intel import CveIntelNvd
from vuln_analysis.data_models.dependencies import DependencyPackage
from vuln_analysis.utils.clients.intel_client import IntelClient
from vuln_analysis.utils.string_utils import package_names_match
from vuln_analysis.utils.url_utils import url_join

logger = logging.getLogger(__name__)

REQUESTS_TIMEOUT = 2

# Mapping of ecosystem strings to standard ecosystem names in deps.dev and univers
SYS_STANDARD_MAPPING = {
    ".net": "nuget",
    "cargo": "cargo",
    "composer": "composer",
    "conan": "conan",
    "conda": "pypi",
    "deb": "deb",
    "dpkg": "deb",
    "go": "go",
    "go-module": "go",
    "golang": "go",
    "java": "maven",
    "maven": "maven",
    "node.js": "npm",
    "npm": "npm",
    "nuget": "nuget",
    "php": "composer",
    "pip": "pypi",
    "pypi": "pypi",
    "python": "pypi",
    "rpm": "rpm",
    "ruby": "rubygems",
    "rubygems": "rubygems",
    "rust": "cargo"
}

# Mapping of standard ecosystem names to univers structured version functions
SYS_VERSION_FUNC_MAPPING = {
    "pypi": versions.PypiVersion,
    "npm": versions.SemverVersion,
    "rubygems": versions.RubygemsVersion,
    "deb": versions.DebianVersion,
    "maven": versions.MavenVersion,
    "nuget": versions.NugetVersion,
    "rpm": versions.RpmVersion,
    "composer": versions.ComposerVersion,
    "go": versions.GolangVersion,
    "conan": versions.ConanVersion,
}

# Standard ecosystem names supported in deps.dev API https://docs.deps.dev/api/v3/#getpackage
DEPDEV_SUPPORTED_SYS = set(["go", "npm", "cargo", "maven", "pypi", "nuget"])


def ubuntu_check(version: str = None):
    version = str(version)
    if version is None:
        return False
    if "ubuntu" in version:
        return True
    return False


def deb_check(version: str = None):
    version = str(version)
    if version is None:
        return False
    if "deb" in version:
        return True
    return False


def rhel_check(version: str = None):
    version = str(version)
    if version is None:
        return False
    if "el" in version:
        return True
    return False


def _is_valid_comparison(v, u):
    return ubuntu_check(v) == ubuntu_check(u) and deb_check(u) == deb_check(v) and rhel_check(u) == rhel_check(v)


class VulnerableDependencyChecker(IntelClient):
    """
    This tool will scan through the input SBOM file and identify all vulnerable packages and dependencies
    indicated by the provided CVEs.
    """

    def __init__(self,
                 *,
                 base_url: str | None = None,
                 image: str,
                 sbom_list: list,
                 session: aiohttp.ClientSession | None = None,
                 respect_retry_after_header: bool = True,
                 retry_on_client_errors: bool = True):

        super().__init__(
            session=session,
            base_url=base_url or os.environ.get('DEPSDEV_BASE_URL'),
            retry_count=1,  # Service returns 404 if the package is not found. So dont retry
            respect_retry_after_header=respect_retry_after_header,
            retry_on_client_errors=retry_on_client_errors)

        self._semaphore = asyncio.Semaphore(25)

        self.image = image
        self.ref_packages = sbom_list
        self.found_count = 0

    @classmethod
    def default_base_url(cls) -> str:
        return "https://api.deps.dev/"

    @staticmethod
    def _check_version_in_range(version_to_check: str, version_range: list[str], system: str) -> bool:
        """Determine if a given version is within a specified range.

        Args:
            version_to_check (str): The version of the target package to check, either str or None
            version_range (list[str]): A set containing four elements: the start/end of the version range
                                  (inclusive/exclusive).
            system (str): The ecosystem of the package, either str or None

        Returns:
            bool: True if the version is within the specified range, False otherwise.
        """

        if not version_to_check:
            raise ValueError("Invalid version to check. version_to_check is empty.")
        elif all([not v for v in version_range]):
            raise ValueError("Invalid version range. version_range is empty.")

        all_versions = version_range + [version_to_check]
        if max([ubuntu_check(v) or deb_check(v) for v in all_versions]):
            system = 'deb'
        if max([rhel_check(v) for v in all_versions]):
            system = 'rpm'

        # Get structured version conversion function based on the package system. Use GenericVersion as default.
        version_func = SYS_VERSION_FUNC_MAPPING.get(system, versions.GenericVersion)

        # Convert version strings to structured version objects
        try:
            version_to_check = version_func(version_to_check)
            ver_start_excl, ver_end_excl, ver_start_incl, ver_end_incl = [
                version_func(v) if v is not None else v for v in version_range
            ]
        except versions.InvalidVersion as e:
            raise e

        # Check the version range start
        if ver_start_incl and _is_valid_comparison(version_to_check, ver_start_incl):
            matches_start = ver_start_incl <= version_to_check
        elif ver_start_excl and _is_valid_comparison(version_to_check, ver_start_excl):
            matches_start = ver_start_excl < version_to_check
        else:
            matches_start = True

        # Check the version range end
        if ver_end_incl and _is_valid_comparison(version_to_check, ver_end_incl):
            matches_end = version_to_check <= ver_end_incl
        elif ver_end_excl and _is_valid_comparison(version_to_check, ver_end_excl):
            matches_end = version_to_check < ver_end_excl
        else:
            matches_end = True

        return matches_start and matches_end

    @staticmethod
    def _check_package_vulnerability(package: DependencyPackage, system: str, vuln: CveIntelNvd.Configuration) -> bool:
        """Determine if a package is vulnerable for a configuration based on its name and version.

        Args:
            package (DependencyPackage): package to check against the vulnerable configuration.
            system (str): standardized system name.
            vuln (CveIntelNvd.Configuration): vulnerable configuration information.

        Returns:
            bool: True if the package matches the vulnerable configuration or version check fails, False otherwise.
        """

        # First, ensure package names match
        if not package_names_match(package.name, vuln.package):
            return False

        if 'ubuntu' in package.version:
            system = 'deb'

        # If package names match, check the version
        try:
            return VulnerableDependencyChecker._check_version_in_range(package.version,
                                                                       [
                                                                           vuln.versionStartExcluding,
                                                                           vuln.versionEndExcluding,
                                                                           vuln.versionStartIncluding,
                                                                           vuln.versionEndIncluding,
                                                                       ],
                                                                       system)
        except Exception as e:
            logger.warning("Version comparison failed for package %s, assuming package may be vulnerable. Error: %s. ",
                           package.name,
                           e)
            return True

    async def _is_maven_package(self, package_name: str, base_url):
        """Check if a package exists in Maven.

        Args:
            package_name (str): Package name in the format "group_id:artifact_id"
            base_url (str): Base URL for the Maven repository

        Returns:
            bool: True if the package exists, False otherwise
        """
        parts = package_name.split(":")
        if len(parts) != 2:
            return False
        group_id, artifact_id = parts

        query = f"g:{group_id}+AND+a:{artifact_id}"
        payload = {"q": query, "core": "gav", "rows": "20", "wt": "json"}

        payload_str = urllib.parse.urlencode(payload, safe=":+")

        try:
            response = await self.request(method="GET", url=base_url, params=payload)
            return response["response"]["numFound"] > 0
        except requests.exceptions.RequestException:
            return False

    async def _infer_pkg_ecosystem(self, package_name: str, version: str = None) -> str:
        """Attempt to infer the ecosystem given the package name and version (this might not be 100% accurate)

        Args:
            package_name (str): Package name

        Returns:
            str: Ecosystem name (e.g. pip, npm, maven, etc.) or "unknown" if not found
        """
        # Try to first infer based on version name
        if ubuntu_check(version) or deb_check(version):
            return "deb"
        elif rhel_check(version):
            return "rpm"

        # Define the mapping of ecosystems to their registries
        registry_mapping = {
            "pip": "https://pypi.org/project/",
            "npm": "https://registry.npmjs.org/",
            "go": "https://pkg.go.dev/",
            "maven": "https://search.maven.org/solrsearch/select",
            "nuget": "https://www.nuget.org/packages/",
            "rubygems": "https://rubygems.org/gems/",
            "rust": "https://crates.io/api/v1/crates/",
            "erlang": "https://hex.pm/api/packages/",
            "composer": "https://packagist.org/packages/",
            "conan": "https://cpp.libhunt.com/",
        }

        # Check each registry to see if the package exists
        for ecosystem, base_url in registry_mapping.items():
            if ecosystem == "maven":
                if await self._is_maven_package(package_name, base_url):
                    return ecosystem
            else:
                url = f"{base_url}{package_name}"
                if ecosystem == "php":
                    url = f"{base_url}{package_name}.json"
                elif ecosystem == "erlang":
                    url = f"{base_url}{package_name.lower()}"

                try:
                    response = await self._session.get(url, timeout=REQUESTS_TIMEOUT)
                    if response.status == 200:
                        if ecosystem == "composer":
                            content = await response.text(encoding="utf-8")
                            if ("vendor_not_found" in content or "package_not_found" in content):
                                continue
                        return ecosystem
                except (
                        aiohttp.http_exceptions.HttpProcessingError,
                        aiohttp.client_exceptions.ClientError,
                        asyncio.TimeoutError,
                ):
                    continue

        return "unknown"

    async def _get_dependency(self, system=None, package: str = "", version: str = ""):
        """Get dependencies for a package from deps.dev API

        Args:
            system (str, optional): Ecosystem of the package. Defaults to None.
            package (str, optional): Package name. Defaults to "".
            version (str, optional): Package version. Defaults to "".

        Returns:
            list: List of dependencies for the package.
        """
        # Attempt to infer missing package ecosystem if not provided in the SBOM
        if system is None:
            system = await self._infer_pkg_ecosystem(package, version)

        self_package = [DependencyPackage(
            system=system,
            name=package,
            version=version,
            relation="SELF",
        )]

        system = SYS_STANDARD_MAPPING.get(system)

        if system not in DEPDEV_SUPPORTED_SYS:
            return self_package

        encoded_pkg = urllib.parse.quote(package, 'utf-8')
        encoded_ver = urllib.parse.quote(version, 'utf-8')
        api_url = (f"v3/systems/{system}/packages/{encoded_pkg}/versions/{encoded_ver}:dependencies")
        url = url_join(self.base_url, api_url)
        package_info = {"package": package, "system": system, "version": version}

        try:

            # Limit the number of concurrent requests to avoid overloading the server
            async with self._semaphore:

                data = await self.request(method="GET", url=url, log_on_error=False)
                if not data:
                    raise ValueError(f"Response from {self.base_url} contains no dependencies for {package_info}")

                self.found_count += 1
                return [
                    DependencyPackage(
                        system=node["versionKey"]["system"],
                        name=node["versionKey"]["name"],
                        version=node["versionKey"]["version"],
                        relation=node["relation"],
                    ) for node in data["nodes"]
                ]

        # Handle packages with no dependencies found
        except (ValueError, aiohttp.ClientResponseError) as e:

            # Only log warning for unexpected errors
            if (isinstance(e, ValueError) or (isinstance(e, aiohttp.ClientResponseError) and e.status == 404)):
                pass
            else:
                logger.warning("Error calling %s for %s: %s", self.base_url, package_info, e)

            return self_package

    async def _collect_all_dependencies(self):
        """Collect all direct and indirect dependencies given the sbom package info

        Returns:
            dict: A dictionary with the following structure: {
                (sbom_pkg, pkg_version): [
                    DependencyPackage(
                        system="unknown",
                        name=pkg_name,
                        version=version,
                        relation="SELF",
                    ),
                    ...
                ]
            }
        """
        logger.info("Collecting SBOM package dependencies from %s for %s", self.base_url, self.image)
        dependencies_info = {}

        with tqdm(total=len(self.ref_packages)) as pbar:

            async def _wrap_coro(pkg_info):
                pkg_name, version, system = (
                    pkg_info.name.lower(),
                    pkg_info.version,
                    pkg_info.system,
                )

                dep_out = await self._get_dependency(system, pkg_name, version)

                pbar.update(1)

                return pkg_name, version, dep_out

            dependency_coros = [_wrap_coro(pkg_info) for pkg_info in self.ref_packages]

            gathered_dep_info = await asyncio.gather(*dependency_coros)

            for pkg_name, version, dependencies in gathered_dep_info:
                dependencies_info[(pkg_name, version)] = dependencies

            logger.info("Collected additional dependency info for %d of %d SBOM packages.",
                        self.found_count,
                        len(self.ref_packages))

            return dependencies_info

    async def load_dependencies(self):
        """
        Load all dependencies for the SBOM packages
        """

        self.dependencies = await self._collect_all_dependencies()

    async def _get_vuln_packages(self, vuln, dependencies_info):
        """Retrieve packages that matches with CVE vulnerability, specific for ghsa, nvd inputs

        Args:
            vuln (Configuration): see return format from _reconstruct_ghsa
            dependencies_info (dict): see return format from _collect_all_dependencies

        Returns:
            list: A list of dictionary with a structure as follows:
                key (tuple): (pkg_name, version) => the affected package in SBOM
                value (DependencyPackage): the matched package informaiton related to the vulnerability indicated by CVE
        """
        if not vuln.package:
            return []

        system = vuln.system.lower() if vuln.system else await self._infer_pkg_ecosystem(vuln.package.lower())
        system = SYS_STANDARD_MAPPING.get(system, system)

        vulnerable_dep = [{
            root_pkg: dependency
        } for root_pkg, dependencies in dependencies_info.items() for dependency in dependencies
                          if VulnerableDependencyChecker._check_package_vulnerability(dependency, system, vuln)]

        return vulnerable_dep

    def _get_vuln_ubuntu_packages(self, notices, dependencies_info):
        """Retrieve packages that match with CVE vulnerability, specific for ubuntu inputs

        Args:
            notices (dict): example format:
                {
                    "focal": [
                        {
                            "description": "Simple Linux Utility for Resource Management",
                            "is_source": true,
                            "name": "slurm-llnl",
                            "version": "19.05.5-1ubuntu0.1~esm2"
                        }, ...
                    ], ...
                }
            dependencies_info (dict): see return format from _collect_all_dependencies

        Returns:
            list: A list of dictionary with a structure as follows:
                key: (pkg_name, version) => the affected package in SBOM
                value: a list of matched vulnerable package information associated with CVE
        """
        vulnerable_dep = []
        version_func = SYS_VERSION_FUNC_MAPPING["deb"]

        for patched_pkg_list in notices.values():
            for patched_pkg in patched_pkg_list:
                name, version = patched_pkg.get("name"), patched_pkg.get("version")

                if not (name and version):
                    continue

                for root_pkg, dependencies in dependencies_info.items():
                    for dependency in dependencies:
                        if package_names_match(dependency.name, name) and version_func(
                                dependency.version) < version_func(version):
                            vulnerable_dep.append({root_pkg: dependency})

        return vulnerable_dep

    def _get_vuln_rhsa_packages(self, vuln_pkg_info, dependencies_info):
        """Retrieve packages that match with CVE vulnerability, specific for ubuntu inputs

        Args:
            vuln_package_info (list): example format: ["python39", "3.9-8100020240214182535.7044f6c1"]
            dependencies_info (dict): see return format from _collect_all_dependencies

        Returns:
            list: A list of dictionary with a structure as follows:
                key: (pkg_name, version) => the affected package in SBOM
                value: a list of matched vulnerable package information associated with CVE
        """
        name, version = vuln_pkg_info
        vulnerable_dep = []
        version_func = SYS_VERSION_FUNC_MAPPING["rpm"]

        if name and version:
            for root_pkg, dependencies in dependencies_info.items():
                for dependency in dependencies:
                    if package_names_match(dependency.name, name) and version_func(
                            dependency.version) < version_func(version):
                        vulnerable_dep.append({root_pkg: dependency})

        return vulnerable_dep

    @staticmethod
    def _extract_range_structure(data, vuln_range):
        """Turn the vulnerable_version_range string from ghsa to structure format

        Args:
            data (Configuration): information before applying vuln_range
            vuln_range (str): vulnerable_version_range string from ghsa.
                - sample1: < 3.1.3
                - sample2: >= 0.14.0, < 14.0.1

        Returns:
            dict: structured output for updating data in function _reconstruct_ghsa
        """
        vuln_list = vuln_range.split(",")
        if len(vuln_list) > 1:
            low, high = vuln_list[0].strip(), vuln_list[1].strip()
            sign_low, low_v = low.split(" ")
            sign_high, high_v = high.split(" ")
            if sign_low == ">=":
                data.versionStartIncluding = low_v
            elif sign_low == ">":
                data.versionStartExcluding = low_v
        else:
            high = vuln_list[0].strip()
            sign_high, high_v = high.split(" ")

        if sign_high == "<=":
            data.versionEndIncluding = high_v
        elif sign_high == "<":
            data.versionEndExcluding = high_v

        return data

    def _reconstruct_ghsa(self, vuln):
        """Transform a ghsa vulnerability input to a defined structure

        Args:
            vuln (dict): ghsa vulnerability input

        Returns:
            Configuration: the defined versioning structure
        """
        pkg_info = vuln.get("package", None)
        if pkg_info:
            data = CveIntelNvd.Configuration(
                package=pkg_info.get("name", None),
                system=pkg_info.get("ecosystem", None),
                versionStartExcluding=None,
                versionEndExcluding=vuln.get("first_patched_version", None),
                versionStartIncluding=None,
                versionEndIncluding=None,
            )

        vulnerable_version_range = vuln.get("vulnerable_version_range", None)
        if vulnerable_version_range:
            data = self._extract_range_structure(data, vulnerable_version_range)

        return data

    async def run_ghsa(self, vulnerabilities):
        """Get vulnerable packages information from intel.ghsa.vulnerabilities

        Args:
            vulnerabilities (list): list of vulnerabilities information from
            intel.ghsa.vulnerabilities
            sample input: [
                {
                    "package": {
                        "ecosystem": "pip",
                        "name": "mlflow"
                    },
                    "vulnerable_version_range": "< 2.9.2",
                    "first_patched_version": "2.9.2",
                    "vulnerable_functions": []
                }, ...
            ]

        list: A list of dictionary with a structure as follows:
            - key (tuple): (pkg_name, version) => the affected package in SBOM
            - value (DependencyPackage): the matched package informaiton related to the
            vulnerability indicated by CVE
        """
        vuln_pkgs = []
        for vuln in vulnerabilities:
            vuln = self._reconstruct_ghsa(vuln)
            vuln_pkg = await self._get_vuln_packages(vuln, self.dependencies)
            if vuln_pkg:
                vuln_pkgs.extend(vuln_pkg)
        return vuln_pkgs

    async def run_nvd(self, vulnerabilities):
        """Get vulnerable packages information from intel.nvd.configurations

        Args:
            vulnerabilities (list): list of vulnerabilities information from
            intel.nvd.configurations

        list: A list of dictionary with a structure as follows:
            - key (tuple): (pkg_name, version) => the affected package in SBOM
            - value (DependencyPackage): the matched package informaiton related to the
            vulnerability indicated by CVE
        """
        vuln_pkgs = []
        for vuln in vulnerabilities:
            vuln_pkg = await self._get_vuln_packages(vuln, self.dependencies)
            if vuln_pkg:
                vuln_pkgs.extend(vuln_pkg)
        return vuln_pkgs

    async def run_ubuntu(self, notices):
        """Get vulnerable packages information from intel.ubuntu.notices

        Args:
            notices (list): list of information from intel.ubuntu.notices

        Returns:
            list: a list of package information from sbom that is related to the vulnerability
        """
        vuln_pkgs = []
        for notice in notices:
            ubuntu_patched_dict = notice.get("release_packages", {})
            if ubuntu_patched_dict:
                vuln_pkg = self._get_vuln_ubuntu_packages(ubuntu_patched_dict, self.dependencies)
                vuln_pkgs.extend(vuln_pkg)

        return vuln_pkgs

    async def run_rhsa(self, vulnerabilities):
        """Get vulnerable packages information from intel.rhsa.affected_release

        Args:
            vulnerabilities (list): list of vulnerabilities information from
            intel.rhsa.affected_release.
            example format: [{
                "product_name": "Red Hat Enterprise Linux 8",
                "release_date": "2024-05-22T00:00:00Z",
                "advisory": "RHSA-2024:2985",
                "cpe": "cpe:/a:redhat:enterprise_linux:8",
                "package": "python39:3.9-8100020240214182535.7044f6c1"
            }, ...]

        Returns:
            list: a list of package information from sbom that is related to the vulnerability
        """
        vuln_pkgs = []
        for vuln in vulnerabilities:
            cve_vuln_pkg = vuln.get("package", "").split(":")
            if len(cve_vuln_pkg) == 2:
                vuln_pkg = self._get_vuln_rhsa_packages(cve_vuln_pkg, self.dependencies)
                vuln_pkgs.extend(vuln_pkg)

        return vuln_pkgs
