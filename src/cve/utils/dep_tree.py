import logging
import subprocess
from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path

logger = logging.getLogger(f"poc.{__name__}")

ROOT_LEVEL_SENTINEL = 'root-top-level-agent-morpheus'


class Ecosystem(Enum):
    GO = 1
    PYTHON = 2
    JAVASCRIPT = 3
    JAVA = 4


class DependencyTreeBuilder(ABC):
    @abstractmethod
    # Build a sort of "upside down" tree - a dict containing mapping of each package to a list of all consuming packages
    def build_tree(self, manifest_path: Path) -> dict[str, list[str]]:
        pass

    @abstractmethod
    # Return only package name, without version
    def extract_package_name(self, package_name: str) -> str:
        pass


class GoDependencyTreeBuilder(DependencyTreeBuilder):

    @staticmethod
    def _parent_son_separator(line: str) -> list[str]:
        return line.split(" ")

    def _get_parent(self, line: str):
        parts = self._parent_son_separator(line)
        return parts[0]

    def _get_son(self, line: str):
        parts = self._parent_son_separator(line)
        return parts[1]

    def __init__(self):
        pass

    def build_tree(self, manifest_path: Path) -> dict[str, list[str]]:
        # Get go version from manifest
        # TODO - download go binary of this version and run the go mod graph using it for optimal performance.
        go_version = self.determine_go_version(manifest_path)

        go_mod_tree = self.get_go_mod_graph_tree(manifest_path)
        lines = go_mod_tree.splitlines()
        root_package_name = self._get_parent(lines[0])
        tree = dict()
        for line in lines:
            line.split(" ")
            parent = self.extract_package_name(self._get_parent(line))
            son = self.extract_package_name(self._get_son(line))
            if tree.get(son, None) is None:
                tree[son] = [parent]
            else:
                tree.get(son).append(parent)
        # Mark the top level for
        tree[root_package_name] = [ROOT_LEVEL_SENTINEL]
        return tree

    @staticmethod
    def determine_go_version(manifest_path):
        go_version = ""
        with open(manifest_path + "/go.mod") as go_mod_file:
            for line in go_mod_file:
                if line.startswith("go"):
                    go_version = line.split(" ")[1]
                    break
        return go_version

    @staticmethod
    def get_go_mod_graph_tree(manifest_path) -> str:
        return subprocess.run(["bash", "-c", f" cd {manifest_path} ; go mod graph -modfile {manifest_path}/go.mod"],
                              capture_output=True, text=True).stdout

    def extract_package_name(self, package_name: str) -> str:
        if package_name.__contains__("@"):
            version_start = package_name.index("@")
            return package_name[: version_start]
        else:
            return package_name


def get_dependency_tree_builder(programming_language: Ecosystem) -> DependencyTreeBuilder:
    if programming_language == Ecosystem.GO.value:
        return GoDependencyTreeBuilder()
    else:
        raise ValueError(f'Unsupported Ecosystem {programming_language}')


class DependencyTree:
    builder: DependencyTreeBuilder
    ecosystem: Ecosystem

    def __init__(self, ecosystem: Ecosystem):
        self.ecosystem = ecosystem
        try:
            self.builder = get_dependency_tree_builder(ecosystem.value)
        except ValueError as err:
            logger.warning(f"Unable to build dependency tree - ${str(err)}")
            self.builder = None
