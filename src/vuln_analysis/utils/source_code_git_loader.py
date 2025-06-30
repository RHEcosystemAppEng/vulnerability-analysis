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

import logging
import os
import typing
from pathlib import Path

from git import Blob as GitBlob
from git import Repo
from langchain_community.document_loaders.blob_loaders.schema import BlobLoader
from langchain_core.document_loaders.blob_loaders import Blob
from tqdm import tqdm

PathLike = typing.Union[str, os.PathLike]

logger = logging.getLogger(__name__)


class SourceCodeGitLoader(BlobLoader):
    """
    Load `Git` repository files.

    The Repository can be local on disk available at `repo_path`,
    or remote at `clone_url` that will be cloned to `repo_path`.
    Currently, supports only text files.

    Each document represents one file in the repository. The `path` points to
    the local Git repository, and the `ref` specifies the git reference to load
    files from. By default, it loads from the `main` branch.
    """

    def __init__(
        self,
        repo_path: PathLike,
        clone_url: str | None = None,
        ref: typing.Optional[str] = "main",
        include: typing.Optional[typing.Iterable[str]] = None,
        exclude: typing.Optional[typing.Iterable[str]] = None,
    ):
        """
        Initialize the Git loader.

        Parameters
        ----------
        repo_path : PathLike
            Path to the local Git repository.
        clone_url : str | None, optional
            URL to the remote Git repository, by default None
        ref : typing.Optional[str], optional
            Commit ID to load files from, by default "main"
        include : typing.Optional[typing.Iterable[str]], optional
            A list of file patterns to include. Uses the glob syntax, by default None
        exclude : typing.Optional[typing.Iterable[str]], optional
            A list of file patterns to exclude. Uses the glob syntax, by default None
        """

        self.repo_path = Path(repo_path)
        self.clone_url = clone_url
        self.ref = ref

        self.include = include
        self.exclude = exclude

        self._repo: Repo | None = None

    def load_repo(self):
        """
        Load the Git repository and return the GitPython `Repo` object.

        Returns
        -------
        Repo
            GitPython `Repo` object representing the Git repository.

        Raises
        ------
        ValueError
            If the repository path does not exist.
        ValueError
            If a different repository is already cloned at the path.
        """

        if (self._repo is not None):
            return self._repo

        if not os.path.exists(self.repo_path) and self.clone_url is None:
            raise ValueError(f"Path {self.repo_path} does not exist")
        elif self.clone_url:
            # If the repo_path already contains a git repository, verify that it's the
            # same repository as the one we're trying to clone.
            if os.path.isdir(os.path.join(self.repo_path, ".git")):
                repo = Repo(self.repo_path)
                # If the existing repository is not the same as the one we're trying to
                # clone, raise an error.
                if repo.remotes.origin.url != self.clone_url:
                    raise ValueError("A different repository is already cloned at this path.")

                logger.info("Updating existing Git repo for URL '%s' @ '%s'", self.clone_url, self.ref)
            else:
                logger.info("Cloning repository from URL: '%s' @ '%s'", self.clone_url, self.ref)
                # Create a shallow clone of the repository without checking out
                repo = Repo.clone_from(self.clone_url, self.repo_path, depth=1, no_checkout=True)

                # Set repo as git safe directory to avoid errors if directory ownership is changed outside the pipeline
                # https://git-scm.com/docs/git-config#Documentation/git-config.txt-safedirectory
                with repo.config_writer(config_level="global") as config:
                    config.add_value("safe", "directory", str(self.repo_path.absolute()))

        else:
            repo = Repo(self.repo_path)
            logger.info("Using existing Git repo at path: '%s' @ '%s'", self.repo_path, self.ref)

        # Reliable way to check out the ref using a shallow clone
        repo.git.fetch("origin", self.ref, depth=1)
        repo.git.checkout("FETCH_HEAD")

        logger.info("Loaded Git repository at path: '%s' @ '%s'", self.repo_path, self.ref)

        self._repo = repo

        return repo

    def yield_blobs(self) -> typing.Iterator[Blob]:
        """
        Yield the blobs from the Git repository. One blob will be generated for each file in the repo which passes the
        include and exclude filters.

        Returns
        -------
        typing.Iterator[Blob]
            An iterator of `Blob` objects representing the files in the repository.

        Yields
        ------
        Iterator[typing.Iterator[Blob]]
            An iterator of `Blob` objects representing the files in the repository.
        """

        repo = self.load_repo()

        logger.info("Scanning documents for Git repository at path: '%s'", self.repo_path)

        all_files_in_repo = [str(item.path) for item in repo.tree().traverse() if isinstance(item, GitBlob)]

        base_path = Path(self.repo_path)

        include_files: set[str] = set()
        exclude_files: set[str] = set()

        for inc in self.include or ["**/*"]:
            include_files = include_files.union(set(str(x.relative_to(base_path)) for x in base_path.glob(inc)))

        for exc in self.exclude or {}:
            exclude_files = exclude_files.union(set(str(x.relative_to(base_path)) for x in base_path.glob(exc)))

        # Filter out files that are not in the repo
        include_files = include_files.intersection(all_files_in_repo)

        # Take the include files and remove the exclude files.
        final_files = include_files - exclude_files

        logger.info("Processing %d files in the Git repository at path: '%s'", len(final_files), self.repo_path)

        for f in tqdm(final_files):

            file_path = Path(f)

            abs_file_path = base_path / file_path

            rel_file_path = str(file_path)

            metadata = {
                "source": rel_file_path,
                "file_path": rel_file_path,
                "file_name": file_path.name,
                "file_type": file_path.suffix,
            }

            yield Blob.from_path(abs_file_path, metadata=metadata)
