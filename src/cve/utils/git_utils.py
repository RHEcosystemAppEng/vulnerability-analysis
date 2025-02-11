# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

from pathlib import Path
from pathlib import PurePath

from git import Repo


def get_repo_from_path(base_dir: str, git_repo: str = ".git") -> Repo:
    """
    Utility function for getting GitPython `Repo` object representing a Git repository.

    Parameters
    ----------
    base_dir : str
        Path to base directory containing one or more Git repos
    git_repo : str
        Relative path to Git repo in base_dir, default is ".git"

    Returns
    -------
    repo
        GitPython `Repo` object representing the Git repository.

    Raises
    ------
    ValueError
        If the repository path does not exist.
    """
    repo_path = base_dir / PurePath(git_repo)
    repo_path = Path(repo_path)
    if os.path.exists(repo_path):
        try:
            return Repo(repo_path)
        except Exception as e:
            raise ValueError(f"Invalid Git repository: {repo_path}") from e
    else:
        raise ValueError(f"Path {repo_path} does not exist")
