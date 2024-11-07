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

from .sbom_parser import SBOMParser


class Syft(SBOMParser):

    def __init__(self, file: str, *args, **kwargs):
        assert file is not None, 'File parameter required for Syft parser'
        super().__init__(file=file)

    @classmethod
    def get_name(cls) -> str:
        return 'syft'

    def parse(self) -> dict[str, str]:
        if os.path.isfile(self.file):
            with open(self.file, 'r') as sbom_in:
                sbom = sbom_in.read()
        else:
            sbom = self.file
        sbom_split = sbom.split('\n')

        sbom_map = dict()
        for idx, line in enumerate(sbom_split):
            if line.startswith('['):
                if sbom_split[idx + 1].startswith(' Version:'):
                    sbom_map[line[1:-1].lower()] = sbom_split[idx + 1].split('\t')[-1].strip()
        return sbom_map
