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


import abc
import importlib
import typing

if (typing.TYPE_CHECKING):
    from .syft_parser import Syft


class SBOMParser(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def __init__(self, file: str, *args, **kwargs):
        self.file = file

    @classmethod
    @abc.abstractmethod
    def get_name(cls) -> str:
        pass

    @abc.abstractmethod
    def parse(self) -> dict:
        """
        The parse method takes the SBOM input and creates a dictionary where keys are the names of the
        installed packages and values are the versions of those packages.

        Returns
        -------
        dict[str, str]
            The installed packages and their versions from the provided SBOM.
        """
        pass

    @typing.overload
    @staticmethod
    def create(parser_type: typing.Literal["syft"], *parser_args, **parser_kwargs) -> "Syft":
        pass

    @typing.overload
    @staticmethod
    def create(parser_type: str, *parser_args, **parser_kwargs) -> "SBOMParser":
        pass

    @staticmethod
    def create(parser_type: str | typing.Literal["syft"], *parser_args, **parser_kwargs):
        """
        Returns an SBOM parser for use in the SBOM Look-up tool.
        Parameters
        ----------
        parser_type : str
            The type of SBOM parser to create
        parser_args : dict[str, typing.Any]
            Additional keyword arguments to pass to the parser
        """
        module_name = f".{parser_type.lower()}_parser"
        module = importlib.import_module(module_name, __package__)

        mod_classes = dict([(name, cls) for name, cls in module.__dict__.items() if isinstance(cls, type)])

        matching_classes = [name for name in mod_classes if name.lower() == parser_type]

        assert len(matching_classes) == 1, (f"Expected to find exactly one class with name {parser_type} in module "
                                            f"{module_name}, but found {matching_classes}")

        class_ = getattr(module, matching_classes[0])

        instance = class_(*parser_args, **parser_kwargs)

        return instance
