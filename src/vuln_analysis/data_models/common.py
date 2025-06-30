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

import sys
import typing
from hashlib import sha512

from pydantic import BaseModel
from pydantic import Field

_LT = typing.TypeVar("_LT")


class HashableModel(BaseModel):
    """
    Subclass of a Pydantic BaseModel that is hashable. Use in objects that need to be hashed for caching purposes.
    """

    def __hash__(self):
        return int.from_bytes(bytes=sha512(f"{self.__class__.__qualname__}::{self.model_dump_json()}".encode(
            'utf-8', errors='ignore')).digest(),
                              byteorder=sys.byteorder)

    def __lt__(self, other):
        return self.__hash__() < other.__hash__()

    def __eq__(self, other):
        return self.__hash__() == other.__hash__()

    def __ne__(self, other):
        return self.__hash__() != other.__hash__()

    def __gt__(self, other):
        return self.__hash__() > other.__hash__()


class TypedBaseModel(BaseModel, typing.Generic[_LT]):
    """
    Subclass of Pydantic BaseModel that allows for specifying the object type. Use in Pydantic discriminated unions.
    """

    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs):
        super().__pydantic_init_subclass__(**kwargs)

        if (cls.__pydantic_generic_metadata__["origin"] is TypedBaseModel):
            # Because we are using a generic type, we need to set the default value of the type field when instantiating
            # a base class. This is the only way to get the value from a typing.Literal
            cls.model_fields["type"].default = typing.get_args(cls.__pydantic_generic_metadata__["args"][0])[0]

    type: _LT = Field(init=False, alias="_type", description="The type of the object", title="Type")

    @classmethod
    def static_type(cls):
        return cls.model_fields["type"].default

    @staticmethod
    def discriminator(v: typing.Any) -> str | None:
        # If its serialized, then we use the alias
        if isinstance(v, dict):
            return v.get("_type", v.get("type"))

        # Otherwise we use the property
        return getattr(v, "type")
