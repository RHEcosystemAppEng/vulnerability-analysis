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


import json
import logging
import typing

from pydantic import BaseModel as BaseModel
from pydantic.v1 import BaseModel as BaseModelV1

logger = logging.getLogger(__name__)


def to_serializable_object(obj: typing.Any):
    """
    Utility function for converting an object to a serializable one, useful for passing as a default to json.dumps().
    """
    # Convert Pydantic V1 objects
    if isinstance(obj, BaseModelV1):
        return obj.dict()

    # Convert Pydantic V2 objects
    elif isinstance(obj, BaseModel):
        return obj.model_dump()

    # Convert all other objects to string
    else:
        logger.warning("Serializing object with unsupported data type to string. Object: %s", obj)
        return str(obj)


def to_json(obj: typing.Any) -> str:
    """
    Serialize object to JSON string with json.dumps(), using the to_serializable_object function as default.
    """
    return json.dumps(obj, default=to_serializable_object)
