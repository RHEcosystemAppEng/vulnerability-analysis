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


import logging
import os
import typing
from enum import Enum
from pathlib import Path

import mrc
import mrc.core.operators as ops
from pydantic import BaseModel

from morpheus.config import Config
from morpheus.pipeline.pass_thru_type_mixin import PassThruTypeMixin
from morpheus.pipeline.single_port_stage import SinglePortStage

logger = logging.getLogger(__name__)


class WriteFileMode(Enum):
    """
    Enum for the write file mode.
    """
    CREATE = "x"  # Create a new file and open it for writing. If the file already exists, the operation will fail.
    APPEND = "a"  # Open the file and append to it. If the file does not exist, it will be created.
    OVERWRITE = "w"  # Open the file and write to it. If the file exists, it will be overwritten.


class WritePydanticToFile(PassThruTypeMixin, SinglePortStage):
    """
    Writes pydantic model to file, used in place of `WriteToFileStage` which requires MessageMeta.

    Parameters
    ----------
    c : Config
        The configuration object.
    filename : str
        The name of the file to write to.
    mode : WriteFileMode, optional
        The write file mode, by default WriteFileMode.CREATE.
    """

    def __init__(self, c: Config, filename: str, mode: WriteFileMode = WriteFileMode.CREATE):

        super().__init__(c)

        self._filename = filename
        self._mode = mode

        if (os.path.exists(self._filename)):
            if (self._mode == WriteFileMode.CREATE):
                raise FileExistsError(
                    f"Cannot write model output to '{self._filename}'. File exists and overwrite = False")
            elif (self._mode == WriteFileMode.APPEND):
                logger.warning(f"Appending to existing file: {self._filename}")
            elif (self._mode == WriteFileMode.OVERWRITE):
                logger.warning(f"Overwriting existing file: {self._filename}")
                os.remove(self._filename)
            else:
                assert False, f"Invalid mode: {self._mode}"
        else:
            # Ensure our directory exists
            os.makedirs(os.path.realpath(os.path.dirname(self._filename)), exist_ok=True)

    @property
    def name(self) -> str:
        return "write-pydantic-to-file"

    def accepted_types(self) -> typing.Tuple:
        """
        Accepted input types for this stage are returned.

        Returns
        -------
        typing.Tuple
            Accepted input types.

        """
        return (BaseModel, )

    def supports_cpp_node(self):
        return False

    def _on_data(self, model: BaseModel) -> BaseModel:
        # Validate that model is a Pydantic object
        if not isinstance(model, BaseModel):
            raise TypeError(f"Expected output to be a Pydantic BaseModel but received: {type(model)}")

        file_path = Path(self._filename)

        # Write file depending on setting for overwrite
        model_json = model.model_dump_json(by_alias=True)

        file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, 'a') as f:
            f.write(model_json)

        # Make stage a pass-through
        return model

    def _build_single(self, builder: mrc.Builder, input_node: mrc.SegmentObject) -> mrc.SegmentObject:

        node = builder.make_node(self.unique_name, ops.map(self._on_data))

        builder.make_edge(input_node, node)

        return node
