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

import logging
from typing import Any
from typing import List
from typing import Tuple

import esprima
from langchain_community.document_loaders.parsers.language.javascript import JavaScriptSegmenter

logger = logging.getLogger(__name__)


class ExtendedJavaScriptSegmenter(JavaScriptSegmenter):
    """Extended JavaScript segmenter that handles shebang and ES optional chaining."""

    def __init__(self, code: str):
        """Initialize the segmenter with preprocessed code."""
        super().__init__(code)
        # Skip files with shebang (#!) line since they typically contain non-standard JavaScript syntax
        if code.startswith("#!"):
            logger.warning("File contains a shebang line. Skipping parsing.")
            self.skip_file = True
        # esprima-python parser limitation: cannot handle JavaScript optional chaining syntax,
        # fallback to regular property access
        else:
            self.skip_file = False
            self.code = self.code.replace("?.", ".")

    def _parse_with_fallback(self) -> Any:
        """Try to parse code as script first, then as module if that fails."""
        try:
            logger.debug("Attempting to parse as a script...")
            return esprima.parseScript(self.code, loc=True)
        except esprima.Error:
            logger.debug("Script parsing failed. Trying module parsing...")
            try:
                return esprima.parseModule(self.code, loc=True)
            except esprima.Error as e:
                logger.error("Module parsing failed: %s", str(e))
                return None

    def extract_functions_classes(self) -> List[str]:
        """Extract functions, classes and exports from the code."""
        if self.skip_file:
            return []

        tree = self._parse_with_fallback()
        if tree is None:
            return []

        functions_classes = []
        for node in tree.body:
            # Handle direct function/class declarations
            if isinstance(node, (esprima.nodes.FunctionDeclaration, esprima.nodes.ClassDeclaration)):
                functions_classes.append(self._extract_code(node))
            # Handle exported declarations
            elif isinstance(node, esprima.nodes.ExportNamedDeclaration):
                if isinstance(node.declaration, (esprima.nodes.FunctionDeclaration, esprima.nodes.ClassDeclaration)):
                    functions_classes.append(self._extract_code(node))

        return functions_classes

    def simplify_code(self) -> str:
        """Simplify the code by replacing function/class bodies with comments."""
        if self.skip_file:
            return self.code

        tree = self._parse_with_fallback()
        if tree is None:
            return self.code

        simplified_lines = self.source_lines[:]
        indices_to_del: List[Tuple[int, int]] = []

        for node in tree.body:
            if isinstance(node, (esprima.nodes.FunctionDeclaration, esprima.nodes.ClassDeclaration)):
                start, end = node.loc.start.line - 1, node.loc.end.line
                simplified_lines[start] = f"// Code for: {simplified_lines[start]}"
                indices_to_del.append((start + 1, end))
            elif isinstance(node, esprima.nodes.ExportNamedDeclaration):
                if isinstance(node.declaration, (esprima.nodes.FunctionDeclaration, esprima.nodes.ClassDeclaration)):
                    start, end = node.loc.start.line - 1, node.loc.end.line
                    simplified_lines[start] = f"// Code for: {simplified_lines[start]}"
                    indices_to_del.append((start + 1, end))

        for start, end in reversed(indices_to_del):
            del simplified_lines[start:end]

        return "\n".join(line for line in simplified_lines)
