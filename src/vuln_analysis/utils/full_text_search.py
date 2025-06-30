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
import os
import re
from pathlib import Path
from typing import Iterable

from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.document_loaders.generic import GenericLoader
from langchain_community.document_loaders.parsers import LanguageParser
from langchain_core.documents import Document
from tantivy import Document as TantivyDocument
from tantivy import Index
from tantivy import SchemaBuilder
from tqdm import tqdm

logger = logging.getLogger(__name__)

variable_pattern = re.compile(r"([A-Z][a-z]+|[a-z]+|[A-Z]+(?=[A-Z]|$))")


def tokenize_code(code: str) -> str:
    """
    Tokenize code into simple readable document format
    """
    matches = re.finditer(r"\b\w{2,}\b", code)
    tokens = []
    for m in matches:
        text = m.group()

        for section in text.split("_"):
            for part in variable_pattern.findall(section):
                if len(part) < 2:
                    continue
                if (sum(1 for c in part if "a" <= c <= "z" or "A" <= c <= "Z" or "0" <= c <= "9") > len(part) // 2
                        and len(part) / len(set(part)) < 4):
                    tokens.append(part.lower())

    return " ".join(tokens)


def clean_query(input_query) -> str:
    """
    Parse a query string with OR/AND operations and fix quotes issues using regex.
    """
    # Remove anything after newline characters
    if '\n' in input_query:
        input_query = input_query.split('\n')[0]

    # Remove outer quotes if the string is surrounded by quotes
    input_query = input_query.strip()
    if (input_query.startswith('"') and input_query.endswith('"')) or \
       (input_query.startswith("'") and input_query.endswith("'")):
        input_query = input_query[1:-1]

    # Replace escaped quotes with empty string
    input_query = re.sub(r'\\"|\\"', '', input_query)

    def replace_quoted(match):
        return match.group(1)

    # Remove quotes around terms while preserving content inside
    input_query = re.sub(r'["\'](.*?)["\']', replace_quoted, input_query)

    # Normalize operators to uppercase
    input_query = re.sub(r'\s+OR\s+', ' OR ', input_query, flags=re.IGNORECASE)
    input_query = re.sub(r'\s+AND\s+', ' AND ', input_query, flags=re.IGNORECASE)
    # Remove any remaining quotes (including trailing quotes)
    input_query = re.sub(r'["\'\`]', '', input_query)

    return input_query


class FullTextSearch:
    INDEX_TYPE = "tantivy"

    def __init__(self, cache_path: str = None, tokenizer=False):
        if cache_path:
            os.makedirs(cache_path, exist_ok=True)
        schema = self._build_schema()
        self.index = Index(schema, path=cache_path)
        self.index.reload()
        self.tokenizer = tokenizer

    @classmethod
    def get_index_directory(cls, base_path: str, hash_value: str) -> Path:
        """Returns the path where the index should be stored"""
        return Path(base_path) / cls.INDEX_TYPE / hash_value

    def _build_schema(self):
        """Build schema for the code index"""
        schema_builder = SchemaBuilder()
        schema_builder.add_text_field("file_path", stored=True)
        schema_builder.add_text_field("content", stored=True)
        schema_builder.add_integer_field("doc_id", stored=True)
        schema = schema_builder.build()
        return schema

    def add_documents(self, documents: Iterable):

        writer = self.index.writer()
        for doc_id, (title, text) in enumerate(documents):
            writer.add_document(TantivyDocument(file_path=title, content=text, doc_id=doc_id))
        writer.commit()

    def is_empty(self):
        return self.index.searcher().num_docs == 0

    def search_index(self, query: str, top_k: int = 10) -> list[dict] | str:

        self.index.reload()
        try:
            if self.tokenizer:
                query = tokenize_code(query)
            query = clean_query(query)
            query, _ = self.index.parse_query_lenient(query)
            searcher = self.index.searcher()
            results = searcher.search(query, limit=top_k).hits
            return [{
                "source": searcher.doc(doc_id)["file_path"][0], "content": searcher.doc(doc_id)["content"][0]
            } for _, doc_id in results]

        except Exception as e:
            logger.exception(e)
            return "There was an error searching for the query."

    def add_documents_from_langchain_chunks(self, documents: list[Document]):
        """Create an index from langchain chunked documents"""

        try:
            documents = [(doc.metadata['source'], doc.page_content) for doc in documents]
            if len(documents) == 0:
                return self.index

            self.add_documents(tqdm(documents, total=len(documents), desc="Indexing"))

        except Exception as e:
            logger.warning(f"Unable to add documents to the index {e}")

    def add_documents_from_code_path(self,
                                     code_path: str,
                                     include_extensions: list[str],
                                     use_langparser=True,
                                     splitter=True):
        """Create an index from raw files."""

        doc_content = []

        if use_langparser:

            loader = GenericLoader.from_filesystem(
                code_path,
                glob="**/*",
                suffixes=include_extensions,
                parser=LanguageParser(),
            )
            docs = loader.load()

            if splitter:
                text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
                docs = text_splitter.split_documents(docs)
            doc_content = [(doc.metadata["source"], doc.page_content) for doc in docs]

        else:

            for root, _, files in os.walk(code_path):
                for file in files:
                    if any(file.endswith(ext) for ext in include_extensions):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, "r") as f:
                                content = f.read()
                                if self.tokenizer:
                                    content = tokenize_code(content)
                                doc_content.append((file_path, content))
                        except Exception as e:
                            logger.warning(f"Error reading {file_path}: {e}")

        self.add_documents(doc_content)
