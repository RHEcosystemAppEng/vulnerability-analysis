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
import re
from collections.abc import Iterable

from langchain.docstore.document import Document
from langchain.document_loaders.text import TextLoader
from langchain_community.retrievers import BM25Retriever


class LangchainCodeSearcher:
    """
    Searcher for code using langchain document loader/chunker

    Parameters
    ----------
    documents : list[Document]
        list of documents to search
    k : int, default = 5
        Number of documents to retrieve when performing a search
    rank_documents : bool, default = False
        When True, and the number of retrieved documents is greater than k, search results are ranked using the bm25
        method.
    """

    def __init__(self, documents: list[Document], k: int = 5, rank_documents: bool = False):
        self.documents = documents
        self.k = k
        self.rank_documents = rank_documents

    @classmethod
    def load_from_repo(cls,
                       repo_path: str,
                       include_extensions: Iterable[str],
                       k: int = 5,
                       rank_documents: bool = False):
        """
        Loads all files from a repo into a list of documents.

        Parameters
        ----------
        repo_path : str
            path to the repository
        include_extensions : list[str]
            list of file extensions to include
        k : int, default = 5
            number of documents to retrieve when performing a search
        rank_documents : bool, default = False
            When True, and the number of retrieved documents is greater than k, search results are ranked using the bm25
            method.
        """
        include_extensions = frozenset(include_extensions)

        documents = []
        for root, _, files in os.walk(repo_path):
            for file in files:
                ext = os.path.splitext(file)[1].lstrip('.')
                if ext in include_extensions:
                    file_path = os.path.join(root, file)
                    loader = TextLoader(file_path, encoding="utf-8")
                    documents.extend(loader.load())

        return cls(documents=documents, k=k, rank_documents=rank_documents)

    def search(self, query: str) -> list[Document]:
        """search for code

        Parameters
        ----------
        query : str
            query to search

        Returns
        -------
        list[Document]
            list of retrieved documents
        """

        query = re.sub(r"[^\w_.]+", "", query)
        pattern = re.compile(re.escape(query), re.IGNORECASE)
        results = []
        for doc in self.documents:
            if pattern.search(doc.page_content):
                results.append(doc)
        
        # use optional bm25 to rank the retrieved documents
        if self.rank_documents and len(results) > self.k:
            return BM25Retriever.from_documents(results, k=self.k).invoke(query)
        else:
            return results[:self.k]
