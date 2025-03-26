from abc import ABC, abstractmethod

from langchain_core.documents import Document


class LanguageFunctionsParser(ABC):


    @abstractmethod
    def create_map_of_local_vars(self, functions_methods_documents: list[Document]) -> dict[str, dict]:
        pass

    @abstractmethod
    def parse_all_type_struct_class_to_fields(self, types: list[Document]) -> dict[tuple, list[tuple]]:
        pass

    @abstractmethod
    def get_function_name(self, function: Document) -> str:
        pass

    @abstractmethod
    def search_for_called_function(self, caller_function: Document, callee_function: str, callee_function_package: str,
                                   code_documents: list[Document], type_documents: list[Document],
                                   callee_function_file_name: str, fields_of_types: dict[tuple, list[tuple]],
                                   functions_local_variables_index: dict[str, dict]) -> bool:
        pass

    @abstractmethod
    def get_package_names(self, function: Document) -> list[str]:
        pass

    @abstractmethod
    def get_package_name(self, function: Document, package_name: str) -> str:
        pass

    @abstractmethod
    def is_root_package(self, function: Document) -> bool:
        pass

    @abstractmethod
    def is_comment_line(self, line: str) -> bool:
        pass

    @abstractmethod
    def get_comment_line_notation(self) -> str:
        pass

    @abstractmethod
    def is_exported_function(self, function: Document) -> bool:
        pass

    @abstractmethod
    def is_function(self, function: Document) -> bool:
        pass

    @abstractmethod
    def dir_name_for_3rd_party_packages(self) -> str:
        pass

    @abstractmethod
    def supported_files_extensions(self) -> list[str]:
        pass

    @abstractmethod
    def is_supported_file_extensions(self, extension: str) -> bool:
        pass

    @abstractmethod
    def is_searchable_file_name(self, function: Document) -> bool:
        pass

    @abstractmethod
    def get_function_reserved_word(self) -> str:
        pass

    @abstractmethod
    def get_type_reserved_word(self) -> str:
        pass
