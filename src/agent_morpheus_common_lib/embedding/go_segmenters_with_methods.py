from typing import List
import re

from langchain_community.document_loaders.parsers.language.go import GoSegmenter


def parse_all_methods(code: str) -> list[str]:
    # regex = r"func\s*\([a-zA-Z0-9\s]*\) [a-zA-X]+\([a-zA-Z0-9\s]*\)([a-zA-Z0-9\s]*){"
    regex = r"func\s*\([a-zA-Z0-9\s\*.]+\) [a-zA-Z]+\([,a-zA-Z0-9\s\[\].]*\)\s*(\(?[a-zA-Z0-9\s.,*]+\)?)?\s*{"
    methods = get_all_functions(code, regex)
    return methods


def parse_all_anonymous_functions(code: str) -> list[str]:
    regex = r"(var)? [a-zA-Z0-9_]+\s*(:)?=\s*func\s*.*{"
    functions = get_all_functions(code, regex)
    return functions


def get_all_functions(code: str, regex: str):
    matches = re.finditer(regex, code)
    functions = list()
    for matchNum, match in enumerate(matches, start=1):
        curly_brackets_counter = 1
        internal_offset = 0
        current_method_body = code[match.end():]
        while curly_brackets_counter > 0 or internal_offset == 0:
            left_bracket_ind = current_method_body[internal_offset:].find("{")
            right_bracket_ind = current_method_body[internal_offset:].find("}")
            if left_bracket_ind < right_bracket_ind and left_bracket_ind != -1:
                curly_brackets_counter += 1
                internal_offset = internal_offset + left_bracket_ind + 1
            else:
                curly_brackets_counter -= 1
                internal_offset = internal_offset + right_bracket_ind + 1
        current_method = code[match.start(): match.end() + 1 + internal_offset]
        functions.append(current_method)
    return functions


class GoSegmenterWithMethods(GoSegmenter):

    def __init__(self, code: str):
        super().__init__(code)

    def extract_functions_classes(self) -> List[str]:
        function_classes = super().extract_functions_classes()
        methods_classes = parse_all_methods(self.code)
        parse_anonymous_functions = parse_all_anonymous_functions(self.code)
        function_classes.extend(methods_classes)
        function_classes.extend(parse_anonymous_functions)
        return function_classes

# test_str = """func (any *uint64Any) LastError() error {
# 	return nil
# }
# """
# parse_all_methods(test_str)
