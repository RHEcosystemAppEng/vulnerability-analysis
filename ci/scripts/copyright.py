# SPDX-FileCopyrightText: Copyright (c) 2019-2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

import argparse
import datetime
import enum
import io
import logging
import os
import re
import sys
import typing

# Now import gitutils. Ignore flake8 error here since there is no other way to
# set up imports
import gitutils  # noqa: E402

# pylint: disable=global-statement

FilesToCheck = [
    # Get all of these extensions and templates (*.in)
    re.compile(r"[.](cmake|cpp|cc|cu|cuh|h|hpp|md|rst|sh|pxd|py|pyx|yml|yaml)(\.in)?$"),
    # And files with a particular file/extension combo
    re.compile(r"CMakeLists[.]txt$"),
    re.compile(r"setup[.]cfg$"),
    re.compile(r"[.]flake8[.]cython$"),
    re.compile(r"meta[.]yaml$"),
    re.compile(r"[^ \/\n]*Dockerfile[^ \/\n]*")
]

# Nothing in a build folder or .cache
ExemptFiles: typing.List[re.Pattern] = [
    re.compile(r"(_version|versioneer)\.py"),  # Skip versioning files
    re.compile(r"^[^ \/\n]*\.cache[^ \/\n]*\/.*$"),  # Ignore .cache folder
    re.compile(r"^[^ \/\n]*build[^ \/\n]*\/.*$"),  # Ignore any build*/ folder
    re.compile(r"^external\/.*$"),  # Ignore external
    re.compile(r"[^ \/\n]*docs/source/(_lib|_modules|_templates)/.*$"),
    re.compile(r"PULL_REQUEST_TEMPLATE.md"),  # Ignore the PR template,
    re.compile(r"[^ \/\n]*conda/environments/.*\.yaml$"),  # Ignore generated environment files
]

# this will break starting at year 10000, which is probably OK :)
CheckSimple = re.compile(r"Copyright *(?:\(c\))? *(\d{4}),? *NVIDIA C(?:ORPORATION|orporation)")
CheckDouble = re.compile(r"Copyright *(?:\(c\))? *(\d{4})-(\d{4}),? *NVIDIA C(?:ORPORATION|orporation)")
CHECK_APACHE_LIC = 'Licensed under the Apache License, Version 2.0 (the "License");'


def is_file_empty(f):
    return os.stat(f).st_size == 0


def check_this_file(f):
    # This check covers things like symlinks which point to files that DNE
    if not (os.path.exists(f)):
        return False
    if is_file_empty(f):
        return False
    for exempt in ExemptFiles:
        if exempt.search(f):
            return False
    for checker in FilesToCheck:
        if checker.search(f):
            return True
    return False


def get_copyright_years(line):
    res = CheckSimple.search(line)
    if res:
        return (int(res.group(1)), int(res.group(1)))
    res = CheckDouble.search(line)
    if res:
        return (int(res.group(1)), int(res.group(2)))
    return (None, None)


def replace_current_year(line, start, end):
    # first turn a simple regex into double (if applicable). then update years
    res = CheckSimple.sub(r"Copyright (c) \1-\1, NVIDIA CORPORATION", line)

    # pylint: disable=consider-using-f-string
    res = CheckDouble.sub(r"Copyright (c) {:04d}-{:04d}, NVIDIA CORPORATION".format(start, end), res)
    return res


class LicenseType(enum.Enum):
    APACHE = "apache"
    PROPRIETARY = "proprietary"

    def __str__(self):
        return self.value


def insert_license(f, this_year, first_line, license_type=LicenseType.APACHE):
    ext = os.path.splitext(f)[1].lstrip('.')
    basename = os.path.basename(f)

    try:
        # Try exact filename first (for files like Dockerfile)
        if basename in EXT_LIC_MAPPING:
            mapping = EXT_LIC_MAPPING[basename]
        else:
            mapping = EXT_LIC_MAPPING[ext]

        if license_type == LicenseType.APACHE:
            license_text = mapping[0].format(YEAR=this_year)
        elif license_type == LicenseType.PROPRIETARY:
            # Get the proprietary license regex pattern and convert it to a clean template
            license_regex = mapping[1]
            license_template = (license_regex.pattern
                              .replace(r"\(", "(")
                              .replace(r"\)", ")")
                              .replace(r"\.", ".")
                              .replace(r",?", "")
                              .replace(r"((\d{4})|(\d{4})-(\d{4}))", "{YEAR}")
                              .replace(r"\.\\n", ".\n"))
            license_text = license_template.format(YEAR=this_year)
        else:
            raise ValueError(f"Unsupported license type: {license_type}")
    except KeyError:
        return [
            f,
            0,
            f"Unsupported file type {basename if basename in EXT_LIC_MAPPING else ext} for automatic insertion of {license_type.value} license",
            None
        ]

    # If the file starts with a #! keep it as the first line
    if first_line.startswith("#!"):
        replace_line = first_line + license_text
    else:
        replace_line = f"{license_text}\n{first_line}"

    return [f, 1, f"{license_type.value.capitalize()} license inserted", replace_line]


def remove_proprietary(f):
    with io.open(f, "r", encoding="utf-8") as file:
        content = file.read()

    ext = os.path.splitext(f)[1].lstrip('.')
    basename = os.path.basename(f)

    try:
        # Try exact filename first (for files like Dockerfile)
        if basename in EXT_LIC_MAPPING:
            prop_re = EXT_LIC_MAPPING[basename][1]
        else:
            prop_re = EXT_LIC_MAPPING[ext][1]
    except KeyError:
        return [f, 0, f"Unsupported file type {basename if basename in EXT_LIC_MAPPING else ext} for proprietary license removal", None]

    match = prop_re.search(content)
    if match is not None:
        content = content.replace(match.group(0), "")

        with io.open(f, "w", encoding="utf-8") as file:
            file.write(content)

    return [f, 1, "Proprietary license replaced", ""]


def check_copyright(f,
                    update_current_year,
                    verify_apache_v2=False,
                    update_start_year=False,
                    do_insert_license=False,
                    license_type=LicenseType.APACHE,
                    git_add=False):
    """
    Checks for copyright headers and their years
    """
    errs = []
    this_year = datetime.datetime.now().year
    line_num = 0
    cr_found = False
    apache_lic_found = not verify_apache_v2
    year_matched = False
    with io.open(f, "r", encoding="utf-8") as file:
        lines = file.readlines()
    for line in lines:
        line_num += 1
        if not apache_lic_found:
            apache_lic_found = CHECK_APACHE_LIC in line

        start, end = get_copyright_years(line)
        if start is None:
            continue

        cr_found = True
        if update_start_year:
            try:
                git_start = gitutils.get_file_add_date(f).year
                if start > git_start:
                    e = [
                        f,
                        line_num,
                        "Current year not included in the "
                        "copyright header",
                        replace_current_year(line, git_start, this_year)
                    ]
                    errs.append(e)
                    continue

            except Exception as excp:
                e = [f, line_num, f"Error determining start year from git: {excp}", None]
                errs.append(e)
                continue

        if start > end:
            e = [f, line_num, "First year after second year in the copyright header (manual fix required)", None]
            errs.append(e)
        if this_year < start or this_year > end:
            e = [f, line_num, "Current year not included in the copyright header", None]
            if this_year < start:
                e[-1] = replace_current_year(line, this_year, end)
            if this_year > end:
                e[-1] = replace_current_year(line, start, this_year)
            errs.append(e)
        else:
            year_matched = True
    file.close()

    if not apache_lic_found:
        if len(lines) > 0:
            if do_insert_license and len(lines):
                e = insert_license(f, this_year, lines[0], license_type)
                cr_found = True
                year_matched = True
            else:
                e = [
                    f,
                    0,
                    "Apache copyright header missing, if this file needs to be "
                    "excempted from this check add it to the 'ExemptFiles' list in "
                    "the 'ci/scripts/copyright.py' file.",
                    True
                ]
            errs.append(e)

    # copyright header itself not found
    if not cr_found:
        e = [f, 0, "Copyright header missing or formatted incorrectly (manual fix required)", None]
        errs.append(e)

    # even if the year matches a copyright header, make the check pass
    if year_matched and apache_lic_found:
        errs = []

    if update_current_year or update_start_year or do_insert_license:
        errs_update = [x for x in errs if x[-1] is not None]
        if len(errs_update) > 0:
            logging.info("File: %s. Changing line(s) %s", f, ', '.join(str(x[1]) for x in errs if x[-1] is not None))
            for _, line_num, __, replacement in errs_update:
                if line_num > 0:
                    line_num -= 1
                lines[line_num] = replacement
            with io.open(f, "w", encoding="utf-8") as out_file:
                for new_line in lines:
                    out_file.write(new_line)

            if git_add:
                gitutils.add_files(f)

        errs = [x for x in errs if x[-1] is None]

    return errs


def _main():
    """
    Checks for copyright headers in all the modified files. In case of local
    repo, this script will just look for uncommitted files and in case of CI
    it compares between branches "$PR_TARGET_BRANCH" and "current-pr-branch"
    """
    log_level = logging.getLevelName(os.environ.get("MORPHEUS_LOG_LEVEL", "INFO"))
    logging.basicConfig(format="%(levelname)s:%(message)s", level=log_level)

    ret_val = 0
    global ExemptFiles

    argparser = argparse.ArgumentParser("Checks for a consistent copyright header in git's modified files")
    argparser.add_argument("--update-start-year",
                           dest='update_start_year',
                           action="store_true",
                           required=False,
                           help="If set, "
                           "update the start year based on a start date parsed "
                           "on the earliest entry from `git log --follow` will "
                           "only set the year if it is less than the current "
                           "copyright year")
    argparser.add_argument("--update-current-year",
                           dest='update_current_year',
                           action="store_true",
                           required=False,
                           help="If set, "
                           "update the current year if a header is already "
                           "present and well formatted.")

    argparser.add_argument("--insert",
                           dest='insert',
                           action="store_true",
                           required=False,
                           help="If set, "
                           "inserts the specified license type into files "
                           "without a license")
    argparser.add_argument("--license-type",
                           dest='license_type',
                           type=LicenseType,
                           choices=list(LicenseType),
                           default=LicenseType.APACHE,
                           help="The type of license to insert (default: apache)")
    argparser.add_argument("--remove-proprietary",
                           dest='remove_proprietary',
                           action="store_true",
                           required=False,
                           help="If set, removes the proprietary license from the file")
    argparser.add_argument(
        "--fix-all",
        dest='fix_all',
        action="store_true",
        required=False,
        help="Shortcut for setting --update-start-year --update-current-year  --insert and --remove-proprietary")

    git_group = argparser.add_mutually_exclusive_group()
    git_group.add_argument("--git-modified-only",
                           dest='git_modified_only',
                           action="store_true",
                           required=False,
                           help="If set, "
                           "only files seen as modified by git will be "
                           "processed. Cannot be combined with --git-diff-commits or --git-diff-staged")
    git_group.add_argument("--git-diff-commits",
                           dest='git_diff_commits',
                           required=False,
                           nargs=2,
                           metavar='hash',
                           help="If set, "
                           "only files modified between the two given commit hashes. "
                           "Cannot be combined with --git-modified-only or --git-diff-staged")
    git_group.add_argument("--git-diff-staged",
                           dest='git_diff_staged',
                           required=False,
                           nargs="?",
                           metavar='HEAD',
                           default=None,
                           const='HEAD',
                           help="If set, "
                           "only files staged for commit. "
                           "Cannot be combined with --git-modified-only or --git-diff-commits")

    argparser.add_argument("--git-add",
                           dest='git_add',
                           action="store_true",
                           required=False,
                           help="If set, "
                           "any files auto-fixed will have `git add` run on them. ")

    argparser.add_argument("--verify-apache-v2",
                           dest='verify_apache_v2',
                           action="store_true",
                           required=False,
                           help="If set, "
                           "verifies all files contain the Apache license "
                           "in their header")
    argparser.add_argument("--exclude",
                           dest='exclude',
                           action="append",
                           required=False,
                           default=["_version\\.py"],
                           help=("Exclude the paths specified (regexp). "
                                 "Can be specified multiple times."))

    (args, dirs) = argparser.parse_known_args()
    try:
        ExemptFiles = ExemptFiles + [re.compile(pathName) for pathName in args.exclude]
    except re.error as re_exception:
        logging.exception("Regular expression error: %s", re_exception, exc_info=True)
        return 1

    if args.git_modified_only:
        files = gitutils.modified_files()
    elif args.git_diff_commits:
        files = gitutils.changed_files(*args.git_diff_commits)
    elif args.git_diff_staged:
        files = gitutils.staged_files(args.git_diff_staged)
    else:
        files = gitutils.all_files(*dirs)

    logging.debug("File count before filter(): %s", len(files))

    # Now filter the files down based on the exclude/include
    files = gitutils.filter_files(files, path_filter=check_this_file)

    logging.info("Checking files (%s):\n   %s", len(files), "\n   ".join(files))

    errors = []
    for f in files:
        if args.remove_proprietary or args.fix_all:
            remove_proprietary(f)

        errors += check_copyright(f,
                                  args.update_current_year,
                                  verify_apache_v2=(args.verify_apache_v2 or args.insert or args.fix_all),
                                  update_start_year=(args.update_start_year or args.fix_all),
                                  do_insert_license=(args.insert or args.fix_all),
                                  license_type=args.license_type,
                                  git_add=args.git_add)

    if len(errors) > 0:
        logging.info("Copyright headers incomplete in some of the files!")
        for e in errors:
            logging.error("  %s:%d Issue: %s", e[0], e[1], e[2])
        logging.info("")
        n_fixable = sum(1 for e in errors if e[-1] is not None)
        path_parts = os.path.abspath(__file__).split(os.sep)
        file_from_repo = os.sep.join(path_parts[path_parts.index("ci"):])
        if n_fixable > 0:
            logging.info(("You can run `python %s --git-modified-only "
                          "--update-current-year --insert` to fix %s of these "
                          "errors.\n"),
                         file_from_repo,
                         n_fixable)
        ret_val = 1
    else:
        logging.info("Copyright check passed")

    return ret_val


A2_LIC_HASH = """# SPDX-FileCopyrightText: Copyright (c) {YEAR}, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
"""

A2_LIC_C = """/*
 * SPDX-FileCopyrightText: Copyright (c) {YEAR}, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
"""

A2_LIC_MD = """<!--
SPDX-FileCopyrightText: Copyright (c) {YEAR}, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->
"""

A2_LIC_RST = """..
   SPDX-FileCopyrightText: Copyright (c) {YEAR}, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
   SPDX-License-Identifier: Apache-2.0

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

"""

NV_PROP_LIC_HASH_RE = re.compile(
    r"""# SPDX-FileCopyrightText: Copyright \(c\) ((\d{4})|(\d{4})-(\d{4})),? NVIDIA CORPORATION & AFFILIATES\. All rights reserved\.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary
#
# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto\. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited\.
""",
    re.MULTILINE)

NV_PROP_LIC_C_RE = re.compile(
    r"""/\*
 \* SPDX-FileCopyrightText: Copyright \(c\) ((\d{4})|(\d{4})-(\d{4})),? NVIDIA CORPORATION & AFFILIATES\. All rights reserved\.
 \* SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 \*
 \* NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 \* property and proprietary rights in and to this material, related
 \* documentation and any modifications thereto\. Any use, reproduction,
 \* disclosure or distribution of this material and related documentation
 \* without an express license agreement from NVIDIA CORPORATION or
 \* its affiliates is strictly prohibited\.
 \*/
""",
    re.MULTILINE)

NV_PROP_LIC_MD_RE = re.compile(
    r"""<!--
SPDX-FileCopyrightText: Copyright \(c\) ((\d{4})|(\d{4})-(\d{4})),? NVIDIA CORPORATION & AFFILIATES\. All rights reserved\.
SPDX-License-Identifier: LicenseRef-NvidiaProprietary

NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
property and proprietary rights in and to this material, related
documentation and any modifications thereto\. Any use, reproduction,
disclosure or distribution of this material and related documentation
without an express license agreement from NVIDIA CORPORATION or
its affiliates is strictly prohibited\.
-->
""",
    re.MULTILINE)

NV_PROP_LIC_RST_RE = re.compile(
    r"""\.\.
   SPDX-FileCopyrightText: Copyright \(c\) ((\d{4})|(\d{4})-(\d{4})),? NVIDIA CORPORATION & AFFILIATES\. All rights reserved\.
   SPDX-License-Identifier: LicenseRef-NvidiaProprietary

   NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
   property and proprietary rights in and to this material, related
   documentation and any modifications thereto\. Any use, reproduction,
   disclosure or distribution of this material and related documentation
   without an express license agreement from NVIDIA CORPORATION or
   its affiliates is strictly prohibited\.

""",
    re.MULTILINE)

# FilesToCheck list will allow us to assume Cmake for the txt extension
EXT_LIC_MAPPING = {
    'c': (A2_LIC_C, NV_PROP_LIC_C_RE),
    'cc': (A2_LIC_C, NV_PROP_LIC_C_RE),
    'cmake': (A2_LIC_HASH, NV_PROP_LIC_HASH_RE),
    'cpp': (A2_LIC_C, NV_PROP_LIC_C_RE),
    'cu': (A2_LIC_C, NV_PROP_LIC_C_RE),
    'cuh': (A2_LIC_C, NV_PROP_LIC_C_RE),
    'Dockerfile': (A2_LIC_HASH, NV_PROP_LIC_HASH_RE),
    'h': (A2_LIC_C, NV_PROP_LIC_C_RE),
    'hpp': (A2_LIC_C, NV_PROP_LIC_C_RE),
    'md': (A2_LIC_MD, NV_PROP_LIC_MD_RE),
    'pxd': (A2_LIC_HASH, NV_PROP_LIC_HASH_RE),
    'py': (A2_LIC_HASH, NV_PROP_LIC_HASH_RE),
    'pyx': (A2_LIC_HASH, NV_PROP_LIC_HASH_RE),
    'rst': (A2_LIC_RST, NV_PROP_LIC_RST_RE),
    'sh': (A2_LIC_HASH, NV_PROP_LIC_HASH_RE),
    'txt': (A2_LIC_HASH, NV_PROP_LIC_HASH_RE),
    'yaml': (A2_LIC_HASH, NV_PROP_LIC_HASH_RE),
    'yml': (A2_LIC_HASH, NV_PROP_LIC_HASH_RE),
}

if __name__ == "__main__":
    sys.exit(_main())
