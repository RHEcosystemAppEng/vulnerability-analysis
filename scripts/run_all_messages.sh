#!/bin/bash
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

# Get the repository root directory
export REPO_ROOT=$(git rev-parse --show-toplevel)

# Find all of the input message JSON files and store in an array
input_files=($(find ${REPO_ROOT}/data/input_messages -name ${1:-"*.json"}))

# Run the LLM script for each input message
for input_file in ${input_files[@]}; do

   base_name=$(basename ${input_file})

   echo "Running workflow for ${base_name}..."

   dotenv -f .env run -- \
      nat run --config_file=configs/config.yml --input_file=${input_file}
done
