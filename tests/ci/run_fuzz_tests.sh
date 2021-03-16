#!/bin/bash -ex
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

source tests/ci/common_fuzz.sh

ls /
ls /corpus_repository
echo $CODEBUILD_CORPUS_REPOSITORY


echo "Building fuzz tests."
build_and_test -DCMAKE_BUILD_TYPE=RelWithDebInfo -DFUZZ=1

pwd
ls
ls test_build_dir/fuzz
fuzz_executables=$(find test_build_dir/fuzz -type f -executable)

for fuzz_path in $fuzz_executables;do
  fuzz_name=$(basename $fuzz_path)
  temp_corpus="test_build_dir/fuzz/${fuzz_name}_new_corpus"
  mkdir -p $temp_corpus
  ${fuzz_path} -timeout=5 -print_final_stats=1 -jobs=1 -workers=1 -max_total_time=60 $temp_corpus "fuzz/${fuzz_name}_corpus"
  ${fuzz_path} -merge=1 "fuzz/${fuzz_name}_corpus" $temp_corpus
done