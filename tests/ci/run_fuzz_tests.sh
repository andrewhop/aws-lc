#!/bin/bash
set -exuo pipefail
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

source tests/ci/common_fuzz.sh


echo "Building fuzz tests."
run_build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DFUZZ=1

pwd
ls
ls test_build_dir/fuzz

DATE_NOW="$(date +%Y-%m-%d)"

FUZZ_TESTS=$(find test_build_dir/fuzz -type f -executable)
NUM_FUZZ_TESTS=$(wc -l "$FUZZ_TESTS")
# We want our CI to take about an hour:
# 2 minutes to build AWS-LC
# 50 minutes (3000 seconds) for all fuzzing
# 8 minutes for merging files
TOTAL_FUZZ_TEST_TIME=3000
TIME_FOR_EACH_FUZZ=$((TOTAL_FUZZ_TEST_TIME/NUM_FUZZ_TESTS))

for FUZZ_TEST in $FUZZ_TESTS;do
  FUZZ_NAME=$(basename "$FUZZ_TEST")

  SRC_CORPUS="${SRC_ROOT}/fuzz/${FUZZ_NAME}_corpus"
  SHARED_CORPUS="${CORPUS_ROOT}/${FUZZ_NAME}/shared_corpus"
  RUN_CORPUS="${CORPUS_ROOT}/${FUZZ_NAME}/run_corpus/${DATE_NOW}/${BUILD_ID}"
  mkdir -p "$SHARED_CORPUS" "$RUN_CORPUS"

  # Step 1 merge any new files from GitHub into the shared corpus
  time ${FUZZ_TEST} -merge=1 "$SHARED_CORPUS" "$SRC_CORPUS"

  # Step 2 run each fuzz test for the determined time
  # This will use the existing shared corpus and write new files to the run corpus
  # https://llvm.org/docs/LibFuzzer.html#options
  time ${FUZZ_TEST} -timeout=5 -print_final_stats=1 -jobs="$NUM_CPU_THREADS" -workers="$NUM_CPU_THREADS" \
    -max_total_time="$TIME_FOR_EACH_FUZZ" "$RUN_CORPUS" "$SHARED_CORPUS"

  # Step 3 merge any new coverage from the run corpus into the shared corpus
    time ${FUZZ_TEST} -merge=1 "$SHARED_CORPUS" "$RUN_CORPUS"
done