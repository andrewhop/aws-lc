#!/bin/bash
set -exuo pipefail
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

source tests/ci/common_fuzz.sh

echo "Building fuzz tests."
#run_build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DFUZZ=1

DATE_NOW="$(date +%Y-%m-%d)"
RUN_ROOT="${CORPUS_ROOT}/runs/${DATE_NOW}/${BUILD_ID}"

FUZZ_TESTS=$(find test_build_dir/fuzz -type f -executable)
NUM_FUZZ_TESTS=$(echo "$FUZZ_TESTS" | wc -l)
# We want our CI to take about an hour:
# 2 minutes to build AWS-LC
# 50 minutes (3000 seconds) for all fuzzing
# 8 minutes for merging files
TOTAL_FUZZ_TEST_TIME=3000
TIME_FOR_EACH_FUZZ=$((TOTAL_FUZZ_TEST_TIME/NUM_FUZZ_TESTS))
#TIME_FOR_EACH_FUZZ=120
for FUZZ_TEST in $FUZZ_TESTS;do
  FUZZ_NAME=$(basename "$FUZZ_TEST")

  SRC_CORPUS="${SRC_ROOT}/fuzz/${FUZZ_NAME}_corpus"
  SHARED_CORPUS="${CORPUS_ROOT}/shared_corpus/${FUZZ_NAME}/shared_corpus"
  ORIGINAL_SHARED_CORPUS_FILE_COUNT=$(find "$SHARED_CORPUS" -type f | wc -l)
  FUZZ_TEST_CORPUS="${RUN_ROOT}/${FUZZ_NAME}/run_corpus"
  LOG_FOLDER="${RUN_ROOT}/${FUZZ_NAME}/logs"
  SUMMARY_LOG="${LOG_FOLDER}/summary.log"
  mkdir -p "$SHARED_CORPUS" "$FUZZ_TEST_CORPUS" "$LOG_FOLDER"

  # Step 1 merge any new files from GitHub into the shared corpus
  time ${FUZZ_TEST} -merge=1 "$SHARED_CORPUS" "$SRC_CORPUS"

  # Step 2 run each fuzz test for the determined time
  # This will use the existing shared corpus and write new files to the run corpus
  # https://llvm.org/docs/LibFuzzer.html#options
  time ${FUZZ_TEST} -timeout=5 -print_final_stats=1 -jobs="$NUM_CPU_THREADS" -workers="$NUM_CPU_THREADS" \
    -max_total_time="$TIME_FOR_EACH_FUZZ" "$FUZZ_TEST_CORPUS" "$SHARED_CORPUS" 2>&1 | tee "$SUMMARY_LOG"

  NEW_FUZZ_FILES=$(find "$FUZZ_TEST_CORPUS" -type f | wc -l)

  # The libfuzzer logs are written to the current working directory and need to be moved after the test is done
  mv ./*.log  "${LOG_FOLDER}/."

  # Step 3 merge any new coverage from the run corpus into the shared corpus
  time ${FUZZ_TEST} -merge=1 "$SHARED_CORPUS" "$FUZZ_TEST_CORPUS"

  FINAL_SHARED_CORPUS_FILE_COUNT=$(find "$SHARED_CORPUS" -type f | wc -l)

  TEST_COUNT=$(grep -o "stat::number_of_executed_units: [0-9]*" "$SUMMARY_LOG" | awk '{test_count += $2} END {print test_count}')
  TESTS_PER_SECOND=$((TEST_COUNT/TOTAL_FUZZ_TEST_TIME))

  FEATURE_COVERAGE=$(grep -o "ft: [0-9]*" "$SUMMARY_LOG" | awk '{print $2}' | sort | tail -1)
  BLOCK_COVERAGE=$(grep -o "cov: [0-9]*" "$SUMMARY_LOG" | awk '{print $2}' | sort | tail -1)


  echo "${FUZZ_NAME} starting shared ${ORIGINAL_SHARED_CORPUS_FILE_COUNT} final shared ${FINAL_SHARED_CORPUS_FILE_COUNT} new files ${NEW_FUZZ_FILES} total test count ${TEST_COUNT} test rate ${TESTS_PER_SECOND} code coverage ${BLOCK_COVERAGE} feature coverage ${FEATURE_COVERAGE}"

done