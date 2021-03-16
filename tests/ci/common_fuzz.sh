# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

source tests/ci/common_posix_setup.sh

if [ -z ${CODEBUILD_CORPUS_REPOSITORY+x} ]; then
  CORPUS_ROOT="${CODEBUILD_CORPUS_REPOSITORY}/fuzzing"
else
  CORPUS_ROOT="${BUILD_ROOT}/temp_corpus"
fi
echo "$CORPUS_ROOT"

if [ -z ${CODEBUILD_BUILD_ID+x} ]; then
  BUILD_ID=$CODEBUILD_BUILD_ID
else
  # Generate a random string in bash https://unix.stackexchange.com/questions/230673/how-to-generate-a-random-string
  BUILD_ID=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13 ; echo '')
fi
echo "$BUILD_ID"
