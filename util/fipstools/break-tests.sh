# Copyright (c) 2022, Google Inc.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# This script runs test_fips repeatedly with different FIPS tests broken. It is
# intended to be observed to demonstrate that the various tests are working and
# thus pauses for a keystroke between tests.
#
# Runs in either device mode (on an attached Android device) or in a locally built
# BoringSSL checkout.
#
# On Android static binaries are not built using FIPS mode, so in device mode each
# test makes changes to libcrypto.so rather than the test binary, test_fips.

set -e

die () {
  echo "ERROR: $@"
  exit 1
}

usage() {
  echo "USAGE: $0 [local|device]"
  exit 1
}

inferred_mode() {
  # Try and infer local or device mode based on makefiles and artifacts.
  if [ -f Android.bp -o -f external/boringssl/Android.bp ]; then
    echo device
  elif [ -f CMakeLists.txt -a -d build/crypto -a -d build/ssl ]; then
    echo local
  else
    echo "Unable to infer mode, please specify on the command line."
    usage
  fi
}

# Prefer mode from command line if present.
case "$1" in
  local|device)
    MODE=$1
    ;;

  "")
    MODE=`inferred_mode`
    ;;

  *)
    usage
    ;;
esac

check_directory() {
  test -d "$1" || die "Directory $1 not found."
}

check_file() {
  test -f "$1" || die "File $1 not found."
}

run_test_locally() {
  eval "$1" || true
}

run_test_on_device() {
  EXECFILE="$1"
  LIBRARY="$2"
  adb shell rm -rf "$DEVICE_TMP"
  adb shell mkdir -p "$DEVICE_TMP"
  adb push "$EXECFILE" "$DEVICE_TMP" > /dev/null
  EXECPATH=$(basename "$EXECFILE")
  adb push "$LIBRARY" "$DEVICE_TMP" > /dev/null
  adb shell "LD_LIBRARY_PATH=$DEVICE_TMP" "$DEVICE_TMP/$EXECPATH" || true
}

device_integrity_break_test() {
  go run "$BORINGSSL/util/fipstools/break-hash.go" "$LIBCRYPTO_BIN" ./libcrypto.so
  $RUN "$TEST_FIPS_BIN" ./libcrypto.so
  rm ./libcrypto.so
}

local_integrity_break_test() {
  go run $BORINGSSL/util/fipstools/break-hash.go "$TEST_FIPS_BIN" ./break-bin
  chmod u+x ./break-bin
  $RUN ./break-bin
  rm ./break-bin
}

local_runtime_break_test() {
  BORINGSSL_FIPS_BREAK_TEST=$1 "$RUN" "$TEST_FIPS_BREAK_BIN"
}

# TODO(prb): make break-hash and break-kat take similar arguments to save having
# separate functions for each.
device_kat_break_test() {
  KAT="$1"
  go run "$BORINGSSL/util/fipstools/break-kat.go" "$LIBCRYPTO_BREAK_BIN" "$KAT" > ./libcrypto.so
  $RUN "$TEST_FIPS_BIN" ./libcrypto.so
  rm ./libcrypto.so
}

local_kat_break_test() {
  KAT="$1"
  go run "$BORINGSSL/util/fipstools/break-kat.go" "$TEST_FIPS_BREAK_BIN" "$KAT" > ./break-bin
  chmod u+x ./break-bin
  $RUN ./break-bin
  rm ./break-bin
}

pause () {
  echo -n "Press <Enter> "
  read
}

if [ "$MODE" = "local" ]; then
  TEST_FIPS_BIN=${TEST_FIPS_BIN:-build/util/fipstools/test_fips}
  TEST_FIPS_BREAK_BIN=${TEST_FIPS_BREAK_BIN:-./test_fips_break}
  check_file "$TEST_FIPS_BIN"
  check_file "$TEST_FIPS_BREAK_BIN"

  BORINGSSL=.
  RUN=run_test_locally
  BREAK_TEST=local_break_test
  INTEGRITY_BREAK_TEST=local_integrity_break_test
  KAT_BREAK_TEST=local_kat_break_test
  RUNTIME_BREAK_TEST=local_runtime_break_test
  if [ ! -f "$TEST_FIPS_BIN" ]; then
    echo "$TEST_FIPS_BIN is missing. Run this script from the top level of a"
    echo "BoringSSL checkout and ensure that BoringSSL has been built in"
    echo "build/ with -DFIPS_BREAK_TEST=TESTS passed to CMake."
    exit 1
  fi
else # Device mode
  test "$ANDROID_BUILD_TOP" || die "'lunch aosp_arm64-eng' first"
  check_directory "$ANDROID_PRODUCT_OUT"

  TEST_FIPS_BIN="$ANDROID_PRODUCT_OUT/system/bin/test_fips"
  check_file "$TEST_FIPS_BIN"
  LIBCRYPTO_BIN="$ANDROID_PRODUCT_OUT/system/lib64/libcrypto.so"
  LIBCRYPTO_BREAK_BIN="libcrypto.so"
  check_file "$LIBCRYPTO_BIN"
  check_file "$LIBCRYPTO_BREAK_BIN"

  test "$ANDROID_SERIAL" || die "ANDROID_SERIAL not set"
  DEVICE_TMP=/data/local/tmp

  BORINGSSL="$ANDROID_BUILD_TOP/external/boringssl/src"
  RUN=run_test_on_device
  INTEGRITY_BREAK_TEST=device_integrity_break_test
  KAT_BREAK_TEST=device_kat_break_test
fi


KATS=$(go run "$BORINGSSL/util/fipstools/break-kat.go" --list-tests)

echo -e '\033[1mNormal output\033[0m'
$RUN "$TEST_FIPS_BIN" "$LIBCRYPTO_BIN"
pause

echo
echo -e '\033[1mIntegrity test failure\033[0m'
$INTEGRITY_BREAK_TEST
pause

for kat in $KATS; do
  echo
  echo -e "\033[1mKAT failure ${kat}\033[0m"
  $KAT_BREAK_TEST $kat
  pause
done

if [ "$MODE" = "local" ]; then
  # TODO(prb): add support for Android devices.
  for runtime_test in EC_PWCT RSA_PWCT; do
    echo
    echo -e "\033[1m${runtime_test} failure\033[0m"
    $RUNTIME_BREAK_TEST ${runtime_test}
    pause
  done
fi
