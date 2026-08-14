# Merge the native-Rust FIPS module's object files into an existing static
# archive (libcrypto.a) so the archive is self-contained: it then holds the Rust
# SHA and integrity code directly, and downstream consumers no longer need to
# also link libfips_module.a.
#
# The combined object produced by fips_module/build.rs
# (combined_fips_objects.o) is inserted intact, so the FIPS integrity boundary
# (start | fips_core | end) is preserved.
#
# Invoked from a POST_BUILD step in crypto/CMakeLists.txt via `cmake -P`.
# Inputs (via -D):
#   LIBCRYPTO_ARCHIVE - path to the static archive to merge into
#   RUST_FIPS_LIB     - path to libfips_module.a
#   AR                - archiver executable
#   RANLIB            - ranlib executable (may be empty)

if(NOT EXISTS "${RUST_FIPS_LIB}")
  message(FATAL_ERROR "Rust FIPS archive not found: ${RUST_FIPS_LIB}")
endif()
if(NOT EXISTS "${LIBCRYPTO_ARCHIVE}")
  message(FATAL_ERROR "libcrypto archive not found: ${LIBCRYPTO_ARCHIVE}")
endif()

# Extract the Rust objects into a scratch directory beside the archive.
get_filename_component(_dir "${LIBCRYPTO_ARCHIVE}" DIRECTORY)
set(_scratch "${_dir}/rust_fips_objs")
file(REMOVE_RECURSE "${_scratch}")
file(MAKE_DIRECTORY "${_scratch}")

execute_process(
  COMMAND "${AR}" x "${RUST_FIPS_LIB}"
  WORKING_DIRECTORY "${_scratch}"
  RESULT_VARIABLE _rc)
if(NOT _rc EQUAL 0)
  message(FATAL_ERROR "Failed to extract ${RUST_FIPS_LIB} (ar x -> ${_rc})")
endif()

file(GLOB _objs "${_scratch}/*.o")
if(NOT _objs)
  message(FATAL_ERROR "No object files extracted from ${RUST_FIPS_LIB}")
endif()

# Insert with replacement so re-running is idempotent across rebuilds (same-named
# members are replaced rather than duplicated).
execute_process(
  COMMAND "${AR}" r "${LIBCRYPTO_ARCHIVE}" ${_objs}
  RESULT_VARIABLE _rc)
if(NOT _rc EQUAL 0)
  message(FATAL_ERROR "Failed to add Rust objects to ${LIBCRYPTO_ARCHIVE} (ar r -> ${_rc})")
endif()

if(RANLIB)
  execute_process(COMMAND "${RANLIB}" "${LIBCRYPTO_ARCHIVE}")
endif()

file(REMOVE_RECURSE "${_scratch}")
