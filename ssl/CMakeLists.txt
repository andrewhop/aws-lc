add_library(
  ssl

  bio_ssl.cc
  custom_extensions.cc
  d1_both.cc
  d1_lib.cc
  d1_pkt.cc
  d1_srtp.cc
  dtls_method.cc
  dtls_record.cc
  encrypted_client_hello.cc
  extensions.cc
  handoff.cc
  handshake.cc
  handshake_client.cc
  handshake_server.cc
  s3_both.cc
  s3_lib.cc
  s3_pkt.cc
  ssl_aead_ctx.cc
  ssl_asn1.cc
  ssl_buffer.cc
  ssl_cert.cc
  ssl_cipher.cc
  ssl_decrepit.c
  ssl_file.cc
  ssl_key_share.cc
  ssl_lib.cc
  ssl_privkey.cc
  ssl_session.cc
  ssl_stat.cc
  ssl_text.cc
  ssl_transcript.cc
  ssl_transfer_asn1.cc
  ssl_versions.cc
  ssl_x509.cc
  t1_enc.cc
  tls_method.cc
  tls_record.cc
  tls13_both.cc
  tls13_client.cc
  tls13_enc.cc
  tls13_server.cc
)
target_compile_definitions(ssl PRIVATE BORINGSSL_IMPLEMENTATION)

target_link_libraries(ssl crypto)

target_include_directories(ssl BEFORE PRIVATE ${AWSLC_BINARY_DIR}/symbol_prefix_include)

target_include_directories(ssl PUBLIC
  $<BUILD_INTERFACE:${AWSLC_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)

if(BUILD_TESTING)
  # ocsp_integration_test.cc does integration tests with the Amazon Trust
  # Services OCSP responder. This is ran as its own test executable because
  # internal sandbox builds cannot properly connect with the host.
  # Since the integration test relies on libssl functionalities to retrieve
  # the certification chain from a host, this integration test dimension is
  # built with libssl and libcrypto.
  add_executable(
    ${INTEGRATION_TEST_EXEC}

    ../crypto/ocsp/ocsp_integration_test.cc
    ../tool/transport_common.cc
    ../tool/fd.cc

    $<TARGET_OBJECTS:crypto_test_data>
  )
  target_link_libraries(${INTEGRATION_TEST_EXEC}
          boringssl_gtest_main ssl )
  target_include_directories(${INTEGRATION_TEST_EXEC} BEFORE PRIVATE ${AWSLC_BINARY_DIR}/symbol_prefix_include)
  add_dependencies(all_tests ${INTEGRATION_TEST_EXEC})
  set_test_location(${INTEGRATION_TEST_EXEC})

  add_executable(
    ${SSL_TEST_EXEC}

    ../crypto/test/file_util.cc
    span_test.cc
    ssl_test.cc
    ssl_client_hello_test.cc
    ssl_c_test.c
    ssl_key_share_test.cc
    ssl_alps_test.cc
    ssl_common_test.cc
    ssl_misc_test.cc
    ssl_version_test.cc
    ssl_ech_test.cc
    ssl_quic_test.cc
    ssl_hybrid_handshake_test.cc
    ssl_encoding_test.cc
    ssl_ciphers_test.cc
    ssl_handshake_test.cc
  )

  target_link_libraries(${SSL_TEST_EXEC} boringssl_gtest_main ssl)
  set_test_location(${SSL_TEST_EXEC})

  target_include_directories(${SSL_TEST_EXEC} BEFORE PRIVATE ${AWSLC_BINARY_DIR}/symbol_prefix_include)

  if(WIN32)
    target_link_libraries(${SSL_TEST_EXEC} ws2_32)
  endif()
  add_dependencies(all_tests ${SSL_TEST_EXEC})
  add_subdirectory(test)
endif()

install(TARGETS ssl
        EXPORT ssl-targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

if(MSVC AND CMAKE_BUILD_TYPE_LOWER MATCHES "relwithdebinfo" AND FIPS)
  install(FILES $<TARGET_FILE_DIR:ssl>/ssl.pdb DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

configure_file("cmake/ssl-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/ssl-config.cmake"
    @ONLY)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/ssl-config.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/ssl/cmake"
    COMPONENT Development)

if (BUILD_SHARED_LIBS)
   set (TARGET_DIR "shared")
else()
   set (TARGET_DIR "static")
endif()

install(EXPORT ssl-targets
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/ssl/cmake/${TARGET_DIR}"
    NAMESPACE AWS::
    COMPONENT Development)
