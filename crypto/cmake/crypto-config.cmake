if(WIN32 OR UNIX)
    find_package(Threads REQUIRED)
endif()

# Allow static or shared lib to be used.
# If both are installed, choose based on BUILD_SHARED_LIBS.
if (BUILD_SHARED_LIBS)
    if (EXISTS "${CMAKE_CURRENT_LIST_DIR}/shared/crypto-targets.cmake")
        include(${CMAKE_CURRENT_LIST_DIR}/shared/crypto-targets.cmake)
        message(STATUS "FOUND AWS-LC CRYPTO cmake config - shared")
    else()
        include(${CMAKE_CURRENT_LIST_DIR}/static/crypto-targets.cmake)
        message(STATUS "FOUND AWS-LC CRYPTO cmake config - static")
    endif()
else()
    if (EXISTS "${CMAKE_CURRENT_LIST_DIR}/static/crypto-targets.cmake")
        include(${CMAKE_CURRENT_LIST_DIR}/static/crypto-targets.cmake)
        message(STATUS "FOUND AWS-LC CRYPTO cmake config - static")
    else()
        include(${CMAKE_CURRENT_LIST_DIR}/shared/crypto-targets.cmake)
        message(STATUS "FOUND AWS-LC CRYPTO cmake config - shared")
    endif()
endif()
