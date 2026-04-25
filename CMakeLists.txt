cmake_minimum_required(VERSION 3.20)

if(NOT DEFINED CMAKE_C_COMPILER AND "$ENV{CC}" STREQUAL "")
    find_program(LIBP2P_DEFAULT_CLANG clang)
    if(LIBP2P_DEFAULT_CLANG)
        set(CMAKE_C_COMPILER "${LIBP2P_DEFAULT_CLANG}" CACHE FILEPATH "Default C compiler")
    endif()
endif()

if(NOT DEFINED CMAKE_CXX_COMPILER AND "$ENV{CXX}" STREQUAL "")
    set(LIBP2P_SELECTED_C_COMPILER "${CMAKE_C_COMPILER}")
    if((LIBP2P_SELECTED_C_COMPILER STREQUAL "") AND (NOT "$ENV{CC}" STREQUAL ""))
        set(LIBP2P_SELECTED_C_COMPILER "$ENV{CC}")
    endif()
    if(LIBP2P_SELECTED_C_COMPILER MATCHES "(^|[/\\\\])clang(-[0-9.]+)?$")
        find_program(LIBP2P_DEFAULT_CLANGXX clang++)
        if(LIBP2P_DEFAULT_CLANGXX)
            set(CMAKE_CXX_COMPILER "${LIBP2P_DEFAULT_CLANGXX}" CACHE FILEPATH "Default C++ compiler")
        endif()
    endif()
endif()

project(c_lean_libp2p LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(BUILD_TESTING "Build c-lean-libp2p tests" ON)

enable_testing()

get_filename_component(LIBP2P_REPO_ROOT "${PROJECT_SOURCE_DIR}/.." ABSOLUTE)

macro(c_lean_libp2p_mirror_c_flag_to_cxx flag)
    string(FIND " ${CMAKE_C_FLAGS} " " ${flag} " _libp2p_c_flag_pos)
    string(FIND " ${CMAKE_CXX_FLAGS} " " ${flag} " _libp2p_cxx_flag_pos)
    if((NOT _libp2p_c_flag_pos EQUAL -1) AND (_libp2p_cxx_flag_pos EQUAL -1))
        string(APPEND CMAKE_CXX_FLAGS " ${flag}")
    endif()
endmacro()

foreach(_libp2p_abi_c_flag IN ITEMS
    -m32
    --coverage
    -fno-omit-frame-pointer
    -fsanitize=address
    -fsanitize=undefined
    -fsanitize=address,undefined
    -fsanitize=memory
    -fsanitize-memory-track-origins
    -fsanitize=thread
)
    c_lean_libp2p_mirror_c_flag_to_cxx("${_libp2p_abi_c_flag}")
endforeach()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(THREADS_PREFER_PTHREAD_FLAG TRUE CACHE BOOL "Prefer -pthread for dependency probes" FORCE)
    set(THREADS_HAVE_PTHREAD_ARG TRUE CACHE BOOL "Linux toolchains support -pthread" FORCE)
endif()

set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(SECP256K1_INSTALL OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_CTIME_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_ECDH OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_RECOVERY OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_MUSIG OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_ELLSWIFT OFF CACHE BOOL "" FORCE)

add_subdirectory(external/secp256k1)

set(LIBP2P_BUILD_TESTING "${BUILD_TESTING}")
set(BUILD_TESTING OFF CACHE BOOL "Build third-party dependency tests" FORCE)
set(BUILD_LIBSSL ON CACHE BOOL "Build AWS-LC libssl" FORCE)
set(BUILD_TOOL OFF CACHE BOOL "Build AWS-LC command-line tool" FORCE)
set(DISABLE_GO ON CACHE BOOL "Do not require Go when building AWS-LC" FORCE)
set(DISABLE_PERL ON CACHE BOOL "Use generated AWS-LC assembly sources" FORCE)
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(OPENSSL_NO_ASM ON CACHE BOOL "Use AWS-LC portable code for 32-bit builds" FORCE)
endif()
add_subdirectory(external/aws-lc)

set(ENABLE_LIB_ONLY ON CACHE BOOL "Build only ngtcp2 libraries" FORCE)
set(ENABLE_STATIC_LIB ON CACHE BOOL "Build ngtcp2 static libraries" FORCE)
set(ENABLE_SHARED_LIB OFF CACHE BOOL "Do not build ngtcp2 shared libraries" FORCE)
set(ENABLE_OPENSSL OFF CACHE BOOL "Do not build ngtcp2 OpenSSL backend" FORCE)
set(ENABLE_BORINGSSL ON CACHE BOOL "Build ngtcp2 BoringSSL/AWS-LC backend" FORCE)
set(ENABLE_GNUTLS OFF CACHE BOOL "Do not build ngtcp2 GnuTLS backend" FORCE)
set(ENABLE_PICOTLS OFF CACHE BOOL "Do not build ngtcp2 picotls backend" FORCE)
set(ENABLE_WOLFSSL OFF CACHE BOOL "Do not build ngtcp2 wolfSSL backend" FORCE)
set(BORINGSSL_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/external/aws-lc/include" CACHE PATH "AWS-LC include directory" FORCE)
set(BORINGSSL_LIBRARIES ssl crypto CACHE STRING "AWS-LC libraries for ngtcp2" FORCE)
set(HAVE_AWSLC TRUE CACHE BOOL "AWS-LC is provided by the aws-lc submodule" FORCE)
add_subdirectory(external/ngtcp2)

set(BUILD_TESTING "${LIBP2P_BUILD_TESTING}" CACHE BOOL "Build c-lean-libp2p tests" FORCE)

if(MSVC)
    target_compile_options(secp256k1 PRIVATE /WX-)
    target_compile_options(secp256k1_precomputed PRIVATE /WX-)
endif()

add_library(c_lean_libp2p_project_defaults INTERFACE)
target_compile_features(c_lean_libp2p_project_defaults INTERFACE c_std_11)
target_compile_options(
    c_lean_libp2p_project_defaults
    INTERFACE
        $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU,Clang,AppleClang>>:-Wall>
        $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU,Clang,AppleClang>>:-Wextra>
        $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU,Clang,AppleClang>>:-Werror>
        $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU,Clang,AppleClang>>:-ffreestanding>
        $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:MSVC>>:/W4>
        $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:MSVC>>:/WX>
)
target_compile_definitions(
    c_lean_libp2p_project_defaults
    INTERFACE
        $<$<C_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>
)
target_include_directories(
    c_lean_libp2p_project_defaults
    INTERFACE
        "${PROJECT_SOURCE_DIR}/include"
)

function(c_lean_libp2p_set_output_directories target_name)
    set_target_properties(
        "${target_name}"
        PROPERTIES
            ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib"
            LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib"
            RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin"
    )
endfunction()

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------

file(
    GLOB_RECURSE
    LIBP2P_SOURCE_FILES
    CONFIGURE_DEPENDS
    LIST_DIRECTORIES FALSE
    "${PROJECT_SOURCE_DIR}/src/*.c"
)

list(SORT LIBP2P_SOURCE_FILES)

add_library(c_lean_libp2p STATIC ${LIBP2P_SOURCE_FILES})
target_link_libraries(
    c_lean_libp2p
    PUBLIC
        c_lean_libp2p_project_defaults
        secp256k1
        ngtcp2_static
        ngtcp2_crypto_boringssl_static
        ssl
        crypto
        $<$<PLATFORM_ID:Windows>:ws2_32>
)
target_include_directories(c_lean_libp2p PRIVATE "${PROJECT_SOURCE_DIR}/external/secp256k1/src")
target_include_directories(
    c_lean_libp2p
    SYSTEM
    PRIVATE
        "${PROJECT_SOURCE_DIR}/external/secp256k1/include"
        "${PROJECT_SOURCE_DIR}/external/ngtcp2/lib/includes"
        "${PROJECT_BINARY_DIR}/external/ngtcp2/lib/includes"
        "${PROJECT_SOURCE_DIR}/external/ngtcp2/crypto/includes"
        "${PROJECT_BINARY_DIR}/external/ngtcp2/crypto/includes"
        "${PROJECT_SOURCE_DIR}/external/aws-lc/include"
        "${PROJECT_BINARY_DIR}/external/aws-lc/symbol_prefix_include"
)

c_lean_libp2p_set_output_directories(c_lean_libp2p)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if(BUILD_TESTING)
    set(LIBP2P_MULTIFORMATS_MODULES
        unsigned_varint
        multicodec
        multibase
        multihash
        multiaddr
    )

    function(c_lean_libp2p_add_test test_name test_source)
        add_executable("${test_name}" "${test_source}")
        target_link_libraries(
            "${test_name}"
            PRIVATE
                c_lean_libp2p
                c_lean_libp2p_project_defaults
        )
        target_compile_options(
            "${test_name}"
            PRIVATE
                $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU,Clang,AppleClang>>:-UNDEBUG>
        )
        target_include_directories("${test_name}" PRIVATE "${PROJECT_SOURCE_DIR}/tests/support")

        c_lean_libp2p_set_output_directories("${test_name}")

        add_test(NAME "${test_name}" COMMAND $<TARGET_FILE:${test_name}>)
        set_tests_properties(
            "${test_name}"
            PROPERTIES
                WORKING_DIRECTORY "${LIBP2P_REPO_ROOT}"
        )
    endfunction()

    function(c_lean_libp2p_add_multiformats_test suite_name module_name)
        set(test_name "${suite_name}_${module_name}")
        set(
            test_source
            "${PROJECT_SOURCE_DIR}/tests/${suite_name}/multiformats/${module_name}/test_${module_name}.c"
        )

        c_lean_libp2p_add_test("${test_name}" "${test_source}")
    endfunction()

    function(c_lean_libp2p_add_peer_id_test suite_name)
        set(test_name "${suite_name}_peer_id")
        set(test_source "${PROJECT_SOURCE_DIR}/tests/${suite_name}/peer_id/test_peer_id.c")

        c_lean_libp2p_add_test("${test_name}" "${test_source}")
    endfunction()

    function(c_lean_libp2p_add_quic_test suite_name module_name)
        set(test_name "${suite_name}_quic_${module_name}")
        set(test_source "${PROJECT_SOURCE_DIR}/tests/${suite_name}/transport/quic/test_quic_${module_name}.c")

        c_lean_libp2p_add_test("${test_name}" "${test_source}")
    endfunction()

    foreach(module_name IN LISTS LIBP2P_MULTIFORMATS_MODULES)
        c_lean_libp2p_add_multiformats_test(unit "${module_name}")
        c_lean_libp2p_add_multiformats_test(spec "${module_name}")
    endforeach()

    c_lean_libp2p_add_peer_id_test(unit)
    c_lean_libp2p_add_peer_id_test(spec)

    c_lean_libp2p_add_quic_test(unit addr)
    c_lean_libp2p_add_quic_test(unit identity)
    c_lean_libp2p_add_quic_test(unit endpoint)
    c_lean_libp2p_add_quic_test(unit lifecycle)
    c_lean_libp2p_add_quic_test(unit service)
    c_lean_libp2p_add_quic_test(unit udp)
    c_lean_libp2p_add_quic_test(spec transport)
    c_lean_libp2p_add_quic_test(spec tls_vectors)
endif()
