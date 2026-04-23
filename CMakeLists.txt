cmake_minimum_required(VERSION 3.20)

if(NOT DEFINED CMAKE_C_COMPILER AND "$ENV{CC}" STREQUAL "")
    find_program(LIBP2P_DEFAULT_CLANG clang)
    if(LIBP2P_DEFAULT_CLANG)
        set(CMAKE_C_COMPILER "${LIBP2P_DEFAULT_CLANG}" CACHE FILEPATH "Default C compiler")
    endif()
endif()

project(c_lean_libp2p LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(BUILD_TESTING "Build c-lean-libp2p tests" ON)

enable_testing()

get_filename_component(LIBP2P_REPO_ROOT "${PROJECT_SOURCE_DIR}/.." ABSOLUTE)

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
target_link_libraries(c_lean_libp2p PUBLIC c_lean_libp2p_project_defaults secp256k1)
target_include_directories(c_lean_libp2p PRIVATE "${PROJECT_SOURCE_DIR}/external/secp256k1/src")

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

    foreach(module_name IN LISTS LIBP2P_MULTIFORMATS_MODULES)
        c_lean_libp2p_add_multiformats_test(unit "${module_name}")
        c_lean_libp2p_add_multiformats_test(spec "${module_name}")
    endforeach()

    c_lean_libp2p_add_peer_id_test(unit)
    c_lean_libp2p_add_peer_id_test(spec)
endif()
