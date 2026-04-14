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

add_library(c_lean_libp2p_project_defaults INTERFACE)
target_compile_features(c_lean_libp2p_project_defaults INTERFACE c_std_11)
target_compile_options(
    c_lean_libp2p_project_defaults
    INTERFACE
        $<$<COMPILE_LANGUAGE:C>:-Wall>
        $<$<COMPILE_LANGUAGE:C>:-Wextra>
        $<$<COMPILE_LANGUAGE:C>:-Werror>
        $<$<COMPILE_LANGUAGE:C>:-ffreestanding>
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
target_link_libraries(c_lean_libp2p PUBLIC c_lean_libp2p_project_defaults)

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

    function(c_lean_libp2p_add_multiformats_test suite_name module_name)
        set(test_name "${suite_name}_${module_name}")
        set(
            test_source
            "${PROJECT_SOURCE_DIR}/tests/${suite_name}/multiformats/${module_name}/test_${module_name}.c"
        )

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

    foreach(module_name IN LISTS LIBP2P_MULTIFORMATS_MODULES)
        c_lean_libp2p_add_multiformats_test(unit "${module_name}")
        c_lean_libp2p_add_multiformats_test(spec "${module_name}")
    endforeach()
endif()
