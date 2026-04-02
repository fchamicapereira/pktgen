cmake_minimum_required(VERSION 3.5)
project(pktgen)

###############################################################################
# Configuring C++ standard version
###############################################################################

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

###############################################################################
# Configuring C standard version
###############################################################################

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_C_EXTENSIONS True)

###############################################################################
# Setting some complation flags
###############################################################################

add_compile_options(-m64 -O3 -march=native -g -Wall -Wextra -Werror -Wno-parentheses -Wfatal-errors)

###############################################################################
# Setting output targets
###############################################################################

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

###############################################################################
# Getting the modules
###############################################################################

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

################################################################################
# Add our CMake module directory to the list of module search directories
################################################################################

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

###############################################################################
# External libraries
###############################################################################

include(${CMAKE_SOURCE_DIR}/cmake/find_dpdk.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/find_pcap.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/find_zstd.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/find_cli11.cmake)

###############################################################################
# Getting the source files
###############################################################################

file(GLOB SOURCES ${PROJECT_SOURCE_DIR}/src/*.c ${PROJECT_SOURCE_DIR}/src/*.cpp)

###############################################################################
# Building the pktgen executable
###############################################################################

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME} 
    ${DPDK_LIBRARIES} 
    ${PCAP_LIBRARIES} 
    ZSTD::ZSTD
    CLI11::CLI11

    # https://stackoverflow.com/questions/56381463/executable-missing-full-library-path-after-build
    # cmake black magic...
    "-Wl,--disable-new-dtags"
)

target_include_directories(${PROJECT_NAME} SYSTEM PUBLIC 
    ${DPDK_INCLUDE_DIR}
    ${PCAP_INCLUDE_DIR}
    ${ZSTD_INCLUDE_DIRS}
)
