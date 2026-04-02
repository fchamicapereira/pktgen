###############################################################################
# Find dpdk
###############################################################################

find_package(PkgConfig REQUIRED)

# This will automatically find only the libraries present on YOUR system
pkg_check_modules(DPDK REQUIRED libdpdk)

set(DPDK_LIBRARIES ${DPDK_LIBRARIES})
set(DPDK_INCLUDE_DIR ${DPDK_INCLUDE_DIRS})

if (DPDK_FOUND)
  message(DPDK_INCLUDE_DIRS="${DPDK_INCLUDE_DIRS}")
  message(DPDK_LIBRARY_DIRS="${DPDK_LIBRARY_DIRS}")

  link_directories(${DPDK_LIBRARY_DIRS})
else()
  message (FATAL_ERROR "DPDK not found.")
endif()
