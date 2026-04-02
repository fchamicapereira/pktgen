###############################################################################
# Find pcap
###############################################################################

find_package(PCAP)

if (PCAP_FOUND)
  message(STATUS "Found PCAP")
  message(STATUS "PCAP_INCLUDE_DIR: ${PCAP_INCLUDE_DIR}")
  message(STATUS "PCAP_LIBRARY: ${PCAP_LIBRARY}")
else()
  message (FATAL_ERROR "PCAP not found.")
endif()
