###############################################################################
# Find zstd
###############################################################################

find_package(ZSTD)

if (ZSTD_FOUND)
    message(STATUS "Found ZSTD")
    message(STATUS "ZSTD_INCLUDE_DIRS: ${ZSTD_INCLUDE_DIRS}")
    message(STATUS "ZSTD_LIBRARIES: ${ZSTD_LIBRARIES}")

    if(ZSTD_FOUND AND NOT (TARGET ZSTD::ZSTD))
        add_library (ZSTD::ZSTD INTERFACE IMPORTED)
        set_target_properties(ZSTD::ZSTD PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${ZSTD_INCLUDE_DIRS}"
            INTERFACE_LINK_LIBRARIES "${ZSTD_LIBRARIES}"
        )
    endif()
else()
    message (FATAL_ERROR "ZSTD not found.")
endif()
