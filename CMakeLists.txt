set(NS3_OFSWITCH13
    "OFF"
    CACHE INTERNAL
    "ON if OFSwitch13 is found."
)

# Check for BOOST dependency
check_include_files(
  "boost/static_assert.hpp"
  BOOST_STATIC_ASSERT_FOUND
  LANGUAGE
  CXX
)

if(NOT BOOST_STATIC_ASSERT_FOUND)
  message(${HIGHLIGHTED_STATUS} "BOOST static assert was not found.")
  message(${HIGHLIGHTED_STATUS} "Skipping OFSwitch13")
  return()
endif()

# Check for BOFUSS dependency

# List of BOFUSS headers files required by OFSwitch13
set(NS3_OFSWITCH13_BOFUSS_HEADERS
  bofuss/action_set.h
  bofuss/datapath.h
  bofuss/dp_actions.h
  bofuss/dp_buffers.h
  bofuss/dp_control.h
  bofuss/dp_ports.h
  bofuss/dpctl.h
  bofuss/flow_entry.h
  bofuss/flow_table.h
  bofuss/group_entry.h
  bofuss/group_table.h
  bofuss/match_std.h
  bofuss/meter_entry.h
  bofuss/meter_table.h
  bofuss/ofl-actions.h
  bofuss/ofl-err.h
  bofuss/ofl-messages.h
  bofuss/ofl-print.h
  bofuss/ofl-structs.h
  bofuss/ofpbuf.h
  bofuss/openflow.h
  bofuss/oxm-match.h
  bofuss/packet_handle_std.h
  bofuss/packet.h
  bofuss/pipeline.h
  bofuss/timeval.h
  bofuss/vlog.h
)

set(NS3_OFSWITCH13_BOFUSS_PATH
    ""
    CACHE PATH
    "The BOFUSS library path"
)
message(STATUS "Looking for BOFUSS library in ${NS3_OFSWITCH13_BOFUSS_PATH}")

find_external_library(
  DEPENDENCY_NAME bofuss
  LIBRARY_NAME bofuss
  HEADER_NAMES ${NS3_OFSWITCH13_BOFUSS_HEADERS}
  SEARCH_PATHS ${NS3_OFSWITCH13_BOFUSS_PATH}
)

if(NOT bofuss_FOUND AND NOT ${bofuss_FOUND})
  message(${HIGHLIGHTED_STATUS} "BOFUSS library was not found.")
  message(${HIGHLIGHTED_STATUS} "The build system will try to download and compile it!")

  include(ExternalProject)
  ExternalProject_Add(
    bofuss_dep
    GIT_REPOSITORY https://github.com/ljerezchaves/ofsoftswitch13.git
    GIT_TAG 1b6106e3e3814c50b323e43b6bb2dec5ab13ffe7
    PREFIX bofuss_dep
    BUILD_IN_SOURCE TRUE
    UPDATE_DISCONNECTED TRUE
    CONFIGURE_COMMAND ./configure --prefix ${CMAKE_OUTPUT_DIRECTORY}
    BUILD_COMMAND make -j${NumThreads}
    INSTALL_COMMAND make install
    LOG_DOWNLOAD true
    LOG_UPDATE true
    LOG_CONFIGURE true
    LOG_BUILD true
    LOG_INSTALL true
    LOG_OUTPUT_ON_FAILURE true
  )

  set(bofuss_LIBRARIES bofuss)
endif()

# Enabling OFSwitch13 compilation
set(NS3_OFSWITCH13
    "ON"
    CACHE INTERNAL
    "ON if OFSwitch13 is found."
)

include_directories(${bofuss_INCLUDE_DIRS})
add_definitions(-DNS3_OFSWITCH13)

# OFSwitch13 source files
set(source_files
  model/ofswitch13-controller.cc
  model/ofswitch13-device.cc
  model/ofswitch13-interface.cc
  model/ofswitch13-learning-controller.cc
  model/ofswitch13-queue.cc
  model/ofswitch13-priority-queue.cc
  model/ofswitch13-port.cc
  model/ofswitch13-socket-handler.cc
  model/queue-tag.cc
  model/tunnel-id-tag.cc
  helper/ofswitch13-device-container.cc
  helper/ofswitch13-external-helper.cc
  helper/ofswitch13-helper.cc
  helper/ofswitch13-internal-helper.cc
  helper/ofswitch13-stats-calculator.cc
)

# OFSwitch13 header files
set(header_files
  model/ofswitch13-controller.h
  model/ofswitch13-device.h
  model/ofswitch13-interface.h
  model/ofswitch13-learning-controller.h
  model/ofswitch13-queue.h
  model/ofswitch13-priority-queue.h
  model/ofswitch13-port.h
  model/ofswitch13-socket-handler.h
  model/queue-tag.h
  model/tunnel-id-tag.h
  helper/ofswitch13-device-container.h
  helper/ofswitch13-external-helper.h
  helper/ofswitch13-helper.h
  helper/ofswitch13-internal-helper.h
  helper/ofswitch13-stats-calculator.h
)

# OFSwitch13 test files
set(test_sources
)

# Libraries to link to the OFSwitch13 module
set(libraries_to_link
  ${libcore}
  ${libnetwork}
  ${libinternet}
  ${libcsma}
  ${libpoint-to-point}
  ${libvirtual-net-device}
  ${bofuss_LIBRARIES}
)

# Build the OFSwitch13 module
build_lib(
  LIBNAME ofswitch13
  SOURCE_FILES ${source_files}
  HEADER_FILES ${header_files}
  LIBRARIES_TO_LINK ${libraries_to_link}
  TEST_SOURCES ${test_sources}
)

# Add BOFUSS dependency to OFSwitch13 module
if(NOT bofuss_FOUND AND NOT ${bofuss_FOUND})
  add_dependencies(${libofswitch13} bofuss_dep)
  if(NOT ${XCODE})
    add_dependencies(${libofswitch13}-obj bofuss_dep)
  endif()
endif()
