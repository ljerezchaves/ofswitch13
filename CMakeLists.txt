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
set(NS3_OFSWITCH13_BOFUSS_PATH
    ./lib/ofsoftswitch13/
    CACHE PATH
    "The BOFUSS library path"
)
message(STATUS "Looking for BOFUSS library in ${NS3_OFSWITCH13_BOFUSS_PATH}")

# List of BOFUSS headers files required by OFSwtich13
set(NS3_OFSWITCH13_BOFUSS_HEADERS
  include/openflow/openflow.h
  udatapath/action_set.h
  udatapath/datapath.h
  udatapath/dp_actions.h
  udatapath/dp_buffers.h
  udatapath/dp_control.h
  udatapath/dp_ports.h
  udatapath/flow_table.h
  udatapath/flow_entry.h
  udatapath/group_table.h
  udatapath/group_entry.h
  udatapath/match_std.h
  udatapath/meter_table.h
  udatapath/meter_entry.h
  udatapath/packet.h
  udatapath/packet_handle_std.h
  udatapath/pipeline.h
  oflib/ofl-actions.h
  oflib/ofl-messages.h
  oflib/ofl-print.h
  oflib/ofl-structs.h
  oflib/oxm-match.h
  lib/ofpbuf.h
  lib/timeval.h
  lib/vlog.h
  utilities/dpctl.h
)

find_external_library(
  DEPENDENCY_NAME BOFUSS
  HEADER_NAMES ${NS3_OFSWITCH13_BOFUSS_HEADERS}
  LIBRARY_NAME udatapath/libns3ofswitch13.a
  SEARCH_PATHS ${NS3_OFSWITCH13_BOFUSS_PATH}
)

if(NOT BOFUSS_FOUND AND NOT ${BOFUSS_FOUND})
  message(${HIGHLIGHTED_STATUS} "BOFUSS library was not found.")
  message(${HIGHLIGHTED_STATUS} "Skipping OFSwitch13")
  return()
endif()

# Enabling OFSwitch13 compilation
set(NS3_OFSWITCH13
    "ON"
    CACHE INTERNAL
    "ON if OFSwitch13 is found."
)

include_directories(${BOFUSS_INCLUDE_DIRS})
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

# Library to link the OFSwitch13 module
set(libraries_to_link
  ${libcsma}
  ${libinternet}
  ${libapplications}
  ${libpoint-to-point}
  ${libvirtual-net-device}
  ${BOFUSS_LIBRARIES}
)

# Don't export BOFUSS library
set(NS3_OFSWITCH13_REEXPORT ${NS3_REEXPORT_THIRD_PARTY_LIBRARIES})
if(${NS3_REEXPORT_THIRD_PARTY_LIBRARIES})
  message(STATUS "Using -DNS3_REEXPORT_THIRD_PARTY_LIBRARIES=OFF with OFSwitch13")
  set(NS3_REEXPORT_THIRD_PARTY_LIBRARIES OFF)
endif()

# Build the OFSwitch13 module
build_lib(
  LIBNAME ofswitch13
  SOURCE_FILES ${source_files}
  HEADER_FILES ${header_files}
  LIBRARIES_TO_LINK ${libraries_to_link}
  TEST_SOURCES ${test_sources}
)

set (NS3_REEXPORT_THIRD_PARTY_LIBRARIES ${NS3_OFSWITCH13_REEXPORT})
