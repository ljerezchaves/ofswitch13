/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Luciano Chaves <luciano@lrc.ic.unicamp.br>
 */

/** \defgroup ofswitch13 OpenFlow 1.3 soft switch (ofsoftswitch13)
 * 
 * This module is an OpenFlow 1.3 compatible switch datapath implementation
 * <https://www.opennetworking.org/images/stories/downloads/specification/openflow-spec-v1.3.0.pdf>.
 * The module depends on the CPqD ofsoftswitch13
 * <https://github.com/ljerezchaves/ofsoftswitch13> implementation compiled
 * as a library (use ./configure --enable-ns3-lib).
 */
#ifndef OFSWITCH13_INTERFACE_H
#define OFSWITCH13_INTERFACE_H

#include <assert.h>
#include <errno.h>

#include "ns3/simulator.h"
#include "ns3/log.h"
#include "ns3/net-device.h"
// #include "ns3/packet.h"
// #include "ns3/address.h"
// #include "ns3/nstime.h"
// #include "ns3/mac48-address.h"

#include <set>
#include <map>
#include <limits>

#include <boost/static_assert.hpp>
#include "openflow/openflow.h"

extern "C"
{
// Workaround, as ofsoftswitch13 uses these two reserved words as member names
#define private _private
#define delete _delete
#define list List

#include "utilities/dpctl.h"

#include "udatapath/packet.h"
#include "udatapath/pipeline.h"
#include "udatapath/flow_table.h"
#include "udatapath/flow_entry.h"
#include "udatapath/dp_ports.h"
#include "udatapath/dp_actions.h"
#include "udatapath/packet_handle_std.h"
#include "udatapath/dp_buffers.h"
// #include "udatapath/datapath.h"
// #include "udatapath/meter_table.h"
// #include "udatapath/action_set.h"

#include "lib/ofpbuf.h"
#include "lib/dynamic-string.h"
#include "lib/hash.h"
// #include "lib/ofp.h"
// #include "lib/vlog.h"
// #include "lib/csum.h"
// #include "lib/packets.h"
// #include "lib/daemon.h"
// #include "lib/poll-loop.h"

#include "oflib/ofl-structs.h"
#include "oflib/oxm-match.h"

// Some internal functions are not declared in header files...
// From flow_table.c
int flow_table_features (struct ofl_table_features *features);
void add_to_timeout_lists (struct flow_table *table, struct flow_entry *entry);

// From pipeline.c
int inst_compare (const void *inst1, const void *inst2);

// From dpctl.c
void parse_flow_mod_args (char *str, struct ofl_msg_flow_mod *req);
void parse_match (char *str, struct ofl_match_header **match);
void parse_inst (char *str, struct ofl_instruction_header **inst);
void make_all_match (struct ofl_match_header **match);

// From dp_actions.c
void output (struct packet *pkt, struct ofl_action_output *action);

#undef list
#undef private
#undef delete
}

namespace ns3 {
namespace ofs {

class OFSwitch13NetDevice;

/**
 * \brief Switch SwPort and its metadata.
 * \see ofsoftswitch13 udatapath/dp_ports.h
 */
struct Port
{
  /**
   * \brief Port constructor.
   * 
   * \see new_port () at udatapath/dp_ports.c
   * \attention Port numbers should start at 1.
   * 
   * \param dev Pointer to NetDevice (port) at the switch.
   * \param port_no Number for this port.
   */
  Port (Ptr<NetDevice> dev, uint32_t port_no);

  uint32_t flags;                 ///< SWP_* flags.
  Ptr<NetDevice> netdev;          ///< Pointer to ns3::NetDevice
  struct ofl_port *conf;          ///< Config information
  struct ofl_port_stats *stats;   ///< Statiscts
  uint32_t port_no;               ///< Port number
};

// /**
//  * \brief Packet Metadata, allows us to track the packet's metadata as it
//  * passes through the switch.
//  */
// struct SwitchPacketMetadata
// {
//   Ptr<Packet> packet;         ///< The original ns3 Packet
//   ofpbuf* buffer;             ///< The OpenFlow buffer created from the Packet
//   uint16_t protocolNumber;    ///< Protocol type of the Packet when the Packet is received
//   Address src;                ///< Source Address of the Packet when the Packet is received
//   Address dst;                ///< Destination Address of the Packet when the Packet is received
// };

} // namespace ofs
} // namespace ns3
#endif /* OFSWITCH13_INTERFACE_H */
