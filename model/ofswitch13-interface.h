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

/** 
 * \defgroup ofswitch13 OpenFlow 1.3 softswitch
 * \brief An OpenFlow 1.3 compatible switch datapath implementation
 * 
 * This module follows the OpenFlow 1.3 switch specification
 * <https://www.opennetworking.org/images/stories/downloads/specification/openflow-spec-v1.3.0.pdf>.
 * It depends on the CPqD ofsoftswitch13
 * <https://github.com/ljerezchaves/ofsoftswitch13> implementation compiled
 * as a library (use ./configure --enable-ns3-lib).
 *
 * \atention Currently, only a subset of features are supported.
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

/**
 * \brief Create and OpenFlow ofpbuf from ns3::Packet
 * 
 * Takes a Ptr<Packet> and generates an OpenFlow buffer (ofpbuf*) from it,
 * loading the packet data as well as its headers into the buffer.
 * 
 * \see ofsoftswitch13 function netdev_recv () at lib/netdev.c
 *
 * \param packet The packet.
 * \param bodyRoom The size to allocate for data.
 * \param headRoom The size to allocate for headers (left unitialized).
 * \return The OpenFlow Buffer created from the packet.
 */
ofpbuf* BufferFromPacket (Ptr<const Packet> packet, size_t bodyRoom, 
    size_t headRoom = 0);

/**
 * \brief Creates an OpenFlow internal packet from openflow buffer
 *
 * This packet in an internal ofsoftswitch13 structure to represent the
 * packet, and it is used to parse fields, lookup for flow matchs, etc.
 *
 * \see ofsoftswitch13 function packet_create () at udatapath/packet.c
 *
 * \param in_port The id of the input port.
 * \param buf The openflow buffer with the packet
 * \param packet_out True if the packet arrived in a packet out msg
 * \return The pointer to the created packet
 */
struct packet* InternalPacketFromBuffer (uint32_t in_port, struct ofpbuf *buf,
    bool packet_out);

/**
 * \brief Create and OpenFlow ofpbuf from internal ofl_msg_*
 * 
 * Takes a ofl_msg_* structure and generates an OpenFlow buffer (ofpbuf*) from
 * it, load the message data into the buffer.
 * 
 * \param msg The ofl_msg_* structure
 * \param xid The transaction id to use.
 * \return The OpenFlow Buffer created from the message
 */
ofpbuf* PackFromMsg (ofl_msg_header *msg, uint32_t xid);

/**
 * \brief Create an ns3::Packet from OpenFlow buffer
 * 
 * Takes an OpenFlow buffer (ofpbuf*) and generates a Ptr<Packet> from it,
 * load the data as well as its headers into the packet and free the buffer
 * memory.
 * 
 * \param buffer The ofpbuf buffer
 * \return The ns3::Packet created.
 */
Ptr<Packet> PacketFromBufferAndFree (ofpbuf* buffer);

/**
 * \brief Create an ns3::Packet from internal OpenFlow packet 
 * 
 * Takes an internal OpenFlow packet (struct packet*) and generates a Ptr<Packet> from it,
 * load the data as well as its headers into the packet.
 * 
 * \param pkt The internal openflow packet
 * \return The ns3::Packet created.
 */
Ptr<Packet> PacketFromInternalPacket (struct packet *pkt);


} // namespace ofs
} // namespace ns3
#endif /* OFSWITCH13_INTERFACE_H */
