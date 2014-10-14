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
 * This section documents the API of ns3 OpenFlow 1.3 compatible switch
 * and controller implementation. This module follows the
 * OpenFlow 1.3 switch specification
 * <https://www.opennetworking.org/images/stories/downloads/specification/openflow-spec-v1.3.0.pdf>.
 * It depends on the CPqD ofsoftswitch13 <https://github.com/ljerezchaves/ofsoftswitch13>
 * implementation compiled as a library (use ./configure --enable-ns3-lib).
 *
 * \attention Currently, not all OpenFlow 1.3 features are supported.
 */
#ifndef OFSWITCH13_INTERFACE_H
#define OFSWITCH13_INTERFACE_H

#include <assert.h>

#include "ns3/simulator.h"
#include "ns3/log.h"
#include "ns3/packet.h"
#include "ns3/csma-module.h"

#include <boost/static_assert.hpp>
#include "openflow/openflow.h"

extern "C"
{
// Workaround, as ofsoftswitch13 uses these two reserved words as member names
#define private _private
#define delete _delete
#define list List

#include "udatapath/packet.h"
#include "udatapath/pipeline.h"
#include "udatapath/flow_table.h"
#include "udatapath/group_table.h"
#include "udatapath/meter_table.h"
#include "udatapath/dp_ports.h"
#include "udatapath/dp_control.h"

 #include "lib/ofpbuf.h"

#include "oflib/ofl-structs.h"
#include "oflib/oxm-match.h"

#include "utilities/dpctl.h"

// From udatapath/datapath.c
struct remote* remote_create (struct datapath *dp, struct rconn *rconn,
                              struct rconn *rconn_aux);

// From udatapath/dp_ports.c
uint32_t port_speed (uint32_t conf);

#undef list
#undef private
#undef delete
}

namespace ns3 {
namespace ofs {

class OFSwitch13NetDevice;
class OFSwitch13Controller;

/**
 * \ingroup ofswitch13
 * Create and OpenFlow ofpbuf from ns3::Packet.  Takes a Ptr<Packet> and
 * generates an OpenFlow buffer (ofpbuf*) from it, loading the packet data as
 * well as its headers into the buffer.
 * \see ofsoftswitch13 function netdev_recv () at lib/netdev.c
 * \param packet The packet.
 * \param bodyRoom The size to allocate for data.
 * \param headRoom The size to allocate for headers (left unitialized).
 * \return The OpenFlow Buffer created from the packet.
 */
ofpbuf* BufferFromPacket (Ptr<const Packet> packet, size_t bodyRoom,
                          size_t headRoom = 0);

/**
 * \ingroup ofswitch13
 * Create and OpenFlow ofpbuf from internal ofl_msg_*. Takes a ofl_msg_*
 * structure and generates an OpenFlow buffer (ofpbuf*) from it, packing
 * message data into the buffer using wire format.
 * \param msg The ofl_msg_* structure.
 * \param xid The transaction id to use.
 * \param exp Experiment handler.
 * \return The OpenFlow Buffer created from the message.
 */
ofpbuf* BufferFromMsg (ofl_msg_header *msg, uint32_t xid, ofl_exp *exp = NULL);

/**
 * \ingroup ofswitch13
 * Create an ns3::Packet from internal ofl_msg_*.  Takes a ofl_msg_* structure
 * and generates an Ptr<Packet> from it, packing message data into the packet
 * using wire format.
 * \param msg The ofl_msg_* structure.
 * \param xid The transaction id to use.
 * \return The ns3::Packet created.
 */
Ptr<Packet> PacketFromMsg (ofl_msg_header *msg, uint32_t xid = 0);

/**
 * \ingroup ofswitch13
 * Create an ns3::Packet from OpenFlow buffer.  Takes an OpenFlow buffer
 * (ofpbuf*) and generates a Ptr<Packet> from it, load the data as well as its
 * headers into the packet and free the buffer memory.
 * \param buffer The ofpbuf buffer.
 * \return The ns3::Packet created.
 */
Ptr<Packet> PacketFromBufferAndFree (ofpbuf* buffer);

/**
 * \ingroup ofswitch13
 * Create an ns3::Packet from OpenFlow buffer. Takes an OpenFlow buffer
 * (ofpbuf*) and generates a Ptr<Packet> from it, load the data as well as its
 * headers into the packet.
 * \param buffer The ofpbuf buffer.
 * \return The ns3::Packet created.
 */
Ptr<Packet> PacketFromBuffer (ofpbuf* buffer);

/**
 * \ingroup ofswitch13
 * Create an ns3::Packet from internal OpenFlow packet.  Takes an internal
 * OpenFlow packet (struct packet*) and generates a Ptr<Packet> from it, load
 * the data as well as its headers into the packet.
 * \param pkt The internal openflow packet.
 * \return The ns3::Packet created.
 */
Ptr<Packet> PacketFromInternalPacket (packet *pkt);

} // namespace ofs
} // namespace ns3
#endif /* OFSWITCH13_INTERFACE_H */
