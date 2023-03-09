/*
 * Copyright (c) 2015 University of Campinas (Unicamp)
 *
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
 * Author: Luciano Jerez Chaves <ljerezchaves@gmail.com>
 */

/**
 * \defgroup ofswitch13 OpenFlow 1.3 software switch
 *
 * This section documents the API of the ns-3 OpenFlow 1.3 compatible switch
 * and controller interface. It follows the OpenFlow 1.3 switch specification
 * <https://www.opennetworking.org/sdn-resources/technical-library>.
 * It depends on the CPqD bofuss software switch available at
 * <https://github.com/ljerezchaves/ofsoftswitch13>, compiled as a library.
 * Check the manual for tutorials on how to compile and use this module.
 */
#ifndef OFSWITCH13_INTERFACE_H
#define OFSWITCH13_INTERFACE_H

#include <ns3/csma-module.h>
#include <ns3/log.h>
#include <ns3/packet.h>
#include <ns3/simulator.h>
#include <ns3/socket.h>

extern "C"
{
#include <bofuss/action_set.h>
#include <bofuss/datapath.h>
#include <bofuss/dp_actions.h>
#include <bofuss/dp_buffers.h>
#include <bofuss/dp_control.h>
#include <bofuss/dp_ports.h>
#include <bofuss/dpctl.h>
#include <bofuss/flow_entry.h>
#include <bofuss/flow_table.h>
#include <bofuss/group_entry.h>
#include <bofuss/group_table.h>
#include <bofuss/match_std.h>
#include <bofuss/meter_entry.h>
#include <bofuss/meter_table.h>
#include <bofuss/ofl-actions.h>
#include <bofuss/ofl-err.h>
#include <bofuss/ofl-messages.h>
#include <bofuss/ofl-print.h>
#include <bofuss/ofl-structs.h>
#include <bofuss/ofpbuf.h>
#include <bofuss/openflow.h>
#include <bofuss/oxm-match.h>
#include <bofuss/packet_handle_std.h>
#include <bofuss/packet.h>
#include <bofuss/pipeline.h>
#include <bofuss/timeval.h>
#include <bofuss/vlog.h>
}

namespace ns3
{

/**
 * TracedCallback signature for sending packets from CsmaNetDevice to OpenFlow
 * pipeline.
 * \attention The packet can be modified by the OpenFlow pipeline.
 * \param netdev The underlying CsmaNetDevice switch port.
 * \param packet The packet.
 */
typedef void (*OpenFlowCallback)(Ptr<Packet> packet);

/**
 * \ingroup ofswitch13
 * Enable the logging system of the bofuss library.
 * By default, it will configure de logging system for maximum verbose dump on
 * console. You can set the \p printToFile parameter to dump messages to file
 * instead.
 * \param printToFile Dump log messages to file instead of console.
 * \param prefix Filename prefix to use for log files.
 * \param explicitFilename Treat the prefix as an explicit filename if true.
 * \param customLevels Custom vlog levels mod1[:facility[:level]] mod2[...
 */
void EnableLibraryLog(bool printToFile = false,
                      std::string prefix = "",
                      bool explicitFilename = false,
                      std::string customLevels = "");

/**
 * \ingroup ofswitch13
 * Create an internal bofuss buffer from ns3::Packet. Takes a
 * Ptr<Packet> and generates a buffer (struct ofpbuf*) from it, loading the
 * packet data as well as its headers into the buffer.
 * \param packet The ns-3 packet.
 * \param bodyRoom The size to allocate for data.
 * \param headRoom The size to allocate for headers (left unitialized).
 * \return The OpenFlow Buffer created from the packet.
 */
struct ofpbuf* BufferFromPacket(Ptr<const Packet> packet,
                                size_t bodyRoom,
                                size_t headRoom = 0);

/**
 * \ingroup ofswitch13
 * Create a new ns3::Packet from internal OFLib message. Takes a ofl_msg_*
 * structure, pack the message using wire format and generates a Ptr<Packet>
 * from it.
 * \param msg The OFLib message structure.
 * \param xid The transaction id to use.
 * \return The ns3::Packet created.
 */
Ptr<Packet> PacketFromMsg(struct ofl_msg_header* msg, uint32_t xid = 0);

/**
 * \ingroup ofswitch13
 * Create a new ns3::Packet from internal bofuss buffer. Takes a buffer
 * (struct ofpbuf*) and generates a Ptr<Packet> from it, load the data as well
 * as its headers into the packet.
 * \param buffer The internal buffer.
 * \return The ns3::Packet created.
 */
Ptr<Packet> PacketFromBuffer(struct ofpbuf* buffer);

} // namespace ns3
#endif /* OFSWITCH13_INTERFACE_H */
