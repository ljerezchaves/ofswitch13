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
 * Author: Blake Hurd  <naimorai@gmail.com>
 *         Luciano Chaves <luciano@lrc.ic.unicamp.br>
 */

/** \defgroup ofswitch13 OpenFlow 1.3 soft switch (ofsoftswitch13)
 * 
 * This module is an OpenFlow 1.3 compatible switch implementation
 * <https://www.opennetworking.org/images/stories/downloads/specification/openflow-spec-v1.3.0.pdf>.
 * The module depends on the CPqD ofsoftswitch13
 * <https://github.com/ljerezchaves/ofsoftswitch13> implementation compiled as
 * a library. For a generic functional description, please refer to the ns-3
 * model library.
 */
#ifndef OFSWITCH13_INTERFACE_H
#define OFSWITCH13_INTERFACE_H

#include <assert.h>
#include <errno.h>

#include "ns3/simulator.h"
#include "ns3/log.h"
#include "ns3/net-device.h"
#include "ns3/packet.h"
#include "ns3/address.h"
#include "ns3/nstime.h"
#include "ns3/mac48-address.h"

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

#include "udatapath/packet.h"
#include "udatapath/pipeline.h"
#include "udatapath/datapath.h"
#include "udatapath/flow_entry.h"
#include "udatapath/dp_ports.h"
#include "udatapath/dp_buffers.h"
#include "udatapath/meter_table.h"
#include "udatapath/packet_handle_std.h"

#include "lib/ofpbuf.h"
#include "lib/fault.h"
#include "lib/vlog.h"
#include "lib/csum.h"
#include "lib/packets.h"
#include "lib/daemon.h"
#include "lib/poll-loop.h"

#include "oflib/ofl-structs.h"

// void execute_entry (struct pipeline *pl, struct flow_entry *entry, struct flow_table **next_table, struct packet **pkt);

#undef list
#undef private
#undef delete
}

namespace ns3 {

class OFSwitch13NetDevice;

namespace ofs {

/**
 * \brief Switch SwPort and its metadata.
 *
 * We need to store port metadata, as OpenFlow can use it to manage queues,
 * stats, etc. Otherwise, we'd refer to it via Ptr<NetDevice> everywhere.
 *
 * \attention Port numbers should start at 1
 *
 * \see ofsoftswitch13 udatapath/dp_ports.h
 */
struct Port
{
  Port (struct datapath *dp_, Ptr<NetDevice> netdev_, uint32_t port_no_);
  ~Port ();

  uint32_t flags;                 ///< SWP_* flags.
  struct datapath *dp;
  Ptr<NetDevice> netdev;
  struct ofl_port *conf;
  struct ofl_port_stats *stats;

  uint16_t max_queues;
  uint16_t num_queues;
  struct sw_queue queues[NETDEV_MAX_QUEUES];  // FIXME trocar por uma queue do ns3
};

/**
 * \brief Packet Metadata, allows us to track the packet's metadata as it
 * passes through the switch.
 */
struct SwitchPacketMetadata
{
  Ptr<Packet> packet;         ///< The Packet itself
  ofpbuf* buffer;             ///< The OpenFlow buffer created from the Packet
  uint16_t protocolNumber;    ///< Protocol type of the Packet when the Packet is received
  Address src;                ///< Source Address of the Packet when the Packet is received
  Address dst;                ///< Destination Address of the Packet when the Packet is received
};



} // namespace ofs
} // namespace ns3
#endif /* OFSWITCH13_INTERFACE_H */
