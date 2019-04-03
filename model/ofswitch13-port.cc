/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
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
 * Author: Luciano Chaves <luciano@lrc.ic.unicamp.br>
 */

#include <ns3/ethernet-header.h>
#include <ns3/ethernet-trailer.h>
#include <ns3/pointer.h>
#include <ns3/csma-net-device.h>
#include <ns3/virtual-net-device.h>
#include "ofswitch13-device.h"
#include "ofswitch13-port.h"
#include "tunnel-id-tag.h"
#include "queue-tag.h"

#undef NS_LOG_APPEND_CONTEXT
#define NS_LOG_APPEND_CONTEXT \
  std::clog << "[dp " << m_dpId << " port " << m_portNo << "] ";

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Port");
NS_OBJECT_ENSURE_REGISTERED (OFSwitch13Port);

static ObjectFactory
GetDefaultQueueFactory ()
{
  // Setting default internal queue configuration.
  ObjectFactory queueFactory;
  queueFactory.SetTypeId ("ns3::OFSwitch13PriorityQueue");
  return queueFactory;
}

OFSwitch13Port::OFSwitch13Port ()
  : m_dpId (0),
  m_portNo (0),
  m_swPort (0),
  m_netDev (0),
  m_openflowDev (0)
{
  NS_LOG_FUNCTION (this);
}

OFSwitch13Port::~OFSwitch13Port ()
{
  NS_LOG_FUNCTION (this);
}

void
OFSwitch13Port::DoDispose ()
{
  NS_LOG_FUNCTION (this);

  m_portQueue->Dispose ();
  if (m_swPort)
    {
      ofl_structs_free_port (m_swPort->conf);
      free (m_swPort->stats);
    }

  m_swPort = 0;
  m_openflowDev = 0;
  m_netDev = 0;
}

TypeId
OFSwitch13Port::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OFSwitch13Port")
    .SetParent<Object> ()
    .SetGroupName ("OFSwitch13")
    .AddConstructor<OFSwitch13Port> ()
    .AddAttribute ("PortQueue",
                   "The OpenFlow queue to use as the TX queue in this port.",
                   PointerValue (),
                   MakePointerAccessor (&OFSwitch13Port::m_portQueue),
                   MakePointerChecker<OFSwitch13Queue> ())
    .AddAttribute ("QueueFactory",
                   "The object factory for the OpenFlow queue.",
                   TypeId::ATTR_GET | TypeId::ATTR_CONSTRUCT,
                   ObjectFactoryValue (GetDefaultQueueFactory ()),
                   MakeObjectFactoryAccessor (&OFSwitch13Port::m_factQueue),
                   MakeObjectFactoryChecker ())

    .AddTraceSource ("SwitchPortRx",
                     "Trace source indicating a packet received at this port.",
                     MakeTraceSourceAccessor (&OFSwitch13Port::m_rxTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("SwitchPortTx",
                     "Trace source indicating a packet sent at this port.",
                     MakeTraceSourceAccessor (&OFSwitch13Port::m_txTrace),
                     "ns3::Packet::TracedCallback")
  ;
  return tid;
}

OFSwitch13Port::OFSwitch13Port (struct datapath *dp, Ptr<NetDevice> netDev,
                                Ptr<OFSwitch13Device> openflowDev)
  : m_dpId (0),
  m_portNo (0),
  m_swPort (0),
  m_netDev (netDev),
  m_openflowDev (openflowDev)
{
  NS_LOG_FUNCTION (this << netDev << openflowDev);

  m_dpId = dp->id;
  m_portNo = ++(dp->ports_num);
  m_swPort = &dp->ports[m_portNo];
  memset (m_swPort, '\0', sizeof *m_swPort);

  // Saving datapath pointer.
  m_swPort->dp = dp;
}

void
OFSwitch13Port::NotifyConstructionCompleted ()
{
  NS_LOG_FUNCTION (this);

  // Check for valid NetDevice type
  Ptr<CsmaNetDevice> csmaDev = m_netDev->GetObject<CsmaNetDevice> ();
  Ptr<VirtualNetDevice> virtDev = m_netDev->GetObject<VirtualNetDevice> ();
  NS_ABORT_MSG_IF (!csmaDev && !virtDev,
                   "NetDevice must be CsmaNetDevice or VirtualNetDevice.");

  // Filling ofsoftswitch13 internal structures for this port.
  size_t oflPortSize = sizeof (struct ofl_port);
  size_t oflPortStatsSize = sizeof (struct ofl_port_stats);

  m_swPort->conf = (struct ofl_port*)xmalloc (oflPortSize);
  memset (m_swPort->conf, 0x00, oflPortSize);
  m_swPort->conf->port_no = m_portNo;
  m_swPort->conf->name = (char*)xmalloc (OFP_MAX_PORT_NAME_LEN);
  snprintf (m_swPort->conf->name, OFP_MAX_PORT_NAME_LEN, "Port %d", m_portNo);
  m_netDev->GetAddress ().CopyTo (m_swPort->conf->hw_addr);
  m_swPort->conf->config = 0x00000000;
  m_swPort->conf->state = 0x00000000 | OFPPS_LIVE;
  m_swPort->conf->curr = GetPortFeatures ();
  m_swPort->conf->advertised = GetPortFeatures ();
  m_swPort->conf->supported = GetPortFeatures ();
  m_swPort->conf->peer = 0x00000000; // FIXME no information about peer port
  m_swPort->conf->curr_speed = port_speed (m_swPort->conf->curr);
  m_swPort->conf->max_speed = port_speed (m_swPort->conf->supported);

  dp_port_live_update (m_swPort);

  m_swPort->stats = (struct ofl_port_stats*)xmalloc (oflPortStatsSize);
  memset (m_swPort->stats, 0x00, oflPortStatsSize);
  m_swPort->stats->port_no = m_portNo;
  m_swPort->flags |= SWP_USED;

  // To avoid a null check failure in ofsoftswitch13
  // dp_ports_handle_stats_request_port (), we are pointing m_swPort->netdev to
  // corresponding ns3::NetDevice, but this pointer must not be used!
  m_swPort->netdev = (struct netdev*)PeekPointer (m_netDev);

  // Creating the OFSwitch13Queue for this switch port
  memset (m_swPort->queues, 0x00, sizeof (m_swPort->queues));
  m_swPort->max_queues = m_swPort->dp->max_queues;
  m_swPort->num_queues = 0;
  m_portQueue = m_factQueue.Create<OFSwitch13Queue> ();
  m_portQueue->SetPortStruct (m_swPort);
  m_portQueue->Initialize ();
  if (csmaDev)
    {
      csmaDev->SetQueue (m_portQueue);
    }

  m_swPort->created = time_msec ();

  list_push_back (&m_swPort->dp->port_list, &m_swPort->node);

  // Notify the controller that this port has been added/created
  struct ofl_msg_port_status msg;
  msg.header.type = OFPT_PORT_STATUS;
  msg.reason = OFPPR_ADD;
  msg.desc = m_swPort->conf;
  dp_send_message (m_swPort->dp, (struct ofl_msg_header*)&msg, 0);

  // Register the receive callback to get packets from the NetDevice.
  if (csmaDev)
    {
      csmaDev->SetOpenFlowReceiveCallback (
        MakeCallback (&OFSwitch13Port::Receive, this));
    }
  else
    {
      NS_ASSERT (virtDev);
      virtDev->SetOpenFlowReceiveCallback (
        MakeCallback (&OFSwitch13Port::Receive, this));
    }
}

Ptr<NetDevice>
OFSwitch13Port::GetPortDevice (void) const
{
  return m_netDev;
}

uint32_t
OFSwitch13Port::GetPortNo (void) const
{
  return m_portNo;
}

Ptr<OFSwitch13Queue>
OFSwitch13Port::GetPortQueue (void) const
{
  return m_portQueue;
}

Ptr<OFSwitch13Device>
OFSwitch13Port::GetSwitchDevice (void) const
{
  return m_openflowDev;
}

bool
OFSwitch13Port::PortUpdateState ()
{
  uint32_t orig_state = m_swPort->conf->state;
  if (m_netDev->IsLinkUp ())
    {
      m_swPort->conf->state &= ~OFPPS_LINK_DOWN;
    }
  else
    {
      m_swPort->conf->state |= OFPPS_LINK_DOWN;
    }
  dp_port_live_update (m_swPort);

  if (orig_state != m_swPort->conf->state)
    {
      NS_LOG_INFO ("Port status has changed. Notifying the controller.");
      struct ofl_msg_port_status msg;
      msg.header.type = OFPT_PORT_STATUS;
      msg.reason = OFPPR_MODIFY;
      msg.desc = m_swPort->conf;
      dp_send_message (m_swPort->dp, (struct ofl_msg_header*)&msg, 0);
      return true;
    }
  return false;
}

uint32_t
OFSwitch13Port::GetPortFeatures ()
{
  NS_LOG_FUNCTION (this);

  DataRate dr;
  Ptr<Channel> channel = m_netDev->GetChannel ();
  if (channel)
    {
      Ptr<CsmaChannel> csmaChannel = channel->GetObject<CsmaChannel> ();
      if (csmaChannel)
        {
          DataRateValue drv;
          csmaChannel->GetAttribute ("DataRate", drv);
          dr = drv.Get ();
        }
    }

  uint32_t feat = 0x00000000;
  feat |= OFPPF_COPPER;
  feat |= OFPPF_AUTONEG;

  if (dr == DataRate ("10Mbps"))
    {
      feat |= OFPPF_10MB_FD;
    }
  else if (dr == DataRate ("100Mbps"))
    {
      feat |= OFPPF_100MB_FD;
    }
  else if (dr == DataRate ("1Gbps"))
    {
      feat |= OFPPF_1GB_FD;
    }
  else if (dr == DataRate ("10Gbps"))
    {
      feat |= OFPPF_10GB_FD;
    }
  else if (dr == DataRate ("40Gbps"))
    {
      feat |= OFPPF_40GB_FD;
    }
  else if (dr == DataRate ("100Gbps"))
    {
      feat |= OFPPF_100GB_FD;
    }
  else if (dr == DataRate ("1000Gbps"))
    {
      feat |= OFPPF_1TB_FD;
    }
  else
    {
      feat |= OFPPF_OTHER;
    }
  return feat;
}

bool
OFSwitch13Port::Receive (Ptr<NetDevice> device, Ptr<const Packet> packet,
                         uint16_t protocol, const Address &from,
                         const Address &to, NetDevice::PacketType packetType)
{
  NS_LOG_FUNCTION (this << packet);

  // Check port configuration.
  if ((m_swPort->conf->config & (OFPPC_NO_RECV | OFPPC_PORT_DOWN)) != 0)
    {
      NS_LOG_WARN ("This port is down or inoperating. Discarding packet");
      return false;
    }

  // Update port stats
  m_swPort->stats->rx_packets++;
  m_swPort->stats->rx_bytes += packet->GetSize ();

  // Fire RX trace source
  m_rxTrace (packet);
  NS_LOG_DEBUG ("Pkt " << packet->GetUid () << " received at this port.");

  // Retrieve the tunnel id from packet, if available.
  Ptr<Packet> localPacket = packet->Copy ();
  TunnelIdTag tunnelIdTag;
  localPacket->PeekPacketTag (tunnelIdTag);
  uint64_t tunnelId = tunnelIdTag.GetTunnelId ();
  NS_LOG_DEBUG ("Pkt tunnel id is " << tunnelId);

  // Send the packet to the OpenFlow pipeline
  NS_LOG_DEBUG ("Pkt copy " << localPacket->GetUid () << " sent to pipeline.");
  m_openflowDev->ReceiveFromSwitchPort (localPacket, m_portNo, tunnelId);
  return true;
}

bool
OFSwitch13Port::Send (Ptr<const Packet> packet, uint32_t queueNo,
                      uint64_t tunnelId)
{
  NS_LOG_FUNCTION (this << packet << queueNo << tunnelId);

  if (m_swPort->conf->config & (OFPPC_PORT_DOWN))
    {
      NS_LOG_WARN ("This port is down. Discarding packet");
      return false;
    }

  // Fire TX trace source (with complete packet)
  m_txTrace (packet);

  Ptr<Packet> packetCopy = packet->Copy ();
  NS_LOG_DEBUG ("Pkt " << packetCopy->GetUid () <<
                " will be sent at this port.");

  // Removing the Ethernet header and trailer from packet, which will be
  // included again by CsmaNetDevice
  EthernetTrailer trailer;
  packetCopy->RemoveTrailer (trailer);
  EthernetHeader header;
  packetCopy->RemoveHeader (header);

  // Tagging the packet with queue and tunnel ids.
  QueueTag queueTag (queueNo);
  packetCopy->ReplacePacketTag (queueTag);
  NS_LOG_DEBUG ("Pkt queue will be " << queueNo);

  TunnelIdTag tunnelIdTag (tunnelId);
  packetCopy->ReplacePacketTag (tunnelIdTag);
  NS_LOG_DEBUG ("Pkt tunnel tag will be " << tunnelId);

  // Send the packet over the underlying net device.
  bool status = m_netDev->SendFrom (packetCopy, header.GetSource (),
                                    header.GetDestination (),
                                    header.GetLengthType ());
  // Updating port statistics
  if (status)
    {
      m_swPort->stats->tx_packets++;
      m_swPort->stats->tx_bytes += packetCopy->GetSize ();
    }
  else
    {
      m_swPort->stats->tx_dropped++;
    }
  return status;
}

struct sw_port*
OFSwitch13Port::GetPortStruct ()
{
  return m_swPort;
}

} // namespace ns3
