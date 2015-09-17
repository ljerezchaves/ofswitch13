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

#define NS_LOG_APPEND_CONTEXT \
  if (m_swPort != 0) { std::clog << "[dp " << m_swPort->dp->id << " port " << m_swPort->conf->port_no << "] "; }

#include "ns3/ethernet-header.h"
#include "ns3/ethernet-trailer.h"
#include "ofswitch13-net-device.h"
#include "ofswitch13-port.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Port");
NS_OBJECT_ENSURE_REGISTERED (OFSwitch13Port);

OFSwitch13Port::OFSwitch13Port ()
  : m_swPort (0),
    m_csmaDev (0),
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

  m_csmaDev = 0;
  m_openflowDev = 0;

  // Calling DoDispose on internal port, so it can use m_swPort pointer to free
  // internal strucutures first.
  m_portQueue->DoDispose ();
  ofl_structs_free_port (m_swPort->conf);
  free (m_swPort->stats);
  m_swPort = 0;
}

TypeId
OFSwitch13Port::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OFSwitch13Port")
    .SetParent<Object> ()
    .SetGroupName ("OFSwitch13")
    .AddConstructor<OFSwitch13Port> ()
    .AddTraceSource ("SwitchPortRx",
                     "Trace source indicating a packet "
                     "received at this switch port",
                     MakeTraceSourceAccessor (&OFSwitch13Port::m_rxTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("SwitchPortTx",
                     "Trace source indicating a packet "
                     "transmitted at this switch port",
                     MakeTraceSourceAccessor (&OFSwitch13Port::m_txTrace),
                     "ns3::Packet::TracedCallback")
  ;
  return tid;
}

OFSwitch13Port::OFSwitch13Port (datapath *dp, Ptr<CsmaNetDevice> csmaDev,
                                Ptr<OFSwitch13NetDevice> openflowDev)
  : m_swPort (0),
    m_csmaDev (csmaDev),
    m_openflowDev (openflowDev)
{
  NS_LOG_FUNCTION (this << csmaDev << openflowDev);

  m_portNo = ++(dp->ports_num);
  m_swPort = &dp->ports[m_portNo];

  memset (m_swPort, '\0', sizeof *m_swPort);

  // Filling ofsoftswitch13 internal structures for this port.
  m_swPort->dp = dp;
  m_swPort->conf = (ofl_port*)xmalloc (sizeof (ofl_port));
  memset (m_swPort->conf, 0x00, sizeof (ofl_port));
  m_swPort->conf->port_no = m_portNo;
  m_swPort->conf->name = (char*)xmalloc (OFP_MAX_PORT_NAME_LEN);
  snprintf (m_swPort->conf->name, OFP_MAX_PORT_NAME_LEN, "Port %d", m_portNo);
  m_csmaDev->GetAddress ().CopyTo (m_swPort->conf->hw_addr);
  m_swPort->conf->config = 0x00000000;
  m_swPort->conf->state = 0x00000000 | OFPPS_LIVE;
  m_swPort->conf->curr = PortGetFeatures ();
  m_swPort->conf->advertised = PortGetFeatures ();
  m_swPort->conf->supported = PortGetFeatures ();
  m_swPort->conf->peer = 0x00000000; // FIXME no information about peer port
  m_swPort->conf->curr_speed = port_speed (m_swPort->conf->curr);
  m_swPort->conf->max_speed = port_speed (m_swPort->conf->supported);

  dp_port_live_update (m_swPort);

  m_swPort->stats = (ofl_port_stats*)xmalloc (sizeof (ofl_port_stats));
  memset (m_swPort->stats, 0x00, sizeof (ofl_port_stats));
  m_swPort->stats->port_no = m_portNo;
  m_swPort->flags |= SWP_USED;

  // To avoid a null check failure in ofsoftswitch13
  // dp_ports_handle_stats_request_port (), we are pointing m_swPort->netdev to
  // corresponding ns3::CsmaNetDevice, but this pointer must not be used!
  m_swPort->netdev = (struct netdev*)PeekPointer (csmaDev);

  // Creating the OFSwitch13Queue for this switch port
  memset (m_swPort->queues, 0x00, sizeof (m_swPort->queues));
  m_swPort->max_queues = OFSwitch13Queue::GetMaxQueues ();
  m_swPort->num_queues = 0;
  m_portQueue = CreateObject<OFSwitch13Queue> (m_swPort);
  csmaDev->SetQueue (m_portQueue);

  m_swPort->created = time_msec ();

  list_push_back (&dp->port_list, &m_swPort->node);

  // Notify the controller that this port has been added/created
  ofl_msg_port_status msg;
  msg.header.type = OFPT_PORT_STATUS;
  msg.reason = OFPPR_ADD;
  msg.desc = m_swPort->conf;
  dp_send_message (m_swPort->dp, (ofl_msg_header*)&msg, 0);

  // Register a trace sink at OFSwitch13Port to get packets from CsmaNetDevice.
  csmaDev->TraceConnectWithoutContext (
    "OpenFlowRx", MakeCallback (&OFSwitch13Port::Receive, this));
}

uint32_t
OFSwitch13Port::GetPortNo (void) const
{
  return m_portNo;
}

bool
OFSwitch13Port::PortUpdateState ()
{
  NS_LOG_FUNCTION (this);

  uint32_t orig_state = m_swPort->conf->state;
  if (m_csmaDev->IsLinkUp ())
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
      NS_LOG_DEBUG ("Port status has changed. Notifying the controller.");
      ofl_msg_port_status msg;
      msg.header.type = OFPT_PORT_STATUS;
      msg.reason = OFPPR_MODIFY;
      msg.desc = m_swPort->conf;
      dp_send_message (m_swPort->dp, (ofl_msg_header*)&msg, 0);
      return true;
    }
  return false;
}

Ptr<OFSwitch13Queue>
OFSwitch13Port::GetOutputQueue ()
{
  NS_LOG_FUNCTION (this);
  return m_portQueue;
}

uint32_t
OFSwitch13Port::PortGetFeatures ()
{
  NS_LOG_FUNCTION (this);

  DataRateValue drv;
  DataRate dr;
  Ptr<CsmaChannel> channel =
    DynamicCast<CsmaChannel> (m_csmaDev->GetChannel ());
  channel->GetAttribute ("DataRate", drv);
  dr = drv.Get ();

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

void
OFSwitch13Port::Receive (Ptr<Packet> packet)
{
  NS_LOG_FUNCTION (this << packet);

  // Check port configuration.
  if (m_swPort->conf->config & ((OFPPC_NO_RECV | OFPPC_PORT_DOWN) != 0))
    {
      NS_LOG_WARN ("This port is down or inoperating. Discarding packet");
      return;
    }

  // Update port stats
  m_swPort->stats->rx_packets++;
  m_swPort->stats->rx_bytes += packet->GetSize ();

  // Fire RX trace source and send the packet to OpenFlow pipeline
  m_rxTrace (packet);
  m_openflowDev->ReceiveFromSwitchPort (packet, m_portNo);
}

bool
OFSwitch13Port::Send (Ptr<Packet> packet, uint32_t queueNo)
{
  NS_LOG_FUNCTION (this << packet << queueNo);

  if (m_swPort->conf->config & (OFPPC_PORT_DOWN))
    {
      NS_LOG_WARN ("This port is down. Discarding packet");
      return false;
    }

  // Fire TX trace source (with complete packet)
  m_txTrace (packet);

  // Removing the Ethernet header and trailer from packet, which will be
  // included again by CsmaNetDevice
  EthernetTrailer trailer;
  packet->RemoveTrailer (trailer);
  EthernetHeader header;
  packet->RemoveHeader (header);

  // Tagging the packet with queue number
  QueueTag queueNoTag (queueNo);
  packet->AddPacketTag (queueNoTag);
  bool status = m_csmaDev->SendFrom (packet, header.GetSource (),
                                     header.GetDestination (),
                                     header.GetLengthType ());
  // Updating port statistics
  if (status)
    {
      m_swPort->stats->tx_packets++;
      m_swPort->stats->tx_bytes += packet->GetSize ();
    }
  else
    {
      m_swPort->stats->tx_dropped++;
    }

  return status;
}

} // namespace ns3
