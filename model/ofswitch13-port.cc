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

#include "ofswitch13-net-device.h"
#include "ofswitch13-interface.h"

#include "ns3/simulator.h"
#include "ns3/integer.h"
#include "ns3/uinteger.h"
#include "ns3/log.h"
#include "ns3/string.h"
#include "ns3/ethernet-header.h"
#include "ns3/ethernet-trailer.h"
#include "ns3/tcp-header.h"
#include "ns3/inet-socket-address.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13NetDevice");

OFPort::OFPort (datapath *dp, Ptr<CsmaNetDevice> csmaDev, 
                Ptr<OFSwitch13NetDevice> openflowDev)
  : m_csmaDev (csmaDev),
    m_openflowDev (openflowDev)
{
  m_portNo = ++(dp->ports_num);
  m_swPort = &dp->ports[m_portNo];

  memset (m_swPort, '\0', sizeof *m_swPort);

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
  // m_swPort->conf->peer = PortGetFeatures ();
  m_swPort->conf->curr_speed = port_speed (m_swPort->conf->curr);
  m_swPort->conf->max_speed = port_speed (m_swPort->conf->supported);

  dp_port_live_update (m_swPort);

  m_swPort->stats = (ofl_port_stats*)xmalloc (sizeof (ofl_port_stats));
  memset (m_swPort->stats, 0x00, sizeof (ofl_port_stats));
  m_swPort->stats->port_no = m_portNo;
  m_swPort->flags |= SWP_USED;

  // To avoid a null check failure in
  // dp_ports_handle_stats_request_port (), we are pointing
  // m_swPort->netdev to ns3::NetDevice, but it will not be used.
  m_swPort->netdev = (struct netdev*)PeekPointer (csmaDev);
  m_swPort->max_queues = NETDEV_MAX_QUEUES;
  m_swPort->num_queues = 0; // No queue support by now
  m_swPort->created = time_msec ();

  memset (m_swPort->queues, 0x00, sizeof (m_swPort->queues));

  list_push_back (&dp->port_list, &m_swPort->node);
}

OFPort::~OFPort ()
{
  m_csmaDev = 0;
  m_openflowDev = 0;
  ofl_structs_free_port (m_swPort->conf);
  free (m_swPort->stats);
}

uint32_t
OFPort::PortGetFeatures ()
{
  DataRateValue drv;
  DataRate dr;
  Ptr<CsmaChannel> channel = DynamicCast<CsmaChannel> (m_csmaDev->GetChannel ());
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

bool
OFPort::PortUpdateState ()
{
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
  return (orig_state != m_swPort->conf->state);
}

void
OFPort::Receive (Ptr<const NetDevice> sender, Ptr<Packet> packet)
{
  NS_LOG_FUNCTION (this);

  // Check port configuration.
  if (m_swPort->conf->config & ((OFPPC_NO_RECV | OFPPC_PORT_DOWN) != 0))
    {
      NS_LOG_WARN ("This port is down. Discarding packet");
      return;
    }

  // Update port stats
  m_swPort->stats->rx_packets++;
  m_swPort->stats->rx_bytes += packet->GetSize ();

  // Fire RX trace source
  // m_swPortRxTrace (packet, this);
  
  m_openflowDev->ReceiveFromSwitchPort (packet, m_portNo);
}

} // namespace ns3
