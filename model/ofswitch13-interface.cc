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
#ifdef NS3_OFSWITCH13

#include "ofswitch13-interface.h"
#include "ofswitch13-net-device.h"

namespace ns3 {
namespace ofs {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Interface");

Port::Port (Ptr<NetDevice> netdev, uint32_t no) 
  : flags (0),
    netdev (netdev)
{  
  port_no = no;
  conf = (ofl_port*)xmalloc (sizeof (ofl_port));
  memset (conf, 0x00, sizeof (ofl_port));
  conf->name = (char*)xmalloc (4);
  snprintf(conf->name, 8, "Port %d", no);
  conf->port_no = no;
  conf->config = 0x00000000;
  conf->state = 0x00000000 | OFPPS_LIVE;
  netdev->GetAddress ().CopyTo (conf->hw_addr);
  
  conf->curr       = GetFeatures (DynamicCast<CsmaNetDevice> (netdev));
  conf->advertised = GetFeatures (DynamicCast<CsmaNetDevice> (netdev));
  conf->supported  = GetFeatures (DynamicCast<CsmaNetDevice> (netdev));
  // conf->peer       = GetFeatures (DynamicCast<CsmaNetDevice> (netdev));
  conf->curr_speed = port_speed (conf->curr);
  conf->max_speed  = port_speed (conf->supported);
  
  stats = (ofl_port_stats*)xmalloc (sizeof (ofl_port_stats));
  memset (stats, 0x00, sizeof (ofl_port_stats));
  stats->port_no = no;

  flags |= SWP_USED;
  created = Simulator::Now ().GetTimeStep ();
}

uint32_t 
Port::GetFeatures (Ptr<CsmaNetDevice> netdev)
{
  DataRateValue drv;
  DataRate dr;
  Ptr<CsmaChannel> channel = DynamicCast<CsmaChannel> (netdev->GetChannel ());
  channel->GetAttribute("DataRate", drv);
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
  else if (dr == DataRate ("1Tbps"))
    {
      feat |= OFPPF_1TB_FD;
    }
  else
    {
      feat |= OFPPF_OTHER;
    }
  return feat;
}

EchoInfo::EchoInfo (Ipv4Address ip)
{
  waiting = true;
  send = Simulator::Now ();
  destIp = ip;
}

Time EchoInfo::GetRtt ()
{
  if (waiting)
    {
      return Time (-1);
    }
  else
    {
      Time rtt = recv - send;
      return recv-send; 
    }
}

ofpbuf* BufferFromPacket (Ptr<const Packet> packet, size_t bodyRoom, 
    size_t headRoom)
{
  NS_LOG_FUNCTION_NOARGS ();

  uint32_t pktSize = packet->GetSize ();
  NS_ASSERT (pktSize <= bodyRoom); 

  ofpbuf *buffer = ofpbuf_new_with_headroom (bodyRoom, headRoom);
  packet->CopyData ((uint8_t*)ofpbuf_put_uninit (buffer, pktSize), pktSize);
  return buffer;
}

ofpbuf* BufferFromMsg (ofl_msg_header *msg, uint32_t xid, ofl_exp *exp)
{
  NS_LOG_FUNCTION_NOARGS ();

  int error;
  uint8_t *buf;
  size_t buf_size;
  ofpbuf *ofpbuf = ofpbuf_new (0);
  
  // Pack message into ofpbuf using wire format
  error = ofl_msg_pack (msg, xid, &buf, &buf_size, exp);
  if (error)
    {
      NS_LOG_ERROR ("Error packing message.");
    }
  ofpbuf_use (ofpbuf, buf, buf_size);
  ofpbuf_put_uninit (ofpbuf, buf_size);

  return ofpbuf;
}

packet * InternalPacketFromBuffer (uint32_t in_port, ofpbuf *buf,
    bool packet_out, datapath* dp) 
{
  NS_LOG_FUNCTION_NOARGS ();
  packet *pkt;
  pkt = (packet*)xmalloc (sizeof (packet));

  pkt->dp         = dp;
  pkt->buffer     = buf;
  pkt->in_port    = in_port;
  pkt->action_set = (action_set*)xmalloc (sizeof (action_set));
  list_init (&pkt->action_set->actions);

  pkt->packet_out       = packet_out;
  pkt->out_group        = OFPG_ANY;
  pkt->out_port         = OFPP_ANY;
  pkt->out_port_max_len = 0;
  pkt->out_queue        = 0;
  pkt->buffer_id        = NO_BUFFER;
  pkt->table_id         = 0;

  // Note: here, the nblink will parse the packet
  pkt->handle_std = packet_handle_std_create (pkt);
  return pkt;
}

Ptr<Packet> PacketFromMsg (ofl_msg_header *msg, uint32_t xid)
{
  return PacketFromBufferAndFree (BufferFromMsg (msg, xid));
}

Ptr<Packet> PacketFromBufferAndFree (ofpbuf* buffer)
{
  NS_LOG_FUNCTION_NOARGS ();
  Ptr<Packet> packet = Create<Packet> ((uint8_t*)buffer->data, buffer->size);
  ofpbuf_delete (buffer);
  return packet;
}

Ptr<Packet> PacketFromInternalPacket (packet *pkt)
{
  NS_LOG_FUNCTION_NOARGS ();
  ofpbuf *buffer = pkt->buffer;
  Ptr<Packet> packet = Create<Packet> ((uint8_t*)buffer->data, buffer->size);
  return packet;
}

} // namespace ofs
} // namespace ns3
#endif // NS3_OFSWITCH13
