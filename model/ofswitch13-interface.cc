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

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Interface");

namespace ns3 {
namespace ofs {

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
  created = Simulator::Now ().ToInteger (Time::MS);
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



using namespace ns3;

Ptr<OFSwitch13NetDevice> GetDatapathDevice (uint64_t id);

/** 
 * Overriding ofsoftswitch13 time_now weak function from lib/timeval.c.
 * \return The current simulation time, in seconds. 
 */
time_t 
time_now (void)
{
  return (time_t)Simulator::Now ().ToInteger (Time::S);
}

/**
 * Overriding ofsoftswitch13 time_msec weak function from lib/timeval.c.
 * \return The current simulation time, in ms.
 */
long long int
time_msec (void)
{
  return (long long int)Simulator::Now ().GetMilliSeconds ();
}

/**
 * Overriding ofsoftswitch13 dp_send_message weak function from
 * udatapath/datapath.c. Sends the given OFLib message to the controller
 * associated with the datapath. The sender parameter is not current in use
 * (except for transaction xid field). Note that the current ns3 implementation
 * only supports a single controller per datapath.
 * \internal This function relies on the global map that stores ofpenflow
 * devices (\see ofswitch13-net-device.cc).
 * \param dp The datapath.
 * \param msg The OFlib message to send.
 * \param sender The sender information (xid).
 * \return 0 if everything's ok, error number otherwise.
 */
int
dp_send_message (struct datapath *dp, struct ofl_msg_header *msg, 
    const struct sender *sender) 
{
  int error = 0;

  Ptr<OFSwitch13NetDevice> dev = GetDatapathDevice (dp->id);
  error = dev->SendToController (msg, sender);
  if (!error)
    {
      NS_LOG_WARN ("There was an error sending the message!");
      return 1;
  }
  return 0;
}

#endif // NS3_OFSWITCH13
