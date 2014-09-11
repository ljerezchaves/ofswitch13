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

Port::Port (Ptr<NetDevice> netdev, uint32_t no) : 
            flags (0),
            netdev (netdev)
{  
    port_no = no;
    conf = (ofl_port*)xmalloc (sizeof (struct ofl_port));
    memset (conf, 0x00, sizeof (struct ofl_port));
    conf->name = (char*)xmalloc (4);
    snprintf(conf->name, 3, "%d", no);
    conf->port_no = no;
    conf->config = 0x00000000;
    conf->state = 0x00000000 | OFPPS_LIVE;
    netdev->GetAddress ().CopyTo (conf->hw_addr);
    // conf->curr       = netdev_get_features(netdev, NETDEV_FEAT_CURRENT);
    // conf->advertised = netdev_get_features(netdev, NETDEV_FEAT_ADVERTISED);
    // conf->supported  = netdev_get_features(netdev, NETDEV_FEAT_SUPPORTED);
    // conf->peer       = netdev_get_features(netdev, NETDEV_FEAT_PEER);
    // conf->curr_speed = port_speed(port->conf->curr);
    // conf->max_speed  = port_speed(port->conf->supported);

    stats = (ofl_port_stats*)xmalloc (sizeof (struct ofl_port_stats));
    memset (stats, 0x00, sizeof (struct ofl_port_stats));
    stats->port_no = no;

    flags |= SWP_USED;
}

ofpbuf* BufferFromPacket (Ptr<const Packet> packet, size_t bodyRoom, size_t headRoom)
{
  NS_LOG_FUNCTION_NOARGS ();

  uint32_t pktSize = packet->GetSize ();
  NS_ASSERT (pktSize <= bodyRoom); 

  ofpbuf *buffer = ofpbuf_new_with_headroom (bodyRoom, headRoom);
  packet->CopyData ((uint8_t*)ofpbuf_put_uninit (buffer, pktSize), pktSize);
  return buffer;
}

ofpbuf* PackFromMsg (ofl_msg_header *msg, uint32_t xid)
{
  NS_LOG_FUNCTION_NOARGS ();

  int error;
  uint8_t *buf;
  size_t buf_size;
  struct ofpbuf *ofpbuf = ofpbuf_new (0);
  
  // Pack message into ofpbuf using wire format
  error = ofl_msg_pack (msg, xid, &buf, &buf_size, NULL/*struct ofl_exp *exp*/);
  if (error)
    {
      NS_LOG_ERROR ("Error packing message.");
    }
  ofpbuf_use (ofpbuf, buf, buf_size);
  ofpbuf_put_uninit (ofpbuf, buf_size);

  return ofpbuf;
}

Ptr<Packet> PacketFromBufferAndFree (ofpbuf* buffer)
{
  NS_LOG_FUNCTION_NOARGS ();
  
  Ptr<Packet> packet = Create<Packet> ((uint8_t*)buffer->data, buffer->size);
  ofpbuf_delete (buffer);
  return packet;
}

} // namespace ofs
} // namespace ns3
#endif // NS3_OFSWITCH13
