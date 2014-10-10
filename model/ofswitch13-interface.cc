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

ofpbuf* 
BufferFromPacket (Ptr<const Packet> packet, size_t bodyRoom, 
    size_t headRoom)
{
  NS_LOG_FUNCTION_NOARGS ();

  uint32_t pktSize = packet->GetSize ();
  NS_ASSERT (pktSize <= bodyRoom); 

  ofpbuf *buffer = ofpbuf_new_with_headroom (bodyRoom, headRoom);
  packet->CopyData ((uint8_t*)ofpbuf_put_uninit (buffer, pktSize), pktSize);
  return buffer;
}

ofpbuf*
BufferFromMsg (ofl_msg_header *msg, uint32_t xid, ofl_exp *exp)
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

Ptr<Packet>
PacketFromMsg (ofl_msg_header *msg, uint32_t xid)
{
  return PacketFromBufferAndFree (BufferFromMsg (msg, xid));
}

Ptr<Packet> 
PacketFromBufferAndFree (ofpbuf* buffer)
{
  NS_LOG_FUNCTION_NOARGS ();
  Ptr<Packet> packet = Create<Packet> ((uint8_t*)buffer->data, buffer->size);
  ofpbuf_delete (buffer);
  return packet;
}

Ptr<Packet> 
PacketFromBuffer (ofpbuf* buffer)
{
  NS_LOG_FUNCTION_NOARGS ();
  Ptr<Packet> packet = Create<Packet> ((uint8_t*)buffer->data, buffer->size);
  return packet;
}


Ptr<Packet> 
PacketFromInternalPacket (packet *pkt)
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
 * associated with the datapath. 
 * \internal This function relies on the global map that stores ofpenflow
 * devices to call the method on the correct object (\see
 * ofswitch13-net-device.cc).
 * \param dp The datapath.
 * \param msg The OFlib message to send.
 * \param sender The sender information.
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
    }
  return !error;
}

/**
 * Overriding ofsoftswitch13 dp_ports_output weak function from
 * udatapath/dp_ports.c. Outputs a datapath packet on the port. 
 * \internal This function relies on the global map that stores ofpenflow
 * devices to call the method on the correct object (\see
 * ofswitch13-net-device.cc).
 * \param dp The datapath.
 * \param buffer The packet buffer.
 * \param out_port The port number.
 * \param queue_id The queue to use.
 */
void
dp_ports_output (struct datapath *dp, struct ofpbuf *buffer, 
    uint32_t out_port, uint32_t queue_id)
{
  Ptr<OFSwitch13NetDevice> dev = GetDatapathDevice (dp->id);
  dev->SendToSwitchPort (buffer, out_port, queue_id);
}

#endif // NS3_OFSWITCH13
