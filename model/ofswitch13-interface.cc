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

#include "ofswitch13-interface.h"
#include "ofswitch13-net-device.h"
#include "ofswitch13-controller.h"

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Interface");

namespace ns3 {
namespace ofs {

ofpbuf*
BufferFromPacket (Ptr<const Packet> packet, size_t bodyRoom, size_t headRoom)
{
  NS_LOG_FUNCTION_NOARGS ();
  NS_ASSERT (packet->GetSize () <= bodyRoom);

  ofpbuf *buffer;
  uint32_t pktSize;

  pktSize = packet->GetSize ();
  buffer = ofpbuf_new_with_headroom (bodyRoom, headRoom);
  packet->CopyData ((uint8_t*)ofpbuf_put_uninit (buffer, pktSize), pktSize);
  return buffer;
}

Ptr<Packet>
PacketFromMsg (ofl_msg_header *msg, uint32_t xid)
{
  NS_LOG_FUNCTION_NOARGS ();

  int error;
  uint8_t *buf;
  size_t buf_size;
  Ptr<Packet> packet;
  ofpbuf *buffer;

  buffer = ofpbuf_new (0);
  error = ofl_msg_pack (msg, xid, &buf, &buf_size, 0);
  if (!error)
    {
      ofpbuf_use (buffer, buf, buf_size);
      ofpbuf_put_uninit (buffer, buf_size);
      packet = Create<Packet> ((uint8_t*)buffer->data, buffer->size);
      ofpbuf_delete (buffer);
    }
  return packet;
}

Ptr<Packet>
PacketFromBuffer (ofpbuf* buffer)
{
  NS_LOG_FUNCTION_NOARGS ();

  Ptr<Packet> packet;

  packet = Create<Packet> ((uint8_t*)buffer->data, buffer->size);
  return packet;
}

} // namespace ofs
} // namespace ns3

using namespace ns3;

/**
 * Overriding ofsoftswitch13 time_now weak function from lib/timeval.c.
 * \return The current simulation time, in seconds.
 */
time_t
time_now (void)
{
  return static_cast<time_t> (Simulator::Now ().ToInteger (Time::S));
}

/**
 * Overriding ofsoftswitch13 time_msec weak function from lib/timeval.c.
 * \return The current simulation time, in ms.
 */
long long int
time_msec (void)
{
  return static_cast<long long int> (Simulator::Now ().GetMilliSeconds ());
}

/** Overriding ofsoftswitch weak functions using static member functions. */
int
send_openflow_buffer_to_remote (struct ofpbuf *buffer, struct remote *remote)
{
  return OFSwitch13Device::SendOpenflowBufferToRemote (buffer, remote);
}

void
dp_actions_output_port (struct packet *pkt, uint32_t out_port,
                        uint32_t out_queue, uint16_t max_len, uint64_t cookie)
{
  OFSwitch13Device::DpActionsOutputPort (pkt, out_port, out_queue, max_len,
                                         cookie);
}

void
dpctl_send_and_print (struct vconn *vconn, struct ofl_msg_header *msg)
{
  OFSwitch13Controller::DpctlSendAndPrint (vconn, msg);
}

void
dpctl_transact_and_print (struct vconn *vconn, struct ofl_msg_header *req,
                          struct ofl_msg_header **repl)
{
  // Different from ofsoftswitch13 dpctl, this transaction doesn't wait for a
  // reply, as ns-3 socket library doesn't provide blocking sockets. So, we
  // send the request and return. The reply will came later, using the ns-3
  // callback mechanism.
  OFSwitch13Controller::DpctlSendAndPrint (vconn, req);
}
