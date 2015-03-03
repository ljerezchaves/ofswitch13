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
#include "ofswitch13-controller.h"

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
  return (time_t) Simulator::Now ().ToInteger (Time::S);
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
 * Overriding ofsoftswitch13 send_openflow_buffer_to_remote weak function from
 * udatapath/datapath.c. Sends the given OFLib buffer message to the controller
 * associated with remote connection structure.
 * \internal This function relies on the global map that stores openflow
 * devices to call the method on the correct object (\see
 * ofswitch13-net-device.cc).
 * \param buffer The message buffer to send.
 * \param remote The controller connection information.
 * \return 0 if everything's ok, error number otherwise.
 */
int
send_openflow_buffer_to_remote (struct ofpbuf *buffer, struct remote *remote)
{
  NS_LOG_FUNCTION_NOARGS ();

  int error = 0;
  Ptr<OFSwitch13NetDevice> dev = GetDatapathDevice (remote->dp->id);
  error = dev->SendToController (buffer, remote);
  if (error)
    {
      NS_LOG_WARN ("There was an error sending the message!");
      return error;
    }
  return 0;
}

/**
 * Overriding ofsoftswitch13 dp_actions_output_port weak function from
 * udatapath/dp_actions.c. Outputs a datapath packet on switch port. This code
 * is nearly the same on ofsoftswitch, but it gets the openflow device from
 * datapath id and uses member functions to send the packet over ns3
 * structures.
 * \internal This function relies on the global map that stores openflow
 * devices to call the method on the correct object (\see
 * ofswitch13-net-device.cc).
 * \param pkt The internal packet to send.
 * \param out_port The switch port number.
 * \param out_queue The queue to use.
 * \param max_len Max lenght of packet to send to controller.
 * \param cookie Packet cookie to send to controller.
 */
void
dp_actions_output_port (struct packet *pkt, uint32_t out_port, 
    uint32_t out_queue, uint16_t max_len, uint64_t cookie)
{
  NS_LOG_FUNCTION_NOARGS ();
  
  Ptr<OFSwitch13NetDevice> dev = GetDatapathDevice (pkt->dp->id);
  switch (out_port) {
    case (OFPP_TABLE):
      {
        if (pkt->packet_out) 
          {
            // Makes sure packet cannot be resubmit to pipeline again.
            pkt->packet_out = false;
            pipeline_process_packet (pkt->dp->pipeline, pkt);
          } 
        else 
          {
            NS_LOG_WARN ("Trying to resubmit packet to pipeline.");
          }
        break;
      }
    case (OFPP_IN_PORT): 
      {
        dev->SendToSwitchPort (pkt, pkt->in_port, 0);
        break;
      }
    case (OFPP_CONTROLLER): 
      {
        struct ofl_msg_packet_in msg;
        msg.header.type = OFPT_PACKET_IN;
        msg.total_len = pkt->buffer->size;
        msg.reason = pkt->handle_std->table_miss ? OFPR_NO_MATCH : OFPR_ACTION;
        msg.table_id = pkt->table_id;
        msg.data = (uint8_t*)pkt->buffer->data;
        msg.cookie = cookie;

        // Even with miss_send_len == OFPCML_NO_BUFFEROFPCML_NO_BUFFER, save
        // the packet into buffer to avoid loosing ns-3 packet uid.
        dp_buffers_save (pkt->dp->buffers, pkt);
        msg.buffer_id = pkt->buffer_id;
        msg.data_length = MIN (max_len, pkt->buffer->size);

        if (!pkt->handle_std->valid)
          {
            packet_handle_std_validate (pkt->handle_std);
          }
        msg.match = (struct ofl_match_header*) &pkt->handle_std->match;
        dp_send_message (pkt->dp, (struct ofl_msg_header *)&msg, 0);
        break;
      }
    case (OFPP_FLOOD):
    case (OFPP_ALL): 
      {
        struct sw_port *p;
        LIST_FOR_EACH (p, struct sw_port, node, &pkt->dp->port_list) 
          {
            if ((p->stats->port_no == pkt->in_port) ||
                (out_port == OFPP_FLOOD && p->conf->config & OFPPC_NO_FWD)) 
              {
                continue;
              }
            dev->SendToSwitchPort (pkt, p->stats->port_no, 0);
          }
        break;
      }
    case (OFPP_NORMAL):
    case (OFPP_LOCAL):
    default: 
      {
        if (pkt->in_port == out_port)
          {
            NS_LOG_WARN ("Can't directly forward to input port.");
          }
        else 
          {
            NS_LOG_DEBUG ("Outputting packet on port " << out_port);
            dev->SendToSwitchPort (pkt, out_port, out_queue);
          }
      }
  }
}

/**
 * Overriding ofsoftswitch13 packet_destroy weak function from
 * udatapath/packet.c. This is necesary to remove packets saved in OpenFlow
 * device while under pipeline process and which were destroyed by the device
 * before beeing forwarded to any switch port.
 * \param pkt The internal packet to destroy.
 */
void
packet_destroy (struct packet *pkt) 
{
  NS_LOG_FUNCTION_NOARGS ();
  
  // If packet is saved in a buffer, do not destroy it if buffer is valid
  if (pkt->buffer_id != NO_BUFFER) 
    {
      if (dp_buffers_is_alive (pkt->dp->buffers, pkt->buffer_id)) 
        {
          return;
        }
      else 
        {
          dp_buffers_discard (pkt->dp->buffers, pkt->buffer_id, false);
        }
    }

  Ptr<OFSwitch13NetDevice> dev = GetDatapathDevice (pkt->dp->id);
  Ptr<Packet> packet = dev->RemovePipelinePacket (pkt->ns3_uid);
  if (packet)
    {
      NS_LOG_WARN ("Openflow destroyed the packet " << packet->GetUid ());
    }
  action_set_destroy (pkt->action_set);
  ofpbuf_delete (pkt->buffer);
  packet_handle_std_destroy (pkt->handle_std);
  free (pkt);
}

/**
 * Overriding ofsoftswitch13 dpctl_send_and_print weak function from
 * utilities/dpctl.c. Send a message from controller to switch.
 * \param vconn The SwitchInfo pointer, sent from controller to
 * dpctl_exec_ns3_command function and get back here to proper identify the
 * controller object.
 * \param msg The OFLib message to send.
 */
void
dpctl_send_and_print (struct vconn *vconn, struct ofl_msg_header *msg)
{
  NS_LOG_FUNCTION_NOARGS ();
  SwitchInfo *sw = (SwitchInfo*)vconn;
  sw->ctrl->SendToSwitch (sw, msg, 0);
}

/**
 * Overriding ofsoftswitch13 dpctl_transact_and_print weak function from
 * utilities/dpctl.c. Send a message from controller to switch.
 * \internal Different from ofsoftswitch13 dpctl, this transaction doesn't
 * wait for a reply, as ns3 socket library doesn't provide blocking sockets. So,
 * we send the request and return. The reply will came later, using the ns3
 * callback mechanism.
 * \param vconn The SwitchInfo pointer, sent from controller to
 * dpctl_exec_ns3_command function and get back here to proper identify the
 * controller object.
 * \param msg The OFLib request to send.
 * \param repl The OFLib reply message (not used by ns3).
 */
void
dpctl_transact_and_print (struct vconn *vconn, struct ofl_msg_header *req,
                          struct ofl_msg_header **repl)
{
  NS_LOG_FUNCTION_NOARGS ();
  dpctl_send_and_print (vconn, req);
}

#endif // NS3_OFSWITCH13
