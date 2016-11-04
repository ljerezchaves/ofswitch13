/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2016 University of Campinas (Unicamp)
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

#include "tunnel-controller.h"
#include <ns3/epc-gtpu-header.h>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("TunnelController");
NS_OBJECT_ENSURE_REGISTERED (TunnelController);

TunnelController::TunnelController ()
{
  NS_LOG_FUNCTION (this);
}

TunnelController::~TunnelController ()
{
  NS_LOG_FUNCTION (this);
}

TypeId
TunnelController::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::TunnelController")
    .SetParent<OFSwitch13Controller> ()
    .SetGroupName ("OFSwitch13")
  ;
  return tid;
}

void
TunnelController::SaveArpEntry (Ipv4Address ipAddr, Mac48Address macAddr)
{
  NS_LOG_FUNCTION (this << ipAddr << macAddr);

  std::pair<Ipv4Address, Mac48Address> entry (ipAddr, macAddr);
  std::pair <IpMacMap_t::iterator, bool> ret;
  ret = m_arpTable.insert (entry);
  if (ret.second == true)
    {
      NS_LOG_DEBUG ("New ARP entry: " << ipAddr << " - " << macAddr);
      return;
    }
  NS_FATAL_ERROR ("This IP already exists in ARP table.");
}

void
TunnelController::DoDispose ()
{
  NS_LOG_FUNCTION (this);
  m_arpTable.clear ();
}

void
TunnelController::HandshakeSuccessful (Ptr<const RemoteSwitch> swtch)
{
  // Send ARP requests to controller
  DpctlExecute (swtch, "flow-mod cmd=add,table=0,prio=16 eth_type=0x0806"
                " apply:output=ctrl");

  // Table miss entry
  DpctlExecute (swtch, "flow-mod cmd=add,table=0,prio=0 apply:output=ctrl");

  // IP packets entering the switch from the physical port 1 are coming from
  // the host node. In this case, set the arbitrary value 0xFFFF for the tunnel
  // id at table 0 and match this tunnel id at table 1. These packets are
  // forwarded to the other switch on the logical port 2.
  DpctlExecute (swtch,
                "flow-mod cmd=add,table=0,prio=1 "
                "in_port=1,eth_type=0x0800 "
                "apply:set_field=tunn_id:0xFFFF goto:1");
  DpctlExecute (swtch,
                "flow-mod cmd=add,table=1,prio=1 "
                "tunn_id=0xFFFF "
                "write:output=2");

  // IP packets entering the switch from the logical port have already been
  // de-encapsulated by the logical port operation, and the tunnel id must
  // match the arbitrary value 0xFFFF. Theses packets are forwarded to the host
  // on the physical port 1.
  DpctlExecute (swtch,
                "flow-mod cmd=add,table=0,prio=1 "
                "in_port=2,eth_type=0x0800,tunn_id=0xFFFF "
                "write:output=1");
}

ofl_err
TunnelController::HandlePacketIn (
  ofl_msg_packet_in *msg, Ptr<const RemoteSwitch> swtch, uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);
  ofl_match_tlv *tlv;

  enum ofp_packet_in_reason reason = msg->reason;
  if (reason == OFPR_NO_MATCH)
    {
      char *m = ofl_structs_match_to_string (msg->match, 0);
      NS_LOG_INFO ("Packet in match: " << m);
      free (m);

      NS_ABORT_MSG ("This packet in was not supposed to be sent to this "
                    "controller. Aborting...");
    }
  else if (reason == OFPR_ACTION)
    {
      // Get Ethernet frame type
      uint16_t ethType;
      tlv = oxm_match_lookup (OXM_OF_ETH_TYPE, (ofl_match*)msg->match);
      memcpy (&ethType, tlv->value, OXM_LENGTH (OXM_OF_ETH_TYPE));

      // Check for ARP packet
      if (ethType == ArpL3Protocol::PROT_NUMBER)
        {
          return HandleArpPacketIn (msg, swtch, xid);
        }
    }

  NS_LOG_WARN ("Ignoring packet sent to controller.");

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, 0 /*dp->exp*/);
  return 0;
}

Mac48Address
TunnelController::GetArpEntry (Ipv4Address ip)
{
  NS_LOG_FUNCTION (this << ip);

  IpMacMap_t::iterator ret;
  ret = m_arpTable.find (ip);
  if (ret != m_arpTable.end ())
    {
      NS_LOG_DEBUG ("Found ARP entry: " << ip << " - " << ret->second);
      return ret->second;
    }
  NS_FATAL_ERROR ("No ARP information for this IP.");
}

ofl_err
TunnelController::HandleArpPacketIn (
  ofl_msg_packet_in *msg, Ptr<const RemoteSwitch> swtch, uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  ofl_match_tlv *tlv;

  // Get ARP operation
  uint16_t arpOp;
  tlv = oxm_match_lookup (OXM_OF_ARP_OP, (ofl_match*)msg->match);
  memcpy (&arpOp, tlv->value, OXM_LENGTH (OXM_OF_ARP_OP));

  // Get input port
  uint32_t inPort;
  tlv = oxm_match_lookup (OXM_OF_IN_PORT, (ofl_match*)msg->match);
  memcpy (&inPort, tlv->value, OXM_LENGTH (OXM_OF_IN_PORT));

  // Check for ARP request
  if (arpOp == ArpHeader::ARP_TYPE_REQUEST)
    {
      // Get target IP address
      Ipv4Address dstIp;
      dstIp = ExtractIpv4Address (OXM_OF_ARP_TPA, (ofl_match*)msg->match);

      // Get target MAC address from ARP table
      Mac48Address dstMac = GetArpEntry (dstIp);
      NS_LOG_DEBUG ("Got ARP request for IP " << dstIp <<
                    ", resolved to " << dstMac);

      // Get source IP address
      Ipv4Address srcIp;
      srcIp = ExtractIpv4Address (OXM_OF_ARP_SPA, (ofl_match*)msg->match);

      // Get Source MAC address
      Mac48Address srcMac;
      tlv = oxm_match_lookup (OXM_OF_ARP_SHA, (ofl_match*)msg->match);
      srcMac.CopyFrom (tlv->value);

      // Create the ARP reply packet
      Ptr<Packet> pkt = CreateArpReply (dstMac, dstIp, srcMac, srcIp);
      uint8_t pktData[pkt->GetSize ()];
      pkt->CopyData (pktData, pkt->GetSize ());

      // Send the ARP reply within an OpenFlow PacketOut message
      ofl_msg_packet_out reply;
      reply.header.type = OFPT_PACKET_OUT;
      reply.buffer_id = OFP_NO_BUFFER;
      reply.in_port = inPort;
      reply.data_length = pkt->GetSize ();
      reply.data = &pktData[0];

      // Send the ARP replay back to the input port
      ofl_action_output *action;
      action = (ofl_action_output*)xmalloc (sizeof (ofl_action_output));
      action->header.type = OFPAT_OUTPUT;
      action->port = OFPP_IN_PORT;
      action->max_len = 0;

      reply.actions_num = 1;
      reply.actions = (ofl_action_header**)&action;

      int error = SendToSwitch (swtch, (ofl_msg_header*)&reply, xid);
      free (action);
      if (error)
        {
          NS_LOG_ERROR ("Error sending packet out with arp request");
        }
    }
  else
    {
      NS_LOG_WARN ("Not supposed to get ARP reply. Ignoring...");
    }

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, 0 /*dp->exp*/);
  return 0;
}

Ipv4Address
TunnelController::ExtractIpv4Address (uint32_t oxm_of, ofl_match* match)
{
  switch (oxm_of)
    {
    case OXM_OF_ARP_SPA:
    case OXM_OF_ARP_TPA:
    case OXM_OF_IPV4_DST:
    case OXM_OF_IPV4_SRC:
      {
        uint32_t ip;
        int size = OXM_LENGTH (oxm_of);
        ofl_match_tlv *tlv = oxm_match_lookup (oxm_of, match);
        memcpy (&ip, tlv->value, size);
        return Ipv4Address (ntohl (ip));
      }
    default:
      NS_FATAL_ERROR ("Invalid IP field.");
    }
}

Ptr<Packet>
TunnelController::CreateArpReply (Mac48Address srcMac, Ipv4Address srcIp,
                                  Mac48Address dstMac, Ipv4Address dstIp)
{
  NS_LOG_FUNCTION (this << srcMac << srcIp << dstMac << dstIp);

  Ptr<Packet> packet = Create<Packet> ();

  // ARP header
  ArpHeader arp;
  arp.SetReply (srcMac, srcIp, dstMac, dstIp);
  packet->AddHeader (arp);

  // Ethernet header
  EthernetHeader eth (false);
  eth.SetSource (srcMac);
  eth.SetDestination (dstMac);
  if (packet->GetSize () < 46)
    {
      uint8_t buffer[46];
      memset (buffer, 0, 46);
      Ptr<Packet> padd = Create<Packet> (buffer, 46 - packet->GetSize ());
      packet->AddAtEnd (padd);
    }
  eth.SetLengthType (ArpL3Protocol::PROT_NUMBER);
  packet->AddHeader (eth);

  // Ethernet trailer
  EthernetTrailer trailer;
  if (Node::ChecksumEnabled ())
    {
      trailer.EnableFcs (true);
    }
  trailer.CalcFcs (packet);
  packet->AddTrailer (trailer);

  return packet;
}

} // namespace ns3
