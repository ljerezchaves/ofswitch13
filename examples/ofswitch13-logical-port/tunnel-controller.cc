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
    .AddConstructor<TunnelController> ()
  ;
  return tid;
}

void
TunnelController::SaveArpEntry (Ipv4Address ipAddr, Mac48Address macAddr)
{
  NS_LOG_FUNCTION (this << ipAddr << macAddr);

  std::pair<Ipv4Address, Mac48Address> entry (ipAddr, macAddr);
  std::pair<IpMacMap_t::iterator, bool> ret;
  ret = m_arpTable.insert (entry);
  if (ret.second == true)
    {
      NS_LOG_INFO ("New ARP entry: " << ipAddr << " - " << macAddr);
      return;
    }
  NS_ABORT_MSG ("This IP already exists in ARP table.");
}

void
TunnelController::SaveTunnelEndpoint (uint64_t dpId, uint32_t portNo,
                                      Ipv4Address ipAddr)
{
  NS_LOG_FUNCTION (this << dpId << portNo << ipAddr);

  DpPortPair_t key (dpId, portNo);
  std::pair<DpPortPair_t, Ipv4Address> entry (key, ipAddr);
  std::pair<DpPortIpMap_t::iterator, bool> ret;
  ret = m_endpointTable.insert (entry);
  if (ret.second == true)
    {
      NS_LOG_INFO ("New endpoint entry: " << dpId << "/" << portNo <<
                   " - " << ipAddr);
      return;
    }
  NS_ABORT_MSG ("This endpoint already exists in tunnel endpoint table.");
}

void
TunnelController::DoDispose ()
{
  NS_LOG_FUNCTION (this);

  m_arpTable.clear ();
  m_endpointTable.clear ();
  OFSwitch13Controller::DoDispose ();
}

void
TunnelController::HandshakeSuccessful (Ptr<const RemoteSwitch> swtch)
{
  NS_LOG_FUNCTION (this << swtch);

  // Send ARP requests to controller.
  DpctlExecute (swtch, "flow-mod cmd=add,table=0,prio=16 eth_type=0x0806 "
                "apply:output=ctrl");

  // Table miss entry.
  DpctlExecute (swtch, "flow-mod cmd=add,table=0,prio=0 apply:output=ctrl");
}

ofl_err
TunnelController::HandlePacketIn (
  struct ofl_msg_packet_in *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  struct ofl_match_tlv *tlv;
  enum ofp_packet_in_reason reason = msg->reason;
  if (reason == OFPR_NO_MATCH)
    {
      char *msgStr = ofl_structs_match_to_string (msg->match, 0);
      NS_LOG_INFO ("Packet in match: " << msgStr);
      free (msgStr);

      // Get input port
      uint32_t inPort;
      tlv = oxm_match_lookup (OXM_OF_IN_PORT, (struct ofl_match*)msg->match);
      memcpy (&inPort, tlv->value, OXM_LENGTH (OXM_OF_IN_PORT));

      if (inPort == 1)
        {
          // IP packets entering the switch from the physical port 1 are coming
          // from the host node. In this case, identify and set TEID and tunnel
          // endpoint IPv4 address into tunnel metadata, and output the packet
          // on the logical port 2.
          Ipv4Address dstAddr = GetTunnelEndpoint (swtch->GetDpId (), 2);
          uint64_t tunnelId = (uint64_t)dstAddr.Get () << 32;
          tunnelId |= 0xFFFF;
          char tunnelIdStr [20];
          sprintf (tunnelIdStr, "0x%016lX", tunnelId);

          std::ostringstream cmd;
          cmd << "flow-mod cmd=add,table=0,prio=11,buffer=" << msg->buffer_id
              << " in_port=1,eth_type=0x0800 "
              << "write:set_field=tunn_id:" << tunnelIdStr
              << ",output=2";
          DpctlExecute (swtch, cmd.str ());

          // All handlers must free the message when everything is ok
          ofl_msg_free ((struct ofl_msg_header*)msg, 0);
          return 0;
        }
      else if (inPort == 2)
        {
          // IP packets entering the switch from the logical port have already
          // been de-encapsulated by the logical port operation, and the tunnel
          // id must match the arbitrary value 0xFFFF defined set above. Theses
          // packets must be forwarded to the host on the physical port 1. In
          // this case, the OpenFlow switch is acting as a router, and we need
          // to set the host destination MAC addresses. Note that the packet
          // leaving the OpenFlow pipeline will not be sent to the IP layer, so
          // no ARP resolution is available and we need to do it manually here.
          Ipv4Address dstIp = ExtractIpv4Address (
              OXM_OF_IPV4_DST, (struct ofl_match*)msg->match);
          Mac48Address dstMac = GetArpEntry (dstIp);

          std::ostringstream cmd;
          cmd << "flow-mod cmd=add,table=0,prio=10,buffer=" << msg->buffer_id
              << " in_port=2,eth_type=0x0800,tunn_id=0xFFFF "
              << "write:set_field=eth_dst:" << dstMac
              << ",output=1";
          DpctlExecute (swtch, cmd.str ());

          // All handlers must free the message when everything is ok
          ofl_msg_free ((struct ofl_msg_header*)msg, 0);
          return 0;
        }

      NS_LOG_ERROR ("This packet in was not supposed to be sent here.");
    }
  else if (reason == OFPR_ACTION)
    {
      // Get Ethernet frame type
      uint16_t ethType;
      tlv = oxm_match_lookup (OXM_OF_ETH_TYPE, (struct ofl_match*)msg->match);
      memcpy (&ethType, tlv->value, OXM_LENGTH (OXM_OF_ETH_TYPE));

      // Check for ARP packet
      if (ethType == ArpL3Protocol::PROT_NUMBER)
        {
          return HandleArpPacketIn (msg, swtch, xid);
        }
    }

  NS_LOG_WARN ("Ignoring packet sent to controller.");

  // All handlers must free the message when everything is ok
  ofl_msg_free ((struct ofl_msg_header*)msg, 0);
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
      NS_LOG_INFO ("Found ARP entry: " << ip << " - " << ret->second);
      return ret->second;
    }
  NS_ABORT_MSG ("No ARP information for this IP.");
}

Ipv4Address
TunnelController::GetTunnelEndpoint (uint64_t dpId, uint32_t portNo)
{
  NS_LOG_FUNCTION (this << dpId << portNo);

  DpPortPair_t key (dpId, portNo);
  DpPortIpMap_t::iterator ret;
  ret = m_endpointTable.find (key);
  if (ret != m_endpointTable.end ())
    {
      NS_LOG_INFO ("Found endpoint entry: " << dpId << "/" << portNo <<
                   " - " << ret->second);
      return ret->second;
    }
  NS_ABORT_MSG ("No tunnel endpoint information for this datapath + port.");
}

ofl_err
TunnelController::HandleArpPacketIn (
  struct ofl_msg_packet_in *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  struct ofl_match_tlv *tlv;

  // Get ARP operation
  uint16_t arpOp;
  tlv = oxm_match_lookup (OXM_OF_ARP_OP, (struct ofl_match*)msg->match);
  memcpy (&arpOp, tlv->value, OXM_LENGTH (OXM_OF_ARP_OP));

  // Get input port
  uint32_t inPort;
  tlv = oxm_match_lookup (OXM_OF_IN_PORT, (struct ofl_match*)msg->match);
  memcpy (&inPort, tlv->value, OXM_LENGTH (OXM_OF_IN_PORT));

  // Check for ARP request
  if (arpOp == ArpHeader::ARP_TYPE_REQUEST)
    {
      // Get target IP address
      Ipv4Address dstIp = ExtractIpv4Address (
          OXM_OF_ARP_TPA, (struct ofl_match*)msg->match);

      // Get target MAC address from ARP table
      Mac48Address dstMac = GetArpEntry (dstIp);
      NS_LOG_INFO ("Got ARP request for IP " << dstIp <<
                   ", resolved to " << dstMac);

      // Get source IP address
      Ipv4Address srcIp;
      srcIp = ExtractIpv4Address (
          OXM_OF_ARP_SPA, (struct ofl_match*)msg->match);

      // Get Source MAC address
      Mac48Address srcMac;
      tlv = oxm_match_lookup (OXM_OF_ARP_SHA, (struct ofl_match*)msg->match);
      srcMac.CopyFrom (tlv->value);

      // Create the ARP reply packet
      Ptr<Packet> pkt = CreateArpReply (dstMac, dstIp, srcMac, srcIp);
      uint8_t pktData[pkt->GetSize ()];
      pkt->CopyData (pktData, pkt->GetSize ());

      // Send the ARP reply within an OpenFlow PacketOut message
      struct ofl_msg_packet_out reply;
      reply.header.type = OFPT_PACKET_OUT;
      reply.buffer_id = OFP_NO_BUFFER;
      reply.in_port = inPort;
      reply.data_length = pkt->GetSize ();
      reply.data = &pktData[0];

      // Send the ARP replay back to the input port
      struct ofl_action_output *action =
        (struct ofl_action_output*)xmalloc (sizeof (struct ofl_action_output));
      action->header.type = OFPAT_OUTPUT;
      action->port = OFPP_IN_PORT;
      action->max_len = 0;

      reply.actions_num = 1;
      reply.actions = (struct ofl_action_header**)&action;

      int error = SendToSwitch (swtch, (struct ofl_msg_header*)&reply, xid);
      free (action);
      if (error)
        {
          NS_LOG_ERROR ("Error sending packet out with ARP request.");
        }
    }
  else
    {
      NS_LOG_WARN ("Not supposed to get ARP reply. Ignoring...");
    }

  // All handlers must free the message when everything is ok
  ofl_msg_free ((struct ofl_msg_header*)msg, 0);
  return 0;
}

Ipv4Address
TunnelController::ExtractIpv4Address (uint32_t oxm_of, struct ofl_match* match)
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
        struct ofl_match_tlv *tlv = oxm_match_lookup (oxm_of, match);
        memcpy (&ip, tlv->value, size);
        return Ipv4Address (ntohl (ip));
      }
    default:
      NS_ABORT_MSG ("Invalid IP field.");
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
