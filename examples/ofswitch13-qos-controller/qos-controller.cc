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
 * Author:  Luciano Chaves <luciano@lrc.ic.unicamp.br>
 */

#include "qos-controller.h"
#include <ns3/network-module.h>
#include <ns3/internet-module.h>

NS_LOG_COMPONENT_DEFINE ("QosController");
NS_OBJECT_ENSURE_REGISTERED (QosController);

QosController::QosController ()
{
  NS_LOG_FUNCTION (this);
}

QosController::~QosController ()
{
  NS_LOG_FUNCTION (this);
}

void
QosController::DoDispose ()
{
  NS_LOG_FUNCTION (this);

  m_arpTable.clear ();
  OFSwitch13Controller::DoDispose ();
}

TypeId
QosController::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QosController")
    .SetParent<OFSwitch13Controller> ()
    .SetGroupName ("OFSwitch13")
    .AddConstructor<QosController> ()
    .AddAttribute ("EnableMeter",
                   "Enable per-flow mettering.",
                   BooleanValue (false),
                   MakeBooleanAccessor (&QosController::m_meterEnable),
                   MakeBooleanChecker ())
    .AddAttribute ("MeterRate",
                   "Per-flow meter rate.",
                   DataRateValue (DataRate ("256Kbps")),
                   MakeDataRateAccessor (&QosController::m_meterRate),
                   MakeDataRateChecker ())
    .AddAttribute ("LinkAggregation",
                   "Enable link aggregation.",
                   BooleanValue (true),
                   MakeBooleanAccessor (&QosController::m_linkAggregation),
                   MakeBooleanChecker ())
    .AddAttribute ("ServerIpAddr",
                   "Server IPv4 address.",
                   AddressValue (Address (Ipv4Address ("10.1.1.1"))),
                   MakeAddressAccessor (&QosController::m_serverIpAddress),
                   MakeAddressChecker ())
    .AddAttribute ("ServerTcpPort",
                   "Server TCP port.",
                   UintegerValue (9),
                   MakeUintegerAccessor (&QosController::m_serverTcpPort),
                   MakeUintegerChecker<uint64_t> ())
    .AddAttribute ("ServerMacAddr",
                   "Server MAC address.",
                   AddressValue (Address (Mac48Address ("00:00:00:00:00:01"))),
                   MakeAddressAccessor (&QosController::m_serverMacAddress),
                   MakeAddressChecker ())
  ;
  return tid;
}

ofl_err
QosController::HandlePacketIn (
  struct ofl_msg_packet_in *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  char *msgStr =
    ofl_structs_match_to_string ((struct ofl_match_header*)msg->match, 0);
  NS_LOG_DEBUG ("Packet in match: " << msgStr);
  free (msgStr);

  if (msg->reason == OFPR_ACTION)
    {
      // Get Ethernet frame type
      uint16_t ethType;
      struct ofl_match_tlv *tlv;
      tlv = oxm_match_lookup (OXM_OF_ETH_TYPE, (struct ofl_match*)msg->match);
      memcpy (&ethType, tlv->value, OXM_LENGTH (OXM_OF_ETH_TYPE));

      if (ethType == ArpL3Protocol::PROT_NUMBER)
        {
          // ARP packet
          return HandleArpPacketIn (msg, swtch, xid);
        }
      else if (ethType == Ipv4L3Protocol::PROT_NUMBER)
        {
          // Must be a TCP packet for connection request
          return HandleConnectionRequest (msg, swtch, xid);
        }
    }

  // All handlers must free the message when everything is ok
  ofl_msg_free ((struct ofl_msg_header*)msg, 0);
  return 0;
}

void
QosController::HandshakeSuccessful (Ptr<const RemoteSwitch> swtch)
{
  NS_LOG_FUNCTION (this << swtch);

  // This function is called after a successfully handshake between controller
  // and each switch. Let's check the switch for proper configuration.
  if (swtch->GetDpId () == 1)
    {
      ConfigureBorderSwitch (swtch);
    }
  else if (swtch->GetDpId () == 2)
    {
      ConfigureAggregationSwitch (swtch);
    }
}

void
QosController::ConfigureBorderSwitch (Ptr<const RemoteSwitch> swtch)
{
  NS_LOG_FUNCTION (this << swtch);

  // For packet-in messages, send only the first 128 bytes to the controller
  DpctlExecute (swtch, "set-config miss=128");

  // Redirect ARP requests to the controller
  DpctlExecute (swtch, "flow-mod cmd=add,table=0,prio=20 "
                "eth_type=0x0806,arp_op=1 apply:output=ctrl");

  // Using group #3 for rewriting headers and forwarding packets to clients
  if (m_linkAggregation)
    {
      // Configure Group #3 for aggregating links 1 and 2
      DpctlExecute (swtch, "group-mod cmd=add,type=sel,group=3 "
                    "weight=1,port=any,group=any set_field=ip_src:10.1.1.1"
                    ",set_field=eth_src:00:00:00:00:00:01,output=1 "
                    "weight=1,port=any,group=any set_field=ip_src:10.1.1.1"
                    ",set_field=eth_src:00:00:00:00:00:01,output=2");
    }
  else
    {
      // Configure Group #3 for sending packets only over link 1
      DpctlExecute (swtch, "group-mod cmd=add,type=ind,group=3 "
                    "weight=0,port=any,group=any set_field=ip_src:10.1.1.1"
                    ",set_field=eth_src:00:00:00:00:00:01,output=1");
    }

  // Groups #1 and #2 send traffic to internal servers (ports 3 and 4)
  DpctlExecute (swtch, "group-mod cmd=add,type=ind,group=1 "
                "weight=0,port=any,group=any set_field=ip_dst:10.1.1.2,"
                "set_field=eth_dst:00:00:00:00:00:08,output=3");
  DpctlExecute (swtch, "group-mod cmd=add,type=ind,group=2 "
                "weight=0,port=any,group=any set_field=ip_dst:10.1.1.3,"
                "set_field=eth_dst:00:00:00:00:00:0a,output=4");

  // Incoming TCP connections (ports 1 and 2) are sent to the controller
  DpctlExecute (swtch, "flow-mod cmd=add,table=0,prio=500 "
                "in_port=1,eth_type=0x0800,ip_proto=6,ip_dst=10.1.1.1,"
                "eth_dst=00:00:00:00:00:01 apply:output=ctrl");
  DpctlExecute (swtch, "flow-mod cmd=add,table=0,prio=500 "
                "in_port=2,eth_type=0x0800,ip_proto=6,ip_dst=10.1.1.1,"
                "eth_dst=00:00:00:00:00:01 apply:output=ctrl");

  // TCP packets from servers are sent to the external network through group 3
  DpctlExecute (swtch, "flow-mod cmd=add,table=0,prio=700 "
                "in_port=3,eth_type=0x0800,ip_proto=6 apply:group=3");
  DpctlExecute (swtch, "flow-mod cmd=add,table=0,prio=700 "
                "in_port=4,eth_type=0x0800,ip_proto=6 apply:group=3");
}

void
QosController::ConfigureAggregationSwitch (Ptr<const RemoteSwitch> swtch)
{
  NS_LOG_FUNCTION (this << swtch);

  if (m_linkAggregation)
    {
      // Configure Group #1 for aggregating links 1 and 2
      DpctlExecute (swtch, "group-mod cmd=add,type=sel,group=1 "
                    "weight=1,port=any,group=any output=1 "
                    "weight=1,port=any,group=any output=2");
    }
  else
    {
      // Configure Group #1 for sending packets only over link 1
      DpctlExecute (swtch, "group-mod cmd=add,type=ind,group=1 "
                    "weight=0,port=any,group=any output=1");
    }

  // Packets from input ports 1 and 2 are redirecte to port 3
  DpctlExecute (swtch, "flow-mod cmd=add,table=0,prio=500 "
                "in_port=1 write:output=3");
  DpctlExecute (swtch, "flow-mod cmd=add,table=0,prio=500 "
                "in_port=2 write:output=3");

  // Packets from input port 3 are redirected to group 1
  DpctlExecute (swtch, "flow-mod cmd=add,table=0,prio=500 "
                "in_port=3 write:group=1");
}

ofl_err
QosController::HandleArpPacketIn (
  struct ofl_msg_packet_in *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  struct ofl_match_tlv *tlv;
  Ipv4Address serverIp = Ipv4Address::ConvertFrom (m_serverIpAddress);
  Mac48Address serverMac = Mac48Address::ConvertFrom (m_serverMacAddress);

  // Get ARP operation
  uint16_t arpOp;
  tlv = oxm_match_lookup (OXM_OF_ARP_OP, (struct ofl_match*)msg->match);
  memcpy (&arpOp, tlv->value, OXM_LENGTH (OXM_OF_ARP_OP));

  // Get input port
  uint32_t inPort;
  tlv = oxm_match_lookup (OXM_OF_IN_PORT, (struct ofl_match*)msg->match);
  memcpy (&inPort, tlv->value, OXM_LENGTH (OXM_OF_IN_PORT));

  // Get source and target IP address
  Ipv4Address srcIp, dstIp;
  srcIp = ExtractIpv4Address (OXM_OF_ARP_SPA, (struct ofl_match*)msg->match);
  dstIp = ExtractIpv4Address (OXM_OF_ARP_TPA, (struct ofl_match*)msg->match);

  // Get Source MAC address
  Mac48Address srcMac, dstMac;
  tlv = oxm_match_lookup (OXM_OF_ARP_SHA, (struct ofl_match*)msg->match);
  srcMac.CopyFrom (tlv->value);
  tlv = oxm_match_lookup (OXM_OF_ARP_THA, (struct ofl_match*)msg->match);
  dstMac.CopyFrom (tlv->value);

  // Check for ARP request
  if (arpOp == ArpHeader::ARP_TYPE_REQUEST)
    {
      uint8_t replyData[64];

      // Check for destination IP
      if (dstIp.IsEqual (serverIp))
        {
          // Reply with virtual service IP/MAC addresses
          Ptr<Packet> pkt = CreateArpReply (serverMac, dstIp, srcMac, srcIp);
          NS_ASSERT_MSG (pkt->GetSize () == 64, "Invalid packet size.");
          pkt->CopyData (replyData, 64);
        }
      else
        {
          // Check for existing information
          Mac48Address replyMac = GetArpEntry (dstIp);
          Ptr<Packet> pkt = CreateArpReply (replyMac, dstIp, srcMac, srcIp);
          NS_ASSERT_MSG (pkt->GetSize () == 64, "Invalid packet size.");
          pkt->CopyData (replyData, 64);
        }

      // Send the ARP replay back to the input port
      struct ofl_action_output *action =
        (struct ofl_action_output*)xmalloc (sizeof (struct ofl_action_output));
      action->header.type = OFPAT_OUTPUT;
      action->port = OFPP_IN_PORT;
      action->max_len = 0;

      // Send the ARP reply within an OpenFlow PacketOut message
      struct ofl_msg_packet_out reply;
      reply.header.type = OFPT_PACKET_OUT;
      reply.buffer_id = OFP_NO_BUFFER;
      reply.in_port = inPort;
      reply.data_length = 64;
      reply.data = &replyData[0];
      reply.actions_num = 1;
      reply.actions = (struct ofl_action_header**)&action;

      SendToSwitch (swtch, (struct ofl_msg_header*)&reply, xid);
      free (action);
    }

  // All handlers must free the message when everything is ok
  ofl_msg_free ((struct ofl_msg_header*)msg, 0);
  return 0;
}

ofl_err
QosController::HandleConnectionRequest (
  struct ofl_msg_packet_in *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  static uint32_t connectionCounter = 0;
  connectionCounter++;

  struct ofl_match_tlv *tlv;
  Ipv4Address serverIp = Ipv4Address::ConvertFrom (m_serverIpAddress);
  Mac48Address serverMac = Mac48Address::ConvertFrom (m_serverMacAddress);

  // Get input port
  uint32_t inPort;
  tlv = oxm_match_lookup (OXM_OF_IN_PORT, (struct ofl_match*)msg->match);
  memcpy (&inPort, tlv->value, OXM_LENGTH (OXM_OF_IN_PORT));

  // Get Source MAC address
  Mac48Address srcMac;
  tlv = oxm_match_lookup (OXM_OF_ETH_SRC, (struct ofl_match*)msg->match);
  srcMac.CopyFrom (tlv->value);

  // Get source and destination IP address
  Ipv4Address srcIp, dstIp;
  srcIp = ExtractIpv4Address (OXM_OF_IPV4_SRC, (struct ofl_match*)msg->match);
  dstIp = ExtractIpv4Address (OXM_OF_IPV4_DST, (struct ofl_match*)msg->match);

  // Get source and destination TCP ports
  uint16_t srcPort, dstPort;
  tlv = oxm_match_lookup (OXM_OF_TCP_SRC, (struct ofl_match*)msg->match);
  memcpy (&srcPort, tlv->value, OXM_LENGTH (OXM_OF_TCP_SRC));
  tlv = oxm_match_lookup (OXM_OF_TCP_DST, (struct ofl_match*)msg->match);
  memcpy (&dstPort, tlv->value, OXM_LENGTH (OXM_OF_TCP_DST));

  // Create an ARP request for further address resolution
  SaveArpEntry (srcIp, srcMac);
  uint8_t replyData[64];
  Ptr<Packet> pkt = CreateArpRequest (serverMac, serverIp, srcIp);
  NS_ASSERT_MSG (pkt->GetSize () == 64, "Invalid packet size.");
  pkt->CopyData (replyData, 64);

  struct ofl_action_output *arpAction =
    (struct ofl_action_output*)xmalloc (sizeof (struct ofl_action_output));
  arpAction->header.type = OFPAT_OUTPUT;
  arpAction->port = OFPP_IN_PORT;
  arpAction->max_len = 0;

  // Send the ARP request within an OpenFlow PacketOut message
  struct ofl_msg_packet_out arpRequest;
  arpRequest.header.type = OFPT_PACKET_OUT;
  arpRequest.buffer_id = OFP_NO_BUFFER;
  arpRequest.in_port = inPort;
  arpRequest.data_length = 64;
  arpRequest.data = &replyData[0];
  arpRequest.actions_num = 1;
  arpRequest.actions = (struct ofl_action_header**)&arpAction;

  SendToSwitch (swtch, (struct ofl_msg_header*)&arpRequest, 0);
  free (arpAction);

  // Check for valid service connection request
  NS_ASSERT_MSG (dstIp.IsEqual (serverIp) && dstPort == m_serverTcpPort,
                 "Invalid IP address / TCP port.");

  // Select an internal server to handle this connection
  uint16_t serverNumber = 1 + (connectionCounter % 2);
  NS_LOG_INFO ("Connection " << connectionCounter <<
               " redirected to server " << serverNumber);

  // If enable, install the metter entry for this connection
  if (m_meterEnable)
    {
      std::ostringstream meterCmd;
      meterCmd << "meter-mod cmd=add,flags=1,meter=" << connectionCounter
               << " drop:rate=" << m_meterRate.GetBitRate () / 1000;
      DpctlExecute (swtch, meterCmd.str ());
    }

  // Install the flow entry for this TCP connection
  std::ostringstream flowCmd;
  flowCmd << "flow-mod cmd=add,table=0,prio=1000 eth_type=0x0800,ip_proto=6"
          << ",ip_src=" << srcIp
          << "ip_dst=" << m_serverIpAddress
          << ",tcp_dst=" << m_serverTcpPort
          << ",tcp_src=" << srcPort;
  if (m_meterEnable)
    {
      flowCmd << " meter:" << connectionCounter;
    }
  flowCmd << " write:group=" << serverNumber;
  DpctlExecute (swtch, flowCmd.str ());

  // Create group action with server number
  struct ofl_action_group *action =
    (struct ofl_action_group*)xmalloc (sizeof (struct ofl_action_group));
  action->header.type = OFPAT_GROUP;
  action->group_id = serverNumber;

  // Send the packet out to the switch.
  struct ofl_msg_packet_out reply;
  reply.header.type = OFPT_PACKET_OUT;
  reply.buffer_id = msg->buffer_id;
  reply.in_port = inPort;
  reply.actions_num = 1;
  reply.actions = (struct ofl_action_header**)&action;
  reply.data_length = 0;
  reply.data = 0;
  if (msg->buffer_id == NO_BUFFER)
    {
      // No packet buffer. Send data back to switch
      reply.data_length = msg->data_length;
      reply.data = msg->data;
    }

  SendToSwitch (swtch, (struct ofl_msg_header*)&reply, xid);
  free (action);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((struct ofl_msg_header*)msg, 0);
  return 0;
}

Ipv4Address
QosController::ExtractIpv4Address (uint32_t oxm_of, struct ofl_match* match)
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
QosController::CreateArpRequest (Mac48Address srcMac, Ipv4Address srcIp,
                                 Ipv4Address dstIp)
{
  NS_LOG_FUNCTION (this << srcMac << srcIp << dstIp);

  Ptr<Packet> packet = Create<Packet> ();

  // ARP header
  ArpHeader arp;
  arp.SetRequest (srcMac, srcIp, Mac48Address::GetBroadcast (), dstIp);
  packet->AddHeader (arp);

  // Ethernet header
  EthernetHeader eth (false);
  eth.SetSource (srcMac);
  eth.SetDestination (Mac48Address::GetBroadcast ());
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

Ptr<Packet>
QosController::CreateArpReply (Mac48Address srcMac, Ipv4Address srcIp,
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

void
QosController::SaveArpEntry (Ipv4Address ipAddr, Mac48Address macAddr)
{
  std::pair<Ipv4Address, Mac48Address> entry (ipAddr, macAddr);
  std::pair <IpMacMap_t::iterator, bool> ret;
  ret = m_arpTable.insert (entry);
  if (ret.second == true)
    {
      NS_LOG_INFO ("New ARP entry: " << ipAddr << " - " << macAddr);
      return;
    }
}

Mac48Address
QosController::GetArpEntry (Ipv4Address ip)
{
  IpMacMap_t::iterator ret;
  ret = m_arpTable.find (ip);
  if (ret != m_arpTable.end ())
    {
      NS_LOG_INFO ("Found ARP entry: " << ip << " - " << ret->second);
      return ret->second;
    }
  NS_ABORT_MSG ("No ARP information for this IP.");
}

