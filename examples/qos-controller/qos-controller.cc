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

  OFSwitch13Controller::DoDispose ();
  Application::DoDispose ();
}

TypeId
QosController::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QosController")
    .SetParent (OFSwitch13Controller::GetTypeId ())
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
QosController::HandlePacketIn (ofl_msg_packet_in *msg, SwitchInfo swtch, uint32_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);

  char *m = ofl_structs_match_to_string ((struct ofl_match_header*)msg->match, 0);
  NS_LOG_DEBUG ("Packet in match: " << m);
  free (m);

  if (msg->reason == OFPR_ACTION)
    {
      // Get Ethernet frame type
      uint16_t ethType;
      ofl_match_tlv *tlv = oxm_match_lookup (OXM_OF_ETH_TYPE, (ofl_match*)msg->match);
      memcpy (&ethType, tlv->value, OXM_LENGTH (OXM_OF_ETH_TYPE));

      if (ethType == ArpL3Protocol::PROT_NUMBER)
        {
          // ARP packet
          return HandleArpPacketIn (msg, swtch, xid);
        }
      else if (ethType == Ipv4L3Protocol::PROT_NUMBER)
        {
          // TCP packet (from incoming connection)
          return HandleConnectionRequest (msg, swtch, xid);
        }
    }

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, 0);
  return 0;
}

void
QosController::ConnectionStarted (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (this << swtch.ipv4);

  // This function is called after a successfully handshake between controller
  // and each switch. Let's check the switch for proper configuration.

  if (swtch.ipv4.IsEqual (Ipv4Address ("10.100.150.1")))
    {
      ConfigureBorderSwitch (swtch);
    }
  else if (swtch.ipv4.IsEqual (Ipv4Address ("10.100.150.5")))
    {
      ConfigureAggregationSwitch (swtch);
    }
}

void
QosController::ConfigureBorderSwitch (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (this << swtch.ipv4);

  // For packet-in messages, send only the first 128 bytes to the controller.
  DpctlCommand (swtch, "set-config miss=128");

  // Send ARP request to the controller when coming from the external side (ports 1 and 2)
  DpctlCommand (swtch, "flow-mod cmd=add,table=0,prio=20 "
                "in_port=1,eth_type=0x0806,arp_op=1 apply:output=ctrl");
  DpctlCommand (swtch, "flow-mod cmd=add,table=0,prio=20 "
                "in_port=2,eth_type=0x0806,arp_op=1 apply:output=ctrl");

  // Flood any other ARP packet (note the lower priority thant previous rule)
  DpctlCommand (swtch, "flow-mod cmd=add,table=0,prio=10 eth_type=0x0806 apply:output=flood");

  // Create the string with setField instructions for outputting traffic
  Mac48Address serverMac = Mac48Address::ConvertFrom (m_serverMacAddress);
  Ipv4Address serverIp = Ipv4Address::ConvertFrom (m_serverIpAddress);
  std::ostringstream setFieldExternal;
  setFieldExternal << "set_field=ip_src:" << serverIp
                   << ",set_field=eth_src:" << serverMac;

  // Using group #3 for rewriting packet headers and forwarding packets to clients
  if (m_linkAggregation)
    {
      // Configure Group #3 for aggregating links 1 and 2
      std::ostringstream groupCommand;
      groupCommand << "group-mod cmd=add,type=sel,group=3 "
                   << "weight=1,port=any,group=any " << setFieldExternal.str () << ",output=1 "
                   << "weight=1,port=any,group=any " << setFieldExternal.str () << ",output=2";
      DpctlCommand (swtch, groupCommand.str ());
    }
  else
    {
      // Configure Group #3 for sending packets only over one connection
      std::ostringstream groupCommand;
      groupCommand << "group-mod cmd=add,type=ind,group=3 "
                   << "weight=0,port=any,group=any " << setFieldExternal.str () << ",output=1";
      DpctlCommand (swtch, groupCommand.str ());
    }

  // Groups #1 and #2 are used for redirecting traffic to internal servers (ports 3 and 4)
  DpctlCommand (swtch, "group-mod cmd=add,type=ind,group=1 weight=0,port=any,group=any "
                "set_field=ip_dst:10.1.1.2,set_field=eth_dst:00:00:00:00:00:08,output=3");
  DpctlCommand (swtch, "group-mod cmd=add,type=ind,group=2 weight=0,port=any,group=any "
                "set_field=ip_dst:10.1.1.3,set_field=eth_dst:00:00:00:00:00:0a,output=4");

  // Incoming TCP connections (ports 1 and 2) are redirected to the controller
  DpctlCommand (swtch, "flow-mod cmd=add,table=0,prio=500 in_port=1,eth_type=0x0800,"
                "ip_proto=6,ip_dst=10.1.1.1,eth_dst=00:00:00:00:00:01 apply:output=ctrl");
  DpctlCommand (swtch, "flow-mod cmd=add,table=0,prio=500 in_port=2,eth_type=0x0800,"
                "ip_proto=6,ip_dst=10.1.1.1,eth_dst=00:00:00:00:00:01 apply:output=ctrl");

  // TCP packets from servers are redirected to the external network through group 3
  DpctlCommand (swtch, "flow-mod cmd=add,table=0,prio=700 "
                "in_port=3,eth_type=0x0800,ip_proto=6 apply:group=3");
  DpctlCommand (swtch, "flow-mod cmd=add,table=0,prio=700 "
                "in_port=4,eth_type=0x0800,ip_proto=6 apply:group=3");
}

void
QosController::ConfigureAggregationSwitch (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (this << swtch.ipv4);

  if (m_linkAggregation)
    {
      // Configure Group #1 for aggregating links 1 and 2
      DpctlCommand (swtch, "group-mod cmd=add,type=sel,group=1 "
                    "weight=1,port=any,group=any output=1 "
                    "weight=1,port=any,group=any output=2");
    }
  else
    {
      // Configure Group #1 for sending packets only over one connection
      DpctlCommand (swtch, "group-mod cmd=add,type=ind,group=1 "
                    "weight=0,port=any,group=any output=1");
    }

  // Packets from ports 1 and 2 are redirecte to port 3
  DpctlCommand (swtch, "flow-mod cmd=add,table=0,prio=500 in_port=1 write:output=3");
  DpctlCommand (swtch, "flow-mod cmd=add,table=0,prio=500 in_port=2 write:output=3");

  // Packets from port 3 are redirected to group 1
  DpctlCommand (swtch, "flow-mod cmd=add,table=0,prio=500 in_port=3 write:group=1");
}

ofl_err
QosController::HandleArpPacketIn (ofl_msg_packet_in *msg, SwitchInfo swtch, uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch.ipv4 << xid);

  ofl_match_tlv *tlv;

  // Get ARP operation
  uint16_t arpOp;
  tlv = oxm_match_lookup (OXM_OF_ARP_OP, (ofl_match*)msg->match);
  memcpy (&arpOp, tlv->value, OXM_LENGTH (OXM_OF_ARP_OP));

  // Check for ARP request
  if (arpOp == ArpHeader::ARP_TYPE_REQUEST)
    {
      // Get input port
      uint32_t inPort;
      tlv = oxm_match_lookup (OXM_OF_IN_PORT, (ofl_match*)msg->match);
      memcpy (&inPort, tlv->value, OXM_LENGTH (OXM_OF_IN_PORT));

      // Get source and  target IP address
      Ipv4Address srcIp, dstIp;
      srcIp = ExtractIpv4Address (OXM_OF_ARP_SPA, (ofl_match*)msg->match);
      dstIp = ExtractIpv4Address (OXM_OF_ARP_TPA, (ofl_match*)msg->match);

      // Get Source MAC address
      Mac48Address srcMac;
      tlv = oxm_match_lookup (OXM_OF_ARP_SHA, (ofl_match*)msg->match);
      srcMac.CopyFrom (tlv->value);

      // Create the ARP reply packet
      Mac48Address serverMac = Mac48Address::ConvertFrom (m_serverMacAddress);
      Ptr<Packet> pkt = CreateArpReply (serverMac, dstIp, srcMac, srcIp);
      uint8_t pktData[pkt->GetSize ()];
      pkt->CopyData (pktData, pkt->GetSize ());

      // Send the ARP replay back to the input port
      ofl_action_output *action;
      action = (ofl_action_output*)xmalloc (sizeof (ofl_action_output));
      action->header.type = OFPAT_OUTPUT;
      action->port = OFPP_IN_PORT;
      action->max_len = 0;

      // Send the ARP reply within an OpenFlow PacketOut message
      ofl_msg_packet_out reply;
      reply.header.type = OFPT_PACKET_OUT;
      reply.buffer_id = OFP_NO_BUFFER;
      reply.in_port = inPort;
      reply.data_length = pkt->GetSize ();
      reply.data = &pktData[0];
      reply.actions_num = 1;
      reply.actions = (ofl_action_header**)&action;

      SendToSwitch (&swtch, (ofl_msg_header*)&reply, xid);
      free (action);
    }
  else
    {
      NS_LOG_WARN ("Not supposed to get ARP reply. Ignoring...");
    }

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, 0 /*dp->exp*/);
  return 0;
}

ofl_err
QosController::HandleConnectionRequest (ofl_msg_packet_in *msg, SwitchInfo swtch, uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch.ipv4 << xid);

  static uint32_t connectionCounter = 0;
  connectionCounter++;

  ofl_match_tlv *tlv;
  Ipv4Address serverAddr = Ipv4Address::ConvertFrom (m_serverIpAddress);

  // Get input port
  uint32_t inPort;
  tlv = oxm_match_lookup (OXM_OF_IN_PORT, (ofl_match*)msg->match);
  memcpy (&inPort, tlv->value, OXM_LENGTH (OXM_OF_IN_PORT));

  // Get source and destination IP address
  Ipv4Address srcIp, dstIp;
  srcIp = ExtractIpv4Address (OXM_OF_IPV4_SRC, (ofl_match*)msg->match);
  dstIp = ExtractIpv4Address (OXM_OF_IPV4_DST, (ofl_match*)msg->match);

  // Get source and destination TCP ports
  uint16_t srcPort, dstPort;
  tlv = oxm_match_lookup (OXM_OF_TCP_SRC, (ofl_match*)msg->match);
  memcpy (&srcPort, tlv->value, OXM_LENGTH (OXM_OF_TCP_SRC));
  tlv = oxm_match_lookup (OXM_OF_TCP_DST, (ofl_match*)msg->match);
  memcpy (&dstPort, tlv->value, OXM_LENGTH (OXM_OF_TCP_DST));

  // Check for valid connection request
  NS_ASSERT_MSG (dstIp.IsEqual (serverAddr) && dstPort == m_serverTcpPort,
                 "Invalid IP address / MAC port.");

  // Select an internal server to handle this connection
  uint16_t serverNumber = 1 + (connectionCounter % 2);
  NS_LOG_INFO ("Connection redirected to server " << serverNumber);

  // If enable, install metter entry
  if (m_meterEnable)
    {
      std::ostringstream meterCmd;
      meterCmd << "meter-mod cmd=add,flags=1,meter=" << connectionCounter
               << " drop:rate=" << m_meterRate.GetBitRate () / 1000;
      DpctlCommand (swtch, meterCmd.str ());
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
  DpctlCommand (swtch, flowCmd.str ());

  // Create group action with server number
  ofl_action_group *action = (ofl_action_group*)xmalloc (sizeof (struct ofl_action_group));
  action->header.type = OFPAT_GROUP;
  action->group_id = serverNumber;

  // Send the packet out to the switch.
  ofl_msg_packet_out reply;
  reply.header.type = OFPT_PACKET_OUT;
  reply.buffer_id = msg->buffer_id;
  reply.in_port = inPort;
  reply.actions_num = 1;
  reply.actions = (ofl_action_header**)&action;
  reply.data_length = 0;
  reply.data = 0;
  if (msg->buffer_id == NO_BUFFER)
    {
      // No packet buffer. Send data back to switch
      reply.data_length = msg->data_length;
      reply.data = msg->data;
    }

  SendToSwitch (&swtch, (ofl_msg_header*)&reply, xid);
  free (action);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, 0 /*dp->exp*/);
  return 0;
}

Ipv4Address
QosController::ExtractIpv4Address (uint32_t oxm_of, ofl_match* match)
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

