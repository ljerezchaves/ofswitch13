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

#include <wordexp.h>
#include "ns3/uinteger.h"
#include "ofswitch13-controller.h"
#include "ofswitch13-net-device.h"

namespace ns3 {

OFSwitch13Controller::EchoInfo::EchoInfo (Ipv4Address ip)
{
  waiting = true;
  send = Simulator::Now ();
  destIp = ip;
}

Time
OFSwitch13Controller::EchoInfo::GetRtt ()
{
  if (waiting)
    {
      return Time (-1);
    }
  else
    {
      Time rtt = recv - send;
      return recv - send;
    }
}

InetSocketAddress
SwitchInfo::GetInet ()
{
  return InetSocketAddress (ipv4, port);
}

/********** Public methods ***********/
NS_LOG_COMPONENT_DEFINE ("OFSwitch13Controller");
NS_OBJECT_ENSURE_REGISTERED (OFSwitch13Controller);

OFSwitch13Controller::OFSwitch13Controller ()
  : m_port (6653)
{
  NS_LOG_FUNCTION (this);
  m_serverSocket = 0;
  m_xid = rand () & 0xffffffff;
}

OFSwitch13Controller::~OFSwitch13Controller ()
{
  NS_LOG_FUNCTION (this);
}

TypeId
OFSwitch13Controller::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OFSwitch13Controller")
    .SetParent<Object> ()
    .SetGroupName ("OFSwitch13")
    .AddAttribute ("Port",
                   "Port on which we listen for incoming packets.",
                   TypeId::ATTR_GET,
                   UintegerValue (0),
                   MakeUintegerAccessor (&OFSwitch13Controller::m_port),
                   MakeUintegerChecker<uint16_t> ())
  ;
  return tid;
}

void
OFSwitch13Controller::DoDispose ()
{
  m_serverSocket = 0;
  m_switchesMap.clear ();
  m_echoMap.clear ();
  m_schedCommands.clear ();

  Application::DoDispose ();
}

void
OFSwitch13Controller::RegisterSwitchMetadata (SwitchInfo swInfo)
{
  NS_LOG_FUNCTION (swInfo.ipv4);

  std::pair <SwitchsMap_t::iterator, bool> ret;
  ret =  m_switchesMap.insert (
      std::pair<Ipv4Address, SwitchInfo> (swInfo.ipv4, swInfo));
  if (ret.second == false)
    {
      NS_LOG_ERROR ("This switch is already registered with this controller");
    }
}

SwitchInfo
OFSwitch13Controller::GetSwitchMetadata (Ptr<OFSwitch13NetDevice> dev)
{
  NS_LOG_FUNCTION (dev);

  SwitchsMap_t::iterator it;
  for (it = m_switchesMap.begin (); it != m_switchesMap.end (); it++)
    {
      if (it->second.netdev == dev)
        {
          return it->second;
        }
    }
  return SwitchInfo ();
}

int
OFSwitch13Controller::DpctlCommand (SwitchInfo swtch, const std::string textCmd)
{
  // If no TCP connection, schedule the command for further execution
  if (swtch.socket == NULL)
    {
      ScheduleCommand (swtch, textCmd);
      return -1;
    }

  int error = 0;
  char **argv;
  size_t argc;

  wordexp_t cmd;
  wordexp (textCmd.c_str (), &cmd, 0);
  argv = cmd.we_wordv;
  argc = cmd.we_wordc;

  if (!strcmp (argv[0], "set-table-match") || !strcmp (argv[0], "ping"))
    {
      NS_LOG_WARN ("Dpctl command currently not supported.");
    }
  else
    {
      return dpctl_exec_ns3_command ((void*)&swtch, argc, argv);
    }

  wordfree (&cmd);
  return error;
}

int
OFSwitch13Controller::DpctlCommand (Ptr<OFSwitch13NetDevice> swtch,
                                    const std::string textCmd)
{
  return DpctlCommand (GetSwitchMetadata (swtch), textCmd);
}

void
OFSwitch13Controller::DpctlSendAndPrint (vconn *swtch, ofl_msg_header *msg)
{
  NS_LOG_FUNCTION_NOARGS ();

  SwitchInfo *sw = (SwitchInfo*)swtch;
  sw->ctrl->SendToSwitch (sw, msg, 0);
}

/********* Protected methods *********/
void
OFSwitch13Controller::StartApplication ()
{
  NS_LOG_FUNCTION (this << "Starting Controller application at port " << m_port);

  // Create the server listening socket
  if (!m_serverSocket)
    {
      m_serverSocket = Socket::CreateSocket (GetNode (),
                                             TcpSocketFactory::GetTypeId ());
      m_serverSocket->SetAttribute ("SegmentSize", UintegerValue (8900));
      m_serverSocket->Bind (InetSocketAddress (Ipv4Address::GetAny (), m_port));
      m_serverSocket->Listen ();
    }

  // Setting socket callbacks
  m_serverSocket->SetRecvCallback (
    MakeCallback (&OFSwitch13Controller::SocketRead, this));
  m_serverSocket->SetAcceptCallback (
    MakeCallback (&OFSwitch13Controller::SocketRequest, this),
    MakeCallback (&OFSwitch13Controller::SocketAccept, this));
  m_serverSocket->SetCloseCallbacks (
    MakeCallback (&OFSwitch13Controller::SocketPeerClose, this),
    MakeCallback (&OFSwitch13Controller::SocketPeerError, this));
}

void
OFSwitch13Controller::StopApplication ()
{
  for (SwitchsMap_t::iterator it = m_switchesMap.begin ();
       it != m_switchesMap.end (); it++)
    {
      it->second.socket->Close ();
    }
  if (m_serverSocket)
    {
      m_serverSocket->Close ();
      m_serverSocket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
    }
  m_switchesMap.clear ();
}

uint32_t
OFSwitch13Controller::GetNextXid ()
{
  return ++m_xid;
}

void
OFSwitch13Controller::ConnectionStarted (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (this << swtch.ipv4);
}

int
OFSwitch13Controller::SendToSwitch (SwitchInfo *swtch, ofl_msg_header *msg,
                                    uint32_t xid)
{
  char *msg_str = ofl_msg_to_string (msg, NULL);
  NS_LOG_DEBUG ("TX to switch " << swtch->ipv4 << ": " << msg_str);
  free (msg_str);

  if (!xid)
    {
      xid = GetNextXid ();
    }

  Ptr<Packet> pkt = ofs::PacketFromMsg (msg, xid);

  // Check for available space in TCP buffer before sending the packet
  Ptr<Socket> switchSocket = swtch->socket;
  if (switchSocket->GetTxAvailable () < pkt->GetSize ())
    {
      NS_FATAL_ERROR ("Unavailable space to send OpenFlow message");
    }

  return !switchSocket->Send (pkt);
}

int
OFSwitch13Controller::SendEchoRequest (SwitchInfo swtch, size_t payloadSize)
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_echo msg;
  msg.header.type = OFPT_ECHO_REQUEST;
  msg.data_length = payloadSize;
  msg.data        = 0;

  if (payloadSize)
    {
      msg.data = (uint8_t*)xmalloc (payloadSize);
      random_bytes (msg.data, payloadSize);
    }

  uint32_t xid = GetNextXid ();
  EchoInfo echo (swtch.ipv4);
  m_echoMap.insert (std::pair<uint32_t, EchoInfo> (xid, echo));

  int error = SendToSwitch (&swtch, (ofl_msg_header*)&msg, xid);

  if (payloadSize)
    {
      free (msg.data);
    }

  return error;
}

int
OFSwitch13Controller::SendBarrierRequest (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_header msg;
  msg.type = OFPT_BARRIER_REQUEST;

  return SendToSwitch (&swtch, &msg);
}


// --- BEGIN: Handlers functions -------
ofl_err
OFSwitch13Controller::HandleEchoRequest (ofl_msg_echo *msg,
                                         SwitchInfo swtch,
                                         uint32_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);

  ofl_msg_echo reply;
  reply.header.type = OFPT_ECHO_REPLY;
  reply.data_length = msg->data_length;
  reply.data        = msg->data;
  SendToSwitch (&swtch, (ofl_msg_header*)&reply, xid);

  ofl_msg_free ((ofl_msg_header*)msg, NULL /*exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleEchoReply (ofl_msg_echo *msg,
                                       SwitchInfo swtch,
                                       uint32_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);

  EchoMsgMap_t::iterator it = m_echoMap.find (xid);
  if (it == m_echoMap.end ())
    {
      NS_LOG_WARN ("Received echo response for unknonw echo request.");
    }
  else
    {
      it->second.waiting = false;
      it->second.recv = Simulator::Now ();
      NS_LOG_DEBUG ("Received echo reply from " << it->second.destIp <<
                    " with RTT " << it->second.GetRtt ().As (Time::MS));
    }

  ofl_msg_free ((ofl_msg_header*)msg, NULL /*exp*/);
  return 0;
}


ofl_err
OFSwitch13Controller::HandleError (ofl_msg_error *msg,
                                   SwitchInfo swtch,
                                   uint32_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);

  char *str;
  str = ofl_msg_to_string ((ofl_msg_header*)msg, NULL);
  NS_LOG_ERROR ("OpenFlow error: " << str);
  free (str);

  ofl_msg_free ((ofl_msg_header*)msg, NULL /*exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleFeaturesReply (ofl_msg_features_reply *msg,
                                           SwitchInfo swtch,
                                           uint32_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  ofl_msg_free ((ofl_msg_header*)msg, NULL /*exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleGetConfigReply (ofl_msg_get_config_reply *msg,
                                            SwitchInfo swtch,
                                            uint32_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  ofl_msg_free ((ofl_msg_header*)msg, NULL /*exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleFlowRemoved (ofl_msg_flow_removed *msg,
                                         SwitchInfo swtch,
                                         uint32_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  ofl_msg_free_flow_removed (msg, true, NULL);
  return 0;
}

ofl_err
OFSwitch13Controller::HandlePortStatus (ofl_msg_port_status *msg,
                                        SwitchInfo swtch,
                                        uint32_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  ofl_msg_free ((ofl_msg_header*)msg, NULL /*exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleAsyncReply (ofl_msg_async_config *msg,
                                        SwitchInfo swtch,
                                        uint32_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  ofl_msg_free ((ofl_msg_header*)msg, NULL /*exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleMultipartReply (ofl_msg_multipart_reply_header *msg,
                                            SwitchInfo swtch,
                                            uint32_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  ofl_msg_free ((ofl_msg_header*)msg, NULL /*exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleRoleReply (ofl_msg_role_request *msg,
                                       SwitchInfo swtch,
                                       uint32_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  ofl_msg_free ((ofl_msg_header*)msg, NULL /*exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleQueueGetConfigReply (ofl_msg_queue_get_config_reply *msg,
                                                 SwitchInfo swtch,
                                                 uint32_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  ofl_msg_free ((ofl_msg_header*)msg, NULL /*exp*/);
  return 0;
}
// --- END: Handlers functions -------


/********** Private methods **********/
int
OFSwitch13Controller::ReceiveFromSwitch (SwitchInfo swtch, ofl_msg_header *msg,
                                         uint32_t xid)
{
  // Dispatches control messages to appropriate handler functions.
  switch (msg->type)
    {
    case OFPT_HELLO:
    case OFPT_BARRIER_REPLY:
      ofl_msg_free (msg, NULL /*exp*/);
      return 0;

    case OFPT_PACKET_IN:
      return HandlePacketIn ((ofl_msg_packet_in*)msg, swtch, xid);

    case OFPT_ECHO_REQUEST:
      return HandleEchoRequest ((ofl_msg_echo*)msg, swtch, xid);

    case OFPT_ECHO_REPLY:
      return HandleEchoReply ((ofl_msg_echo*)msg, swtch, xid);

    case OFPT_ERROR:
      return HandleError ((ofl_msg_error*)msg, swtch, xid);

    case OFPT_FEATURES_REPLY:
      return HandleFeaturesReply ((ofl_msg_features_reply*)msg, swtch, xid);

    case OFPT_GET_CONFIG_REPLY:
      return HandleGetConfigReply ((ofl_msg_get_config_reply*)msg, swtch, xid);

    case OFPT_FLOW_REMOVED:
      return HandleFlowRemoved ((ofl_msg_flow_removed*)msg, swtch, xid);

    case OFPT_PORT_STATUS:
      return HandlePortStatus ((ofl_msg_port_status*)msg, swtch, xid);

    case OFPT_GET_ASYNC_REPLY:
      return HandleAsyncReply ((ofl_msg_async_config*)msg, swtch, xid);

    case OFPT_MULTIPART_REPLY:
      return HandleMultipartReply ((ofl_msg_multipart_reply_header*)msg, swtch, xid);

    case OFPT_ROLE_REPLY:
      return HandleRoleReply ((ofl_msg_role_request*)msg, swtch, xid);

    case OFPT_QUEUE_GET_CONFIG_REPLY:
      return HandleQueueGetConfigReply ((ofl_msg_queue_get_config_reply*)msg, swtch, xid);

    case OFPT_EXPERIMENTER:
    default:
      return ofl_error (OFPET_BAD_REQUEST, OFPGMFC_BAD_TYPE);
    }
}

void
OFSwitch13Controller::SocketRead (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  static Ptr<Packet> pendingPacket = 0;
  static uint32_t pendingBytes = 0;
  static Address from;

  do
    {
      if (!pendingBytes)
        {
          // Starting with a new OpenFlow message.
          // At least 8 bytes (OpenFlow header) must be available for read
          uint32_t rxBytesAvailable = socket->GetRxAvailable ();
          NS_ASSERT_MSG (rxBytesAvailable >= 8, "At least 8 bytes must be available for read");

          // Receive the OpenFlow header
          pendingPacket = socket->RecvFrom (sizeof (ofp_header), 0, from);

          // Get the OpenFlow message size
          ofp_header header;
          pendingPacket->CopyData ((uint8_t*)&header, sizeof (ofp_header));
          pendingBytes = ntohs (header.length) - sizeof (ofp_header);
        }

      // Receive the remaining OpenFlow message
      if (pendingBytes)
        {
          if (socket->GetRxAvailable () < pendingBytes)
            {
              // We need to wait for more bytes
              return;
            }
          pendingPacket->AddAtEnd (socket->Recv (pendingBytes, 0));
        }

      if (InetSocketAddress::IsMatchingType (from))
        {
          Ipv4Address ipv4 = InetSocketAddress::ConvertFrom (from).GetIpv4 ();
          NS_LOG_LOGIC ("At time " << Simulator::Now ().GetSeconds () <<
                        "s the OpenFlow Controller received " <<  pendingPacket->GetSize () <<
                        " bytes from switch " << ipv4 <<
                        " port " << InetSocketAddress::ConvertFrom (from).GetPort ());

          uint32_t xid;
          ofl_msg_header *msg;
          ofl_err error;

          SwitchsMap_t::iterator it = m_switchesMap.find (ipv4);
          NS_ASSERT_MSG (it != m_switchesMap.end (), "Unknown switch " << from);

          // Get the openflow buffer, unpack the message and send to handler
          ofpbuf *buffer = ofs::BufferFromPacket (pendingPacket, pendingPacket->GetSize ());
          error = ofl_msg_unpack ((uint8_t*)buffer->data, buffer->size, &msg, &xid, NULL);
          if (!error)
            {
              char *msg_str = ofl_msg_to_string (msg, NULL);
              NS_LOG_DEBUG ("RX from switch " << ipv4 << ": " << msg_str);
              free (msg_str);

              error = ReceiveFromSwitch (it->second, msg, xid);
              if (error)
                {
                  // NOTE: It is assumed that if a handler returns with error,
                  // it did not use any part of the control message, thus it
                  // can be freed up. If no error is returned however, the
                  // message must be freed inside the handler (because the
                  // handler might keep parts of the message)
                  ofl_msg_free (msg, NULL);
                }
            }
          ofpbuf_delete (buffer);
        }
      pendingPacket = 0;
      pendingBytes = 0;

      // Repeat until socket buffer gets emtpy
    }
  while (socket->GetRxAvailable ());
}

bool
OFSwitch13Controller::SocketRequest (Ptr<Socket> socket, const Address& from)
{
  NS_LOG_FUNCTION (this << socket << from);
  NS_LOG_LOGIC ("Switch request connection from " <<
                InetSocketAddress::ConvertFrom (from).GetIpv4 ());
  return true;
}

void
OFSwitch13Controller::SocketAccept (Ptr<Socket> socket, const Address& from)
{
  NS_LOG_FUNCTION (this << socket << from);

  // Find the switch in our database
  Ipv4Address ipv4 = InetSocketAddress::ConvertFrom (from).GetIpv4 ();
  SwitchsMap_t::iterator it = m_switchesMap.find (ipv4);
  NS_ASSERT_MSG (it != m_switchesMap.end (), "Unregistered switch " << ipv4);

  NS_LOG_LOGIC ("Switch request connection accepted from " << ipv4);
  SwitchInfo *swInfo = &it->second;
  socket->SetRecvCallback (MakeCallback (&OFSwitch13Controller::SocketRead, this));

  // Update other switch information
  swInfo->ctrl = this;
  swInfo->socket = socket;
  swInfo->port = InetSocketAddress::ConvertFrom (from).GetPort ();

  // Handshake messages
  ofl_msg_header hello;
  hello.type = OFPT_HELLO;
  SendToSwitch (swInfo, &hello);

  ofl_msg_header features;
  features.type = OFPT_FEATURES_REQUEST;
  SendToSwitch (swInfo, &features);

  SendBarrierRequest (*swInfo);

  // Executing any scheduled commands for this switch
  std::pair <DevCmdMap_t::iterator, DevCmdMap_t::iterator> ret;
  ret = m_schedCommands.equal_range (swInfo->netdev);
  for (DevCmdMap_t::iterator it = ret.first; it != ret.second; it++)
    {
      DpctlCommand (*swInfo, it->second);
    }
  m_schedCommands.erase (ret.first, ret.second);

  // Notify the connection started
  ConnectionStarted (*swInfo);
}

void
OFSwitch13Controller::SocketPeerClose (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

void
OFSwitch13Controller::SocketPeerError (Ptr<Socket> socket)
{
  NS_LOG_WARN (this << socket);
}

void
OFSwitch13Controller::ScheduleCommand (SwitchInfo swtch, const std::string textCmd)
{
  NS_ASSERT (swtch.netdev);
  std::pair<Ptr<OFSwitch13NetDevice>,std::string> entry (swtch.netdev, textCmd);
  m_schedCommands.insert (entry);
}

} // namespace ns3
