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
#include "ns3/tcp-socket-factory.h"
#include "ofswitch13-controller.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Controller");
NS_OBJECT_ENSURE_REGISTERED (OFSwitch13Controller);

/********** Public methods ***********/
OFSwitch13Controller::OFSwitch13Controller ()
  : m_port (6653),
    m_serverSocket (0)
{
  NS_LOG_FUNCTION (this);

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
  NS_LOG_FUNCTION (this);

  m_serverSocket = 0;
  m_switchesMap.clear ();
  m_echoMap.clear ();
  m_barrierMap.clear ();
  m_schedCommands.clear ();

  Application::DoDispose ();
}

int
OFSwitch13Controller::DpctlExecute (Ptr<const RemoteSwitch> swtch,
                                    const std::string textCmd)
{
  NS_LOG_FUNCTION (this << swtch << textCmd);

  int error = 0;
  char **argv;
  size_t argc;

  wordexp_t cmd;
  wordexp (textCmd.c_str (), &cmd, 0);
  argv = cmd.we_wordv;
  argc = cmd.we_wordc;

  if (!strcmp (argv[0], "set-table-match") || !strcmp (argv[0], "ping"))
    {
      NS_LOG_ERROR ("Dpctl command currently not supported.");
    }
  else
    {
      return dpctl_exec_ns3_command ((void*)PeekPointer (swtch), argc, argv);
    }

  wordfree (&cmd);
  return error;
}

int
OFSwitch13Controller::DpctlExecute (uint64_t dpId, const std::string textCmd)
{
  NS_LOG_FUNCTION (this << dpId << textCmd);

  Ptr<const RemoteSwitch> swtch = GetRemoteSwitch (dpId);
  NS_ASSERT_MSG (swtch, "Can't execute command for an unregistered switch.");
  return DpctlExecute (swtch, textCmd);
}

int
OFSwitch13Controller::DpctlSchedule (uint64_t dpId, const std::string textCmd)
{
  NS_LOG_FUNCTION (this << textCmd);

  Ptr<const RemoteSwitch> swtch = GetRemoteSwitch (dpId);
  NS_ASSERT_MSG (!swtch, "Can't schedule command for a registered switch.");

  std::pair <uint64_t, std::string> entry (dpId, textCmd);
  m_schedCommands.insert (entry);
  return 0;
}

void
OFSwitch13Controller::DpctlSendAndPrint (vconn *vconn, ofl_msg_header *msg)
{
  NS_LOG_FUNCTION_NOARGS ();

  Ptr<const RemoteSwitch> swtch ((RemoteSwitch*)vconn, true);
  swtch->m_ctrlApp->SendToSwitch (swtch, msg, 0);
}

/********* Protected methods *********/
void
OFSwitch13Controller::StartApplication ()
{
  NS_LOG_FUNCTION (this << m_port);

  // Create the server listening socket
  if (!m_serverSocket)
    {
      m_serverSocket =
        Socket::CreateSocket (GetNode (), TcpSocketFactory::GetTypeId ());
      m_serverSocket->SetAttribute ("SegmentSize", UintegerValue (8900));
      m_serverSocket->Bind (InetSocketAddress (Ipv4Address::GetAny (),
                                               m_port));
      m_serverSocket->Listen ();
    }

  // Setting socket callbacks
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
  NS_LOG_FUNCTION (this << m_port);

  for (SwitchsMap_t::iterator it = m_switchesMap.begin ();
       it != m_switchesMap.end (); it++)
    {
      Ptr<RemoteSwitch> swtch = it->second;
      swtch->m_socket->Close ();
    }
  if (m_serverSocket)
    {
      m_serverSocket->Close ();
      m_serverSocket->SetRecvCallback (
        MakeNullCallback<void, Ptr<Socket> > ());
    }
  m_switchesMap.clear ();
}

uint32_t
OFSwitch13Controller::GetNextXid ()
{
  NS_LOG_FUNCTION (this);

  return ++m_xid;
}

void
OFSwitch13Controller::HandshakeSuccessful (Ptr<const RemoteSwitch> swtch)
{
  NS_LOG_FUNCTION (this << swtch);
}

Ptr<const OFSwitch13Controller::RemoteSwitch>
OFSwitch13Controller::GetRemoteSwitch (uint64_t dpId) const
{
  NS_LOG_FUNCTION (this << dpId);

  SwitchsMap_t::const_iterator it;
  for (it = m_switchesMap.begin (); it != m_switchesMap.end (); it++)
    {
      Ptr<const RemoteSwitch> swtch = it->second;
      if (swtch->m_dpId == dpId)
        {
          return swtch;
        }
    }
  return 0;
}

int
OFSwitch13Controller::SendToSwitch (Ptr<const RemoteSwitch> swtch,
                                    ofl_msg_header *msg, uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch);

  char *msg_str = ofl_msg_to_string (msg, 0);
  NS_LOG_DEBUG ("TX to switch " << swtch->GetIpv4 () << ": " << msg_str);
  free (msg_str);

  // Set the transaction ID only for unknown values
  if (!xid)
    {
      xid = GetNextXid ();
    }

  // Create the packet and check for available space in TCP buffer
  Ptr<Packet> pkt = ofs::PacketFromMsg (msg, xid);
  if (swtch->m_socket->GetTxAvailable () < pkt->GetSize ())
    {
      NS_FATAL_ERROR ("Unavailable space to send OpenFlow message.");
    }
  return !(swtch->m_socket->Send (pkt));
}

int
OFSwitch13Controller::SendEchoRequest (Ptr<const RemoteSwitch> swtch,
                                       size_t payloadSize)
{
  NS_LOG_FUNCTION (this << swtch);

  // Create the echo request message
  ofl_msg_echo msg;
  msg.header.type = OFPT_ECHO_REQUEST;
  msg.data_length = payloadSize;
  msg.data = 0;

  // Fill payload with random bytes
  if (payloadSize)
    {
      msg.data = (uint8_t*)xmalloc (payloadSize);
      random_bytes (msg.data, payloadSize);
    }

  // Create and save the echo metadata for this request
  uint32_t xid = GetNextXid ();
  std::pair <uint32_t, EchoInfo> entry (xid, EchoInfo (swtch));
  std::pair <EchoMsgMap_t::iterator, bool> ret;
  ret = m_echoMap.insert (entry);
  if (ret.second == false)
    {
      NS_LOG_ERROR ("Error requesting echo to switch " << swtch);
    }

  // Send the message to the switch
  int error = SendToSwitch (swtch, (ofl_msg_header*)&msg, xid);

  // Free the payload
  if (payloadSize)
    {
      free (msg.data);
    }
  return error;
}

int
OFSwitch13Controller::SendBarrierRequest (Ptr<const RemoteSwitch> swtch)
{
  NS_LOG_FUNCTION (this << swtch);

  // Create the barrier request message
  ofl_msg_header msg;
  msg.type = OFPT_BARRIER_REQUEST;

  // Create and save the barrier metadata for this request
  uint32_t xid = GetNextXid ();
  std::pair <uint32_t, BarrierInfo> entry (xid, BarrierInfo (swtch));
  std::pair <BarrierMsgMap_t::iterator, bool> ret;
  ret = m_barrierMap.insert (entry);
  if (ret.second == false)
    {
      NS_LOG_ERROR ("Error requesting barrier to switch " << swtch);
    }

  // Send the message to the switch
  return SendToSwitch (swtch, &msg, xid);
}

// --- BEGIN: Handlers functions -------
ofl_err
OFSwitch13Controller::HandleEchoRequest (
  ofl_msg_echo *msg, Ptr<const RemoteSwitch> swtch, uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  // Create the echo reply message
  ofl_msg_echo reply;
  reply.header.type = OFPT_ECHO_REPLY;
  reply.data_length = msg->data_length;
  reply.data = msg->data;
  SendToSwitch (swtch, (ofl_msg_header*)&reply, xid);
  ofl_msg_free ((ofl_msg_header*)msg, 0 /*exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleEchoReply (
  ofl_msg_echo *msg, Ptr<const RemoteSwitch> swtch, uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  EchoMsgMap_t::iterator it = m_echoMap.find (xid);
  if (it == m_echoMap.end ())
    {
      NS_LOG_WARN ("Echo response for unknonw echo request.");
    }
  else
    {
      it->second.m_waiting = false;
      it->second.m_recv = Simulator::Now ();
      NS_LOG_INFO ("Echo reply from " << it->second.m_swtch->GetIpv4 () <<
                   " with RTT " << it->second.GetRtt ().As (Time::MS));
      m_echoMap.erase (it);
    }

  ofl_msg_free ((ofl_msg_header*)msg, 0);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleBarrierReply (
  ofl_msg_header *msg, Ptr<const RemoteSwitch> swtch, uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  BarrierMsgMap_t::iterator it = m_barrierMap.find (xid);
  if (it == m_barrierMap.end ())
    {
      NS_LOG_WARN ("Barrier response for unknonw barrier request.");
    }
  else
    {
      NS_LOG_INFO ("Barrier reply from " << it->second.m_swtch->GetIpv4 ());
      m_barrierMap.erase (it);
    }

  ofl_msg_free (msg, 0);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleHello (
  ofl_msg_header *msg, Ptr<const RemoteSwitch> swtch, uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  // We got the hello message from the switch. Let's proceed with the handshake
  // and request the switch features.
  ofl_msg_free (msg, 0);

  ofl_msg_header features;
  features.type = OFPT_FEATURES_REQUEST;
  SendToSwitch (swtch, &features);
  SendBarrierRequest (swtch);

  return 0;
}

ofl_err
OFSwitch13Controller::HandleFeaturesReply (
  ofl_msg_features_reply *msg, Ptr<RemoteSwitch> swtch, uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  // We got the features reply message from the switch. Let's save switch
  // features into metadata structure.
  swtch->m_dpId = msg->datapath_id;
  swtch->m_numBuffers = msg->n_buffers;
  swtch->m_numTables = msg->n_tables;
  swtch->m_auxiliaryId = msg->auxiliary_id;
  swtch->m_capabilities = msg->capabilities;
  ofl_msg_free ((ofl_msg_header*)msg, 0);

  // Executing any scheduled commands for this OpenFlow datapath ID
  std::pair <DpIdCmdMap_t::iterator, DpIdCmdMap_t::iterator> ret;
  ret = m_schedCommands.equal_range (swtch->m_dpId);
  for (DpIdCmdMap_t::iterator it = ret.first; it != ret.second; it++)
    {
      DpctlExecute (swtch, it->second);
    }
  m_schedCommands.erase (ret.first, ret.second);

  // Notify listeners that the handshake procedure is concluded.
  HandshakeSuccessful (swtch);
  return 0;
}

ofl_err
OFSwitch13Controller::HandlePacketIn (
  ofl_msg_packet_in *msg, Ptr<const RemoteSwitch> swtch, uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  ofl_msg_free ((ofl_msg_header*)msg, 0);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleError (
  ofl_msg_error *msg, Ptr<const RemoteSwitch> swtch, uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  char *str;
  str = ofl_msg_to_string ((ofl_msg_header*)msg, 0);
  NS_LOG_ERROR ("OpenFlow error: " << str);
  free (str);

  ofl_msg_free ((ofl_msg_header*)msg, 0);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleGetConfigReply (
  ofl_msg_get_config_reply *msg, Ptr<const RemoteSwitch> swtch, uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  ofl_msg_free ((ofl_msg_header*)msg, 0);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleFlowRemoved (
  ofl_msg_flow_removed *msg, Ptr<const RemoteSwitch> swtch, uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  ofl_msg_free_flow_removed (msg, true, 0);
  return 0;
}

ofl_err
OFSwitch13Controller::HandlePortStatus (
  ofl_msg_port_status *msg, Ptr<const RemoteSwitch> swtch, uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  ofl_msg_free ((ofl_msg_header*)msg, 0);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleAsyncReply (
  ofl_msg_async_config *msg, Ptr<const RemoteSwitch> swtch, uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  ofl_msg_free ((ofl_msg_header*)msg, 0);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleMultipartReply (
  ofl_msg_multipart_reply_header *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  ofl_msg_free ((ofl_msg_header*)msg, 0);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleRoleReply (
  ofl_msg_role_request *msg, Ptr<const RemoteSwitch> swtch, uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  ofl_msg_free ((ofl_msg_header*)msg, 0);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleQueueGetConfigReply (
  ofl_msg_queue_get_config_reply *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  ofl_msg_free ((ofl_msg_header*)msg, 0);
  return 0;
}
// --- END: Handlers functions -------

/********** Private methods **********/
int
OFSwitch13Controller::HandleSwitchMsg (
  ofl_msg_header *msg, Ptr<RemoteSwitch> swtch, uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  // Dispatches control messages to appropriate handler functions.
  switch (msg->type)
    {
    case OFPT_HELLO:
      return HandleHello (msg, swtch, xid);

    case OFPT_BARRIER_REPLY:
      return HandleBarrierReply (msg, swtch, xid);

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
      return HandleMultipartReply ((ofl_msg_multipart_reply_header*)msg,
                                   swtch, xid);

    case OFPT_ROLE_REPLY:
      return HandleRoleReply ((ofl_msg_role_request*)msg, swtch, xid);

    case OFPT_QUEUE_GET_CONFIG_REPLY:
      return HandleQueueGetConfigReply ((ofl_msg_queue_get_config_reply*)msg,
                                        swtch, xid);

    case OFPT_EXPERIMENTER:
    default:
      return ofl_error (OFPET_BAD_REQUEST, OFPGMFC_BAD_TYPE);
    }
}

void
OFSwitch13Controller::ReceiveFromSwitch (Ptr<Packet> packet, Address from)
{
  NS_LOG_FUNCTION (this << packet);

  NS_LOG_INFO ("At time " << Simulator::Now ().GetSeconds () <<
               "s the OpenFlow controller " << this <<
               " received " << packet->GetSize () <<
               " bytes from switch " << from);

  uint32_t xid;
  ofl_msg_header *msg;
  ofl_err error;

  // Get the openflow buffer, unpack the message and send to message handler
  ofpbuf *buffer;
  buffer = ofs::BufferFromPacket (packet, packet->GetSize ());
  error = ofl_msg_unpack ((uint8_t*)buffer->data, buffer->size, &msg, &xid, 0);

  if (!error)
    {
      char *msg_str = ofl_msg_to_string (msg, 0);
      Ipv4Address swtchIp = InetSocketAddress::ConvertFrom (from).GetIpv4 ();
      NS_LOG_DEBUG ("RX from switch " << swtchIp << ": " << msg_str);
      free (msg_str);

      Ptr<RemoteSwitch> swtch = GetRemoteSwitch (from);
      error = HandleSwitchMsg (msg, swtch, xid);
      if (error)
        {
          // NOTE: It is assumed that if a handler returns with error,
          // it did not use any part of the control message, thus it
          // can be freed up. If no error is returned however, the
          // message must be freed inside the handler (because the
          // handler might keep parts of the message)
          ofl_msg_free (msg, 0);
        }
    }
  if (error)
    {
      NS_LOG_ERROR ("Error processing OpenFlow message from switch.");
    }
  ofpbuf_delete (buffer);
}

Ptr<OFSwitch13Controller::RemoteSwitch>
OFSwitch13Controller::GetRemoteSwitch (Address address)
{
  NS_LOG_FUNCTION (this << address);

  SwitchsMap_t::const_iterator it = m_switchesMap.find (address);
  if (it != m_switchesMap.end ())
    {
      return it->second;
    }
  NS_FATAL_ERROR ("Couldn't find the remote switch for this address.");
}

bool
OFSwitch13Controller::SocketRequest (Ptr<Socket> socket, const Address& from)
{
  NS_LOG_FUNCTION (this << socket << from);

  NS_ASSERT_MSG (InetSocketAddress::IsMatchingType (from),
                 "Invalid address type (only IPv4 supported by now).");
  NS_LOG_INFO ("Switch request connection from " <<
               InetSocketAddress::ConvertFrom (from).GetIpv4 ());
  return true;
}

void
OFSwitch13Controller::SocketAccept (Ptr<Socket> socket, const Address& from)
{
  NS_LOG_FUNCTION (this << socket << from);

  Ipv4Address ipv4 = InetSocketAddress::ConvertFrom (from).GetIpv4 ();
  NS_LOG_INFO ("Switch request connection accepted from " << ipv4);

  // This is a new switch connection to this controller.
  // Let's create the remote switch metadata and save it.
  Ptr<RemoteSwitch> swtch = Create<RemoteSwitch> ();
  swtch->m_address = from;
  swtch->m_ctrlApp = this;
  swtch->m_socket = socket;

  // As we have more than one socket that is used for communication between
  // this OpenFlow controller and switches, we need to handle the processing of
  // receiving messages from sockets in an independent way. So, each socket has
  // its own socket reader for receiving bytes and extracting OpenFlow
  // messages.
  swtch->m_reader = Create<SocketReader> (socket);
  swtch->m_reader->SetReceiveCallback (
    MakeCallback (&OFSwitch13Controller::ReceiveFromSwitch, this));

  std::pair <Address, Ptr<RemoteSwitch> > entry (swtch->m_address, swtch);
  std::pair <SwitchsMap_t::iterator, bool> ret;
  ret = m_switchesMap.insert (entry);
  if (ret.second == false)
    {
      NS_LOG_ERROR ("This switch is already registered with this controller.");
    }

  // Let's send the hello message to the switch and wait for the hello message
  // from the switch to proceed with the handshake procedure.
  ofl_msg_header hello;
  hello.type = OFPT_HELLO;
  SendToSwitch (swtch, &hello);
}

void
OFSwitch13Controller::SocketPeerClose (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

void
OFSwitch13Controller::SocketPeerError (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);

  NS_LOG_ERROR ("Socket peer error " << socket);
}

OFSwitch13Controller::RemoteSwitch::RemoteSwitch ()
  : m_socket (0),
    m_reader (0),
    m_ctrlApp (0),
    m_dpId (0),
    m_role (OFPCR_ROLE_EQUAL)
{
  m_address = Address ();
}

Ipv4Address
OFSwitch13Controller::RemoteSwitch::GetIpv4 (void) const
{
  return InetSocketAddress::ConvertFrom (m_address).GetIpv4 ();
}

uint16_t
OFSwitch13Controller::RemoteSwitch::GetPort (void) const
{
  return InetSocketAddress::ConvertFrom (m_address).GetPort ();
}

uint64_t
OFSwitch13Controller::RemoteSwitch::GetDpId (void) const
{
  return m_dpId;
}

OFSwitch13Controller::EchoInfo::EchoInfo (Ptr<const RemoteSwitch> swtch)
  : m_waiting (true),
    m_send (Simulator::Now ()),
    m_swtch (swtch)
{
}

Time
OFSwitch13Controller::EchoInfo::GetRtt (void) const
{
  if (m_waiting)
    {
      return Time (-1);
    }
  else
    {
      return m_recv - m_send;
    }
}

OFSwitch13Controller::BarrierInfo::BarrierInfo (Ptr<const RemoteSwitch> swtch)
  : m_waiting (true),
    m_swtch (swtch)
{
}

} // namespace ns3
