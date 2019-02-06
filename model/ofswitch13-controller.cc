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
#include <ns3/uinteger.h>
#include <ns3/tcp-socket-factory.h>
#include "ofswitch13-controller.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Controller");
NS_OBJECT_ENSURE_REGISTERED (OFSwitch13Controller);

/********** Public methods ***********/
OFSwitch13Controller::OFSwitch13Controller ()
  : m_serverSocket (0)
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
                   "Port number to listen for incoming packets.",
                   UintegerValue (6653),
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

  wordexp_t cmd;
  wordexp (textCmd.c_str (), &cmd, 0);
  char **argv = cmd.we_wordv;
  size_t argc = cmd.we_wordc;

  if ((strcmp (argv[0], "ping") == 0)
      || (strcmp (argv[0], "monitor") == 0)
      || (strcmp (argv[0], "set-desc") == 0)
      || (strcmp (argv[0], "queue-mod") == 0)
      || (strcmp (argv[0], "queue-del") == 0))
    {
      NS_LOG_ERROR ("Dpctl experimenter command currently not supported.");
      wordfree (&cmd);
      return EXIT_FAILURE;
    }

  int ret = dpctl_exec_ns3_command ((void*)PeekPointer (swtch), argc, argv);
  wordfree (&cmd);
  return ret;
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
OFSwitch13Controller::DpctlSendAndPrint (struct vconn *vconn,
                                         struct ofl_msg_header *msg)
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
  TypeId tcpFactory = TypeId::LookupByName ("ns3::TcpSocketFactory");
  m_serverSocket = Socket::CreateSocket (GetNode (), tcpFactory);
  m_serverSocket->SetAttribute ("SegmentSize", UintegerValue (8900));
  m_serverSocket->Bind (InetSocketAddress (Ipv4Address::GetAny (), m_port));
  m_serverSocket->Listen ();

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

  for (auto const &it : m_switchesMap)
    {
      Ptr<RemoteSwitch> swtch = it.second;
      swtch->m_handler = 0;
    }
  m_switchesMap.clear ();

  if (m_serverSocket)
    {
      m_serverSocket->Close ();
      m_serverSocket->SetRecvCallback (
        MakeNullCallback<void, Ptr<Socket> > ());
    }
}

uint32_t
OFSwitch13Controller::GetNextXid ()
{
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

  for (auto const &it : m_switchesMap)
    {
      Ptr<const RemoteSwitch> swtch = it.second;
      if (swtch->m_dpId == dpId)
        {
          return swtch;
        }
    }
  return 0;
}

int
OFSwitch13Controller::SendToSwitch (Ptr<const RemoteSwitch> swtch,
                                    struct ofl_msg_header *msg, uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch);

  char *msgStr = ofl_msg_to_string (msg, 0);
  NS_LOG_DEBUG ("TX to switch " << swtch->GetIpv4 () <<
                " [dp " << swtch->GetDpId () << "]: " << msgStr);
  free (msgStr);

  // Set the transaction ID only for unknown values
  if (!xid)
    {
      xid = GetNextXid ();
    }

  // Create the packet from the OpenFlow message and send it to the switch.
  return swtch->m_handler->SendMessage (ofs::PacketFromMsg (msg, xid));
}

void
OFSwitch13Controller::SendEchoRequest (Ptr<const RemoteSwitch> swtch,
                                       size_t payloadSize)
{
  NS_LOG_FUNCTION (this << swtch);

  // Create the echo request message
  struct ofl_msg_echo msg;
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
  auto ret = m_echoMap.insert (entry);
  if (ret.second == false)
    {
      NS_LOG_ERROR ("Error requesting echo to switch " << swtch);
    }

  // Send the message to the switch
  SendToSwitch (swtch, (struct ofl_msg_header*)&msg, xid);

  // Free the payload
  if (payloadSize)
    {
      free (msg.data);
    }
}

void
OFSwitch13Controller::SendBarrierRequest (Ptr<const RemoteSwitch> swtch)
{
  NS_LOG_FUNCTION (this << swtch);

  // Create the barrier request message
  struct ofl_msg_header msg;
  msg.type = OFPT_BARRIER_REQUEST;

  // Create and save the barrier metadata for this request
  uint32_t xid = GetNextXid ();
  std::pair <uint32_t, BarrierInfo> entry (xid, BarrierInfo (swtch));
  auto ret = m_barrierMap.insert (entry);
  if (ret.second == false)
    {
      NS_LOG_ERROR ("Error requesting barrier to switch " << swtch);
    }

  // Send the message to the switch
  SendToSwitch (swtch, &msg, xid);
}

// --- BEGIN: Handlers functions -------
ofl_err
OFSwitch13Controller::HandleEchoRequest (
  struct ofl_msg_echo *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  // Create the echo reply message
  struct ofl_msg_echo reply;
  reply.header.type = OFPT_ECHO_REPLY;
  reply.data_length = msg->data_length;
  reply.data = msg->data;
  SendToSwitch (swtch, (struct ofl_msg_header*)&reply, xid);
  ofl_msg_free ((struct ofl_msg_header*)msg, 0);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleEchoReply (
  struct ofl_msg_echo *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  auto it = m_echoMap.find (xid);
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

  ofl_msg_free ((struct ofl_msg_header*)msg, 0);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleBarrierReply (
  struct ofl_msg_header *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  auto it = m_barrierMap.find (xid);
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
  struct ofl_msg_header *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  // We got the hello message from the switch. Let's proceed with the handshake
  // and request the switch features.
  ofl_msg_free (msg, 0);

  struct ofl_msg_header features;
  features.type = OFPT_FEATURES_REQUEST;
  SendToSwitch (swtch, &features);
  SendBarrierRequest (swtch);

  return 0;
}

ofl_err
OFSwitch13Controller::HandleFeaturesReply (
  struct ofl_msg_features_reply *msg, Ptr<RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  // We got the features reply message from the switch. Let's save switch
  // features into metadata structure.
  swtch->m_dpId = msg->datapath_id;
  swtch->m_nBuffers = msg->n_buffers;
  swtch->m_nTables = msg->n_tables;
  swtch->m_auxiliaryId = msg->auxiliary_id;
  swtch->m_capabilities = msg->capabilities;
  ofl_msg_free ((struct ofl_msg_header*)msg, 0);

  // Executing any scheduled commands for this OpenFlow datapath ID
  auto ret = m_schedCommands.equal_range (swtch->m_dpId);
  for (auto it = ret.first; it != ret.second; it++)
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
  struct ofl_msg_packet_in *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  ofl_msg_free ((struct ofl_msg_header*)msg, 0);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleError (
  struct ofl_msg_error *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  char *msgStr = ofl_msg_to_string ((struct ofl_msg_header*)msg, 0);
  NS_LOG_ERROR ("OpenFlow error: " << msgStr);
  free (msgStr);

  ofl_msg_free ((struct ofl_msg_header*)msg, 0);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleGetConfigReply (
  struct ofl_msg_get_config_reply *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  ofl_msg_free ((struct ofl_msg_header*)msg, 0);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleFlowRemoved (
  struct ofl_msg_flow_removed *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  ofl_msg_free_flow_removed (msg, true, 0);
  return 0;
}

ofl_err
OFSwitch13Controller::HandlePortStatus (
  struct ofl_msg_port_status *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  ofl_msg_free ((struct ofl_msg_header*)msg, 0);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleAsyncReply (
  struct ofl_msg_async_config *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  ofl_msg_free ((struct ofl_msg_header*)msg, 0);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleMultipartReply (
  struct ofl_msg_multipart_reply_header *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  ofl_msg_free ((struct ofl_msg_header*)msg, 0);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleRoleReply (
  struct ofl_msg_role_request *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  ofl_msg_free ((struct ofl_msg_header*)msg, 0);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleQueueGetConfigReply (
  struct ofl_msg_queue_get_config_reply *msg, Ptr<const RemoteSwitch> swtch,
  uint32_t xid)
{
  NS_LOG_FUNCTION (this << swtch << xid);

  ofl_msg_free ((struct ofl_msg_header*)msg, 0);
  return 0;
}
// --- END: Handlers functions -------

/********** Private methods **********/
ofl_err
OFSwitch13Controller::HandleSwitchMsg (
  struct ofl_msg_header *msg, Ptr<RemoteSwitch> swtch, uint32_t xid)
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
      return HandlePacketIn (
        (struct ofl_msg_packet_in*)msg, swtch, xid);

    case OFPT_ECHO_REQUEST:
      return HandleEchoRequest (
        (struct ofl_msg_echo*)msg, swtch, xid);

    case OFPT_ECHO_REPLY:
      return HandleEchoReply (
        (struct ofl_msg_echo*)msg, swtch, xid);

    case OFPT_ERROR:
      return HandleError (
        (struct ofl_msg_error*)msg, swtch, xid);

    case OFPT_FEATURES_REPLY:
      return HandleFeaturesReply (
        (struct ofl_msg_features_reply*)msg, swtch, xid);

    case OFPT_GET_CONFIG_REPLY:
      return HandleGetConfigReply (
        (struct ofl_msg_get_config_reply*)msg, swtch, xid);

    case OFPT_FLOW_REMOVED:
      return HandleFlowRemoved (
        (struct ofl_msg_flow_removed*)msg, swtch, xid);

    case OFPT_PORT_STATUS:
      return HandlePortStatus (
        (struct ofl_msg_port_status*)msg, swtch, xid);

    case OFPT_GET_ASYNC_REPLY:
      return HandleAsyncReply (
        (struct ofl_msg_async_config*)msg, swtch, xid);

    case OFPT_MULTIPART_REPLY:
      return HandleMultipartReply (
        (struct ofl_msg_multipart_reply_header*)msg, swtch, xid);

    case OFPT_ROLE_REPLY:
      return HandleRoleReply (
        (struct ofl_msg_role_request*)msg, swtch, xid);

    case OFPT_QUEUE_GET_CONFIG_REPLY:
      return HandleQueueGetConfigReply (
        (struct ofl_msg_queue_get_config_reply*)msg, swtch, xid);

    case OFPT_EXPERIMENTER:
    default:
      return ofl_error (OFPET_BAD_REQUEST, OFPGMFC_BAD_TYPE);
    }
}

void
OFSwitch13Controller::ReceiveFromSwitch (Ptr<Packet> packet, Address from)
{
  NS_LOG_FUNCTION (this << packet);

  uint32_t xid;
  struct ofl_msg_header *msg;
  ofl_err error;

  // Get the openflow buffer, unpack the message and send to message handler
  struct ofpbuf *buffer = ofs::BufferFromPacket (packet, packet->GetSize ());
  error = ofl_msg_unpack ((uint8_t*)buffer->data, buffer->size, &msg, &xid, 0);

  if (!error)
    {
      Ptr<RemoteSwitch> swtch = GetRemoteSwitch (from);
      char *msgStr = ofl_msg_to_string (msg, 0);
      NS_LOG_DEBUG ("RX from switch " << swtch->GetIpv4 () <<
                    " [dp " << swtch->GetDpId () << "]: " << msgStr);
      free (msgStr);

      error = HandleSwitchMsg (msg, swtch, xid);
      if (error)
        {
          // NOTE: It is assumed that if a handler returns with error, it did
          // not use any part of the control message, thus it can be freed up.
          // If no error is returned however, the message must be freed inside
          // the handler (because the handler might keep parts of the message)
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

  auto it = m_switchesMap.find (address);
  if (it != m_switchesMap.end ())
    {
      return it->second;
    }
  NS_ABORT_MSG ("Couldn't find the remote switch for this address.");
}

bool
OFSwitch13Controller::SocketRequest (Ptr<Socket> socket, const Address& from)
{
  NS_LOG_FUNCTION (this << socket << from);

  NS_ASSERT_MSG (InetSocketAddress::IsMatchingType (from),
                 "Invalid address type (only IPv4 supported by now).");
  Ipv4Address ipAddr = InetSocketAddress::ConvertFrom (from).GetIpv4 ();
  uint16_t port = InetSocketAddress::ConvertFrom (from).GetPort ();
  NS_LOG_INFO ("Switch request connection from " << ipAddr << ":" << port);

  return true;
}

void
OFSwitch13Controller::SocketAccept (Ptr<Socket> socket, const Address& from)
{
  NS_LOG_FUNCTION (this << socket << from);

  Ipv4Address ipAddr = InetSocketAddress::ConvertFrom (from).GetIpv4 ();
  uint16_t port = InetSocketAddress::ConvertFrom (from).GetPort ();
  NS_LOG_INFO ("Switch connection accepted from " << ipAddr << ":" << port);

  // This is a new switch connection to this controller.
  // Let's create the remote switch metadata and save it.
  Ptr<RemoteSwitch> swtch = Create<RemoteSwitch> ();
  swtch->m_address = from;
  swtch->m_ctrlApp = Ptr<OFSwitch13Controller> (this);

  // As we have more than one socket that is used for communication between
  // this OpenFlow controller and switches, we need to handle the process of
  // sending/receiving OpenFlow messages to/from sockets in an independent way.
  // So, each socket has its own socket handler to this end.
  swtch->m_handler = CreateObject<OFSwitch13SocketHandler> (socket);
  swtch->m_handler->SetReceiveCallback (
    MakeCallback (&OFSwitch13Controller::ReceiveFromSwitch, this));

  std::pair <Address, Ptr<RemoteSwitch> > entry (swtch->m_address, swtch);
  auto ret = m_switchesMap.insert (entry);
  if (ret.second == false)
    {
      NS_LOG_ERROR ("This switch is already registered with this controller.");
    }

  // Let's send the hello message to the switch and wait for the hello message
  // from the switch to proceed with the handshake procedure.
  struct ofl_msg_header hello;
  hello.type = OFPT_HELLO;
  SendToSwitch (swtch, &hello);
}

void
OFSwitch13Controller::SocketPeerClose (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);

  NS_LOG_DEBUG ("Connection successfully closed.");
  socket->ShutdownSend ();
  socket->ShutdownRecv ();
}

void
OFSwitch13Controller::SocketPeerError (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);

  NS_LOG_ERROR ("Socket peer error " << socket);
  socket->ShutdownSend ();
  socket->ShutdownRecv ();
}

OFSwitch13Controller::RemoteSwitch::RemoteSwitch ()
  : m_handler (0),
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
