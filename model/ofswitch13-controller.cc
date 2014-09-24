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

#include <wordexp.h>
#include "ns3/uinteger.h"
#include "ofswitch13-controller.h"
#include "ofswitch13-net-device.h"

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Controller");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (OFSwitch13Controller);

static void
LogOflMsg (ofl_msg_header *msg, bool isRx=false)
{
  char *str;
  str = ofl_msg_to_string (msg, NULL);
  if (isRx)
    {
      NS_LOG_INFO ("RX from switch: " << str);
    }
  else
    {
      NS_LOG_INFO ("TX to swtc: " << str);
    }
  free (str);
}

InetSocketAddress
SwitchInfo::GetInet ()
{
  return InetSocketAddress (ipv4, port);
}

int
OFSwitch13Controller::DpctlCommand (SwitchInfo swtch, const std::string textCmd)
{
  int bytes = 0;
  char **argv;
  size_t argc;
  
  // Parse dpctl command
  wordexp_t cmd;
  wordexp (textCmd.c_str (), &cmd, 0);
  argv = cmd.we_wordv;
  argc = cmd.we_wordc;

  if (strcmp (argv[0], "features") == 0)
    {
      NS_ASSERT_MSG (argc == 1, "Invalid number of arguments for command " << argv[0]);
      bytes = RequestFeatures (swtch);
    }
  else if (strcmp (argv[0], "get-config") == 0)
    {
      NS_ASSERT_MSG (argc == 1, "Invalid number of arguments for command " << argv[0]);
      bytes = RequestConfig (swtch);
    }
  else if (strcmp (argv[0], "table-features") == 0)
    {
      NS_ASSERT_MSG (argc == 1, "Invalid number of arguments for command " << argv[0]);
      bytes = RequestTableFeatures (swtch);
    }
  else if (strcmp (argv[0], "stats-desc") == 0)
    {
      NS_ASSERT_MSG (argc == 1, "Invalid number of arguments for command " << argv[0]);
      bytes = RequestSwitchDesc (swtch);
    }
  else if (strcmp (argv[0], "stats-flow") == 0)
    {
      NS_ASSERT_MSG (argc >= 1 && argc <= 3 , "Invalid number of arguments for command " << argv[0]);
      bytes = DpctlStatsFlowCommand (swtch, --argc, ++argv);
    }
  else if (strcmp (argv[0], "stats-aggr") == 0)
    {
      NS_ASSERT_MSG (argc >= 1 && argc <= 3 , "Invalid number of arguments for command " << argv[0]);
      bytes = DpctlStatsAggrCommand (swtch, --argc, ++argv);
    }
  else if (strcmp (argv[0], "stats-table") == 0)
    {
      NS_ASSERT_MSG (argc == 1, "Invalid number of arguments for command " << argv[0]);
      bytes = RequestTableStats (swtch);
    }
  else if (strcmp (argv[0], "stats-port") == 0)
    {
      NS_ASSERT_MSG (argc == 1 || argc == 2 , "Invalid number of arguments for command " << argv[0]);
      bytes = DpctlStatsPortCommand (swtch, --argc, ++argv);
    }
  else if (strcmp (argv[0], "port-desc") == 0)
    {
      NS_ASSERT_MSG (argc == 1, "Invalid number of arguments for command " << argv[0]);
      bytes = RequestPortDesc (swtch);
    }
  else if (strcmp (argv[0], "set-config") == 0)
    {
      NS_ASSERT_MSG (argc == 2, "Invalid number of arguments for command " << argv[0]);
      bytes = DpctlSetConfigCommand (swtch, --argc, ++argv);
    }
  else if (strcmp (argv[0], "flow-mod") == 0)
    {
      NS_ASSERT_MSG (argc >= 2 && argc <= 9, "Invalid number of arguments for command " << argv[0]);
      bytes = DpctlFlowModCommand (swtch, --argc, ++argv);
    }
  else if (strcmp (argv[0], "group-mod") == 0)
    {
      NS_ASSERT_MSG (argc >= 2 && argc <= UINT8_MAX, "Invalid number of arguments for command " << argv[0]);
      bytes = DpctlGroupModCommand (swtch, --argc, ++argv);
    }
  else if (strcmp (argv[0], "get-async") == 0)
    {
      NS_ASSERT_MSG (argc == 1, "Invalid number of arguments for command " << argv[0]);
      bytes = RequestAsync (swtch);
    }
  else if (strcmp (argv[0], "port-mod") == 0)
    {
      NS_ASSERT_MSG (argc == 2, "Invalid number of arguments for command " << argv[0]);
      bytes = DpctlPortModCommand (swtch, --argc, ++argv);
    }
  else if (strcmp (argv[0], "table-mod") == 0)
    {
      NS_ASSERT_MSG (argc == 2, "Invalid number of arguments for command " << argv[0]);
      bytes = DpctlTableModCommand (swtch, --argc, ++argv);
    }
  // set-table-match ??

  wordfree (&cmd);
  return bytes;
}

/********** Public methods ***********/
OFSwitch13Controller::OFSwitch13Controller ()
{
  NS_LOG_FUNCTION (this);
  m_serverSocket = 0;
  m_xid = 0x11000000;
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
    .AddAttribute ("Port",
                   "Port on which we listen for incoming packets.",
                   UintegerValue (6653),
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

  Application::DoDispose ();
}

void 
OFSwitch13Controller::RegisterSwitchMetadata (SwitchInfo swInfo)
{
  NS_LOG_FUNCTION (swInfo.ipv4);

  std::pair <SwitchsMap_t::iterator, bool> ret;
  ret =  m_switchesMap.insert (std::pair<Ipv4Address, SwitchInfo> (swInfo.ipv4, swInfo));
  if (ret.second == false) 
    {
      NS_LOG_ERROR ("This switch is already registered with this controller");
    }
}

void 
OFSwitch13Controller::SetConnectionCallback (SwitchConnectionCallback_t cb)
{
  m_connectionCallback = cb;
}

/********* Protected methods *********/
int
OFSwitch13Controller::SendToSwitch (SwitchInfo swtch, Ptr<Packet> pkt)
{
  Ptr<Socket> switchSocket = swtch.socket;
  return switchSocket->Send (pkt);
}

int
OFSwitch13Controller::SendHello (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_header msg;
  msg.type = OFPT_HELLO;
  
  LogOflMsg (&msg);
  return SendToSwitch (swtch, ofs::PacketFromMsg (&msg, ++m_xid));
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

  uint64_t xid = ++m_xid;
  ofs::EchoInfo echo (swtch.ipv4);
  m_echoMap.insert (std::pair<uint64_t, ofs::EchoInfo> (xid, echo));
  
  LogOflMsg ((ofl_msg_header*)&msg);
  Ptr<Packet> pkt = ofs::PacketFromMsg ((ofl_msg_header*)&msg, xid);
  
  if (payloadSize)
    {
      free (msg.data);
    } 
  return SendToSwitch (swtch, pkt);
}

int
OFSwitch13Controller::RequestBarrier (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_header msg;
  msg.type = OFPT_BARRIER_REQUEST;

  LogOflMsg (&msg);
  return SendToSwitch (swtch, ofs::PacketFromMsg (&msg, ++m_xid));
}

int
OFSwitch13Controller::RequestAsync (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_async_config msg;
  msg.header.type = OFPT_GET_ASYNC_REQUEST;
  msg.config = NULL;

  LogOflMsg ((ofl_msg_header*)&msg);
  return SendToSwitch (swtch, ofs::PacketFromMsg ((ofl_msg_header*)&msg, ++m_xid));
}

int
OFSwitch13Controller::RequestFeatures (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_header msg;
  msg.type = OFPT_FEATURES_REQUEST;
  
  LogOflMsg (&msg);
  return SendToSwitch (swtch, ofs::PacketFromMsg (&msg, ++m_xid));
}

int
OFSwitch13Controller::RequestConfig (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_header msg;
  msg.type = OFPT_GET_CONFIG_REQUEST;
  
  LogOflMsg (&msg);
  return SendToSwitch (swtch, ofs::PacketFromMsg (&msg, ++m_xid));
}

int
OFSwitch13Controller::RequestSwitchDesc (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_multipart_request_header msg;
  msg.header.type = OFPT_MULTIPART_REQUEST;
  msg.type = OFPMP_DESC; 
  msg.flags = 0x0000;

  LogOflMsg ((ofl_msg_header*)&msg);
  return SendToSwitch (swtch, ofs::PacketFromMsg ((ofl_msg_header*)&msg, ++m_xid));
}

int
OFSwitch13Controller::RequestTableStats (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_multipart_request_header msg;
  msg.header.type = OFPT_MULTIPART_REQUEST;
  msg.type = OFPMP_TABLE; 
  msg.flags = 0x0000;

  LogOflMsg ((ofl_msg_header*)&msg);
  return SendToSwitch (swtch, ofs::PacketFromMsg ((ofl_msg_header*)&msg, ++m_xid));
}

int
OFSwitch13Controller::RequestPortStats (SwitchInfo swtch, uint32_t port)
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_multipart_request_port msg;
  msg.header.header.type = OFPT_MULTIPART_REQUEST;
  msg.header.type = OFPMP_PORT_STATS;
  msg.header.flags = 0x0000;
  msg.port_no = port;

  LogOflMsg ((ofl_msg_header*)&msg);
  return SendToSwitch (swtch, ofs::PacketFromMsg ((ofl_msg_header*)&msg, ++m_xid));
}

int
OFSwitch13Controller::RequestTableFeatures (SwitchInfo swtch)
{
  // FIXME Not implemented in switch yet
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_multipart_request_table_features msg;
  msg.header.header.type = OFPT_MULTIPART_REQUEST;
  msg.header.type = OFPMP_TABLE_FEATURES;
  msg.header.flags = 0x0000;
  msg.tables_num = 0;
  msg.table_features = NULL;
  
  LogOflMsg ((ofl_msg_header*)&msg);
  return SendToSwitch (swtch, ofs::PacketFromMsg ((ofl_msg_header*)&msg, ++m_xid));
}

int
OFSwitch13Controller::RequestPortDesc (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_multipart_request_header msg;
  msg.header.type = OFPT_MULTIPART_REQUEST;
  msg.type = OFPMP_PORT_DESC; 
  msg.flags = 0x0000;

  LogOflMsg ((ofl_msg_header*)&msg);
  return SendToSwitch (swtch, ofs::PacketFromMsg ((ofl_msg_header*)&msg, ++m_xid));
}

ofl_err
OFSwitch13Controller::HandleMsgHello (ofl_msg_header *msg, SwitchInfo swtch, uint64_t xid) 
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  // Nothing to do: the ofsoftswitch13 already checks for OpenFlow version when
  // unpacking the message

  // All handlers must free the message when everything is ok
  ofl_msg_free (msg, NULL/*exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleMsgEchoRequest (ofl_msg_echo *msg, SwitchInfo swtch, uint64_t xid) 
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  
  // Just reply with echo response
  ofl_msg_echo reply;
  reply.header.type = OFPT_ECHO_REPLY;
  reply.data_length = msg->data_length;
  reply.data        = msg->data;
  
  LogOflMsg ((ofl_msg_header*)&reply);
  SendToSwitch (swtch, ofs::PacketFromMsg ((ofl_msg_header*)&reply, xid)); 

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleMsgEchoReply (ofl_msg_echo *msg, SwitchInfo swtch, uint64_t xid) 
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  
  ofs::EchoMsgMap_t::iterator it = m_echoMap.find (xid);
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

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*exp*/);
  return 0;
}

ofl_err 
OFSwitch13Controller::HandleMsgBarrierReply (ofl_msg_header *msg, SwitchInfo swtch, uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  
  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*exp*/);
  return 0;
}

ofl_err 
OFSwitch13Controller::HandleMsgError (ofl_msg_error *msg, SwitchInfo swtch, uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
 
  // This base controller only logs the error to user
  char *str;
  str = ofl_msg_to_string ((ofl_msg_header*)msg, NULL);
  NS_LOG_ERROR ("OpenFlow error: " << str);
  free (str);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleMsgFeaturesReply (ofl_msg_features_reply *msg, SwitchInfo swtch, uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleMsgGetConfigReply (ofl_msg_get_config_reply *msg, SwitchInfo swtch, uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  
  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*exp*/);
  return 0;
}

ofl_err 
OFSwitch13Controller::HandleMsgFlowRemoved (ofl_msg_flow_removed *msg, SwitchInfo swtch, uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);

  // All handlers must free the message when everything is ok
  ofl_msg_free_flow_removed(msg, true, NULL);
  return 0;
}

ofl_err 
OFSwitch13Controller::HandleMsgPortStatus (ofl_msg_port_status *msg, SwitchInfo swtch, uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  
  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*exp*/);
  return 0;
}

ofl_err 
OFSwitch13Controller::HandleMsgAsyncReply (ofl_msg_async_config *msg, SwitchInfo swtch, uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  
  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*exp*/);
  return 0;
}

ofl_err 
OFSwitch13Controller::HandleMsgMultipartReply (ofl_msg_multipart_reply_header *msg, SwitchInfo swtch, uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  // There are several types of multipart replies. Derived controlleres can
  // handle these messages as they wish.
  
  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*exp*/);
  return 0;
}

ofl_err 
OFSwitch13Controller::HandleMsgRoleReply (ofl_msg_role_request *msg, SwitchInfo swtch, uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*exp*/);
  return 0;
}
  
ofl_err 
OFSwitch13Controller::HandleMsgQueueGetConfigReply (ofl_msg_queue_get_config_reply *msg, SwitchInfo swtch, uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*exp*/);
  return 0;
}

/********** Private methods **********/
void
OFSwitch13Controller::StartApplication ()
{
  NS_LOG_FUNCTION (this << "Starting Controller application at port " << m_port);

  // Create the server listening socket
  if (!m_serverSocket)
    {
      m_serverSocket = Socket::CreateSocket (GetNode (), TcpSocketFactory::GetTypeId ());
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
  for (SwitchsMap_t::iterator it = m_switchesMap.begin (); it != m_switchesMap.end (); it++)
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

int
OFSwitch13Controller::ReceiveFromSwitch (SwitchInfo swtch, ofpbuf* buffer)
{
  NS_ASSERT (buffer);

  uint32_t xid;
  ofl_msg_header *msg;
  ofl_err error;
  
  error = ofl_msg_unpack ((uint8_t*)buffer->data, buffer->size, &msg, &xid, NULL/*&ofl_exp*/);
  if (!error)
    {
      LogOflMsg ((ofl_msg_header*)msg, true/*Rx*/);
      /* Dispatches control messages to appropriate handler functions. */
      switch (msg->type)
        {
          case OFPT_HELLO:
            error = HandleMsgHello (msg, swtch, xid);
            break;
          case OFPT_ERROR:
            error = HandleMsgError ((ofl_msg_error*)msg, swtch, xid);
            break;
          case OFPT_ECHO_REQUEST:
            error = HandleMsgEchoRequest ((ofl_msg_echo*)msg, swtch, xid);
            break;
          case OFPT_ECHO_REPLY:
            error = HandleMsgEchoReply ((ofl_msg_echo*)msg, swtch, xid);
            break;
          case OFPT_EXPERIMENTER:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
            break;

          /* Switch configuration messages. */
          case OFPT_FEATURES_REQUEST:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          case OFPT_FEATURES_REPLY:
            error = HandleMsgFeaturesReply ((ofl_msg_features_reply*)msg, swtch, xid);
            break;
          case OFPT_GET_CONFIG_REQUEST:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          case OFPT_GET_CONFIG_REPLY:
            error = HandleMsgGetConfigReply ((ofl_msg_get_config_reply*)msg, swtch, xid);
            break;
          case OFPT_SET_CONFIG:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;

          /* Asynchronous messages. */
          case OFPT_PACKET_IN:
            error = HandleMsgPacketIn ((ofl_msg_packet_in*)msg, swtch, xid);
            break;
          case OFPT_FLOW_REMOVED:
            error = HandleMsgFlowRemoved ((ofl_msg_flow_removed*)msg, swtch, xid);
            break;
          case OFPT_PORT_STATUS:
            error = HandleMsgPortStatus ((ofl_msg_port_status*)msg, swtch, xid);
            break;

          /* Controller command messages. */
          case OFPT_GET_ASYNC_REQUEST:
          case OFPT_SET_ASYNC:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;       
          case OFPT_GET_ASYNC_REPLY:
            error = HandleMsgAsyncReply ((ofl_msg_async_config*)msg, swtch, xid);
            break;
          case OFPT_PACKET_OUT:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          case OFPT_FLOW_MOD:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          case OFPT_GROUP_MOD:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          case OFPT_PORT_MOD:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          case OFPT_TABLE_MOD:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;

          /* Statistics messages. */
          case OFPT_MULTIPART_REQUEST:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          case OFPT_MULTIPART_REPLY:
            error = HandleMsgMultipartReply ((ofl_msg_multipart_reply_header*)msg, swtch, xid);
            break;

          /* Barrier messages. */
          case OFPT_BARRIER_REQUEST:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          case OFPT_BARRIER_REPLY:
            error = HandleMsgBarrierReply (msg, swtch, xid);
            break;
          
          /* Role messages. */
          case OFPT_ROLE_REQUEST:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          case OFPT_ROLE_REPLY:
            error = HandleMsgRoleReply ((ofl_msg_role_request*)msg, swtch, xid);
            break;

          /* Queue Configuration messages. */
          case OFPT_QUEUE_GET_CONFIG_REQUEST:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          case OFPT_QUEUE_GET_CONFIG_REPLY:
            error = HandleMsgQueueGetConfigReply ((ofl_msg_queue_get_config_reply*)msg, swtch, xid);
            break;
          case OFPT_METER_MOD:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;            
          
          default: 
            error = ofl_error (OFPET_BAD_REQUEST, OFPGMFC_BAD_TYPE);
        }
      if (error)
      {
        /**
         * NOTE: It is assumed that if a handler returns with error, it did not
         * use any part of the control message, thus it can be freed up. If no
         * error is returned however, the message must be freed inside the
         * handler (because the handler might keep parts of the message) 
         */
        ofl_msg_free (msg, NULL/*exp*/);
      }
    }
  
  if (error)
    {
      NS_LOG_WARN ("Error processing OpenFlow message received from switch " << swtch.ipv4);
    }
  ofpbuf_delete (buffer);
  return error; 
}

int
OFSwitch13Controller::DpctlFlowModCommand (SwitchInfo swtch, int argc, char *argv[])
{
  NS_LOG_FUNCTION (swtch.ipv4);

  // Create the internal flow_mod message
  ofl_msg_flow_mod msgLocal;
  ofl_msg_flow_mod *msg = &msgLocal;
  msgLocal.header.type = OFPT_FLOW_MOD;
  msgLocal.cookie = 0x0000000000000000ULL;
  msgLocal.cookie_mask = 0x0000000000000000ULL;
  msgLocal.table_id = 0x00;
  msgLocal.command = OFPFC_ADD;
  msgLocal.idle_timeout = OFP_FLOW_PERMANENT;
  msgLocal.hard_timeout = OFP_FLOW_PERMANENT;
  msgLocal.priority = OFP_DEFAULT_PRIORITY;
  msgLocal.buffer_id = 0xffffffff;
  msgLocal.out_port = OFPP_ANY;
  msgLocal.out_group = OFPG_ANY;
  msgLocal.flags = 0x0000;
  msgLocal.match = NULL;
  msgLocal.instructions_num = 0;
  msgLocal.instructions = NULL;

  // Parse flow-mod dpctl command
  parse_flow_mod_args (argv[0], msg); 
  if (argc > 1) 
    {
      size_t i, j;
      size_t inst_num = 0;
      if (argc > 2)
        {
          inst_num = argc - 2;
          j = 2;
          parse_match (argv[1], &(msg->match));
        }
      else 
        {
          if (msg->command == OFPFC_DELETE) 
            {
              inst_num = 0;
              parse_match (argv[1], &(msg->match));
            } 
          else 
            {
              /**
               * We copy the value because we don't know if it is an
               * instruction or match.  If the match is empty, the argv is
               * modified causing errors to instructions parsing
               */
              char *cpy = (char*)malloc (strlen (argv[1]) + 1);
              memset (cpy, 0x00, strlen (argv[1]) + 1);
              memcpy (cpy, argv[1], strlen (argv[1])); 
              parse_match (cpy, &(msg->match));
              free (cpy);
              if (msg->match->length <= 4)
                {
                  inst_num = argc - 1;
                  j = 1;
                }
            }
        }

      msg->instructions_num = inst_num;
      msg->instructions = (ofl_instruction_header**)xmalloc (sizeof (ofl_instruction_header*) * inst_num);
      for (i=0; i < inst_num; i++) 
        {
          parse_inst (argv[j+i], &(msg->instructions[i]));
        }
    } 
  else 
    {
      make_all_match (&(msg->match));
    }

  // Create packet, free memory and send
  LogOflMsg ((ofl_msg_header*)msg);
  return SendToSwitch (swtch, ofs::PacketFromMsg ((ofl_msg_header*)msg, ++m_xid));
}

int
OFSwitch13Controller::DpctlGroupModCommand (SwitchInfo swtch, int argc, char *argv[])
{
  struct ofl_msg_group_mod msg;
  msg.header.type = OFPT_GROUP_MOD;
  msg.command = OFPGC_ADD;
  msg.type = OFPGT_ALL;
  msg.group_id = OFPG_ALL;
  msg.buckets_num = 0;
  msg.buckets = NULL;

  parse_group_mod_args (argv[0], &msg);

  if (argc > 1) 
    {
      size_t i;
      size_t buckets_num = (argc - 1) / 2;

      msg.buckets_num = buckets_num;
      msg.buckets = (ofl_bucket**)xmalloc (sizeof (ofl_bucket *) * buckets_num);

      for (i=0; i < buckets_num; i++) 
        {
          msg.buckets[i] = (ofl_bucket*)xmalloc (sizeof (ofl_bucket));
          msg.buckets[i]->weight = 0;
          msg.buckets[i]->watch_port = OFPP_ANY;
          msg.buckets[i]->watch_group = OFPG_ANY;
          msg.buckets[i]->actions_num = 0;
          msg.buckets[i]->actions = NULL;

          parse_bucket (argv[i*2+1], msg.buckets[i]);
          parse_actions (argv[i*2+2], &(msg.buckets[i]->actions_num), &(msg.buckets[i]->actions));
        }
    }

  // Create packet, free memory and send
  LogOflMsg ((ofl_msg_header*)&msg);
  return SendToSwitch (swtch, ofs::PacketFromMsg ((ofl_msg_header*)&msg, ++m_xid));
}

int
OFSwitch13Controller::DpctlSetConfigCommand (SwitchInfo swtch, int argc, char *argv[])
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_set_config msg;
  msg.header.type = OFPT_SET_CONFIG;
  msg.config = (ofl_config*)xmalloc (sizeof (ofl_config));
  msg.config->flags = OFPC_FRAG_NORMAL;
  msg.config->miss_send_len = OFP_DEFAULT_MISS_SEND_LEN;

  // Parse set-config dpctl command
  parse_config (argv[0], msg.config); 
  
  // Create packet, free memory and send
  LogOflMsg ((ofl_msg_header*)&msg);
  return SendToSwitch (swtch, ofs::PacketFromMsg ((ofl_msg_header*)&msg, ++m_xid));
}

int
OFSwitch13Controller::DpctlStatsFlowCommand (SwitchInfo swtch, int argc, char *argv[])
{
  NS_LOG_FUNCTION (swtch.ipv4);

  struct ofl_msg_multipart_request_flow msg;
  msg.header.header.type = OFPT_MULTIPART_REQUEST;
  msg.header.type = OFPMP_FLOW; 
  msg.header.flags = 0x0000;
  msg.cookie = 0x0000000000000000ULL;
  msg.cookie_mask = 0x0000000000000000ULL;
  msg.table_id = 0xff;
  msg.out_port = OFPP_ANY;
  msg.out_group = OFPG_ANY;
  msg.match = NULL;

  if (argc > 0)
    {
      parse_flow_stat_args (argv[0], &msg); 
    }
  if (argc > 1)
    {
      parse_match (argv[1], &(msg.match));
    }
  else
    {
      make_all_match (&(msg.match));
    }
  
  // Create packet, free memory and send
  LogOflMsg ((ofl_msg_header*)&msg);
  return SendToSwitch (swtch, ofs::PacketFromMsg ((ofl_msg_header*)&msg, ++m_xid));
}

int
OFSwitch13Controller::DpctlStatsAggrCommand (SwitchInfo swtch, int argc, char *argv[])
{
  NS_LOG_FUNCTION (swtch.ipv4);

  struct ofl_msg_multipart_request_flow msg;
  msg.header.header.type = OFPT_MULTIPART_REQUEST;
  msg.header.type = OFPMP_AGGREGATE; 
  msg.header.flags = 0x0000;
  msg.cookie = 0x0000000000000000ULL;
  msg.cookie_mask = 0x0000000000000000ULL;
  msg.table_id = 0xff;
  msg.out_port = OFPP_ANY;
  msg.out_group = OFPG_ANY;
  msg.match = NULL;

  if (argc > 0)
    {
      parse_flow_stat_args (argv[0], &msg); 
    }
  if (argc > 1)
    {
      parse_match (argv[1], &(msg.match));
    }
  else
    {
      make_all_match (&(msg.match));
    }

  LogOflMsg ((ofl_msg_header*)&msg);
  return SendToSwitch (swtch, ofs::PacketFromMsg ((ofl_msg_header*)&msg, ++m_xid));
}

int
OFSwitch13Controller::DpctlStatsPortCommand (SwitchInfo swtch, int argc, char *argv[])
{
  NS_LOG_FUNCTION (swtch.ipv4);

  if (argc > 0)
    {
      uint32_t port;
      parse_port (argv[0], &port); 
      return RequestPortStats (swtch, port);
    }
  else
    {
      return RequestPortStats (swtch);
    }
}

int
OFSwitch13Controller::DpctlPortModCommand (SwitchInfo swtch, int argc, char *argv[])
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_port_mod msg;
  msg.header.type = OFPT_PORT_MOD;
  msg.port_no = OFPP_ANY;
  msg.config = 0x00000000;
  msg.mask = 0x00000000;
  msg.advertise = 0x00000000;
  memset (msg.hw_addr, 0xff, OFP_ETH_ALEN);

  parse_port_mod (argv[0], &msg);

  LogOflMsg ((ofl_msg_header*)&msg);
  return SendToSwitch (swtch, ofs::PacketFromMsg ((ofl_msg_header*)&msg, ++m_xid));
}

int
OFSwitch13Controller::DpctlTableModCommand (SwitchInfo swtch, int argc, char *argv[])
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_table_mod msg;
  msg.header.type = OFPT_TABLE_MOD;
  msg.table_id = 0xff;
  msg.config = 0x00;

  parse_table_mod (argv[0], &msg);

  LogOflMsg ((ofl_msg_header*)&msg);
  return SendToSwitch (swtch, ofs::PacketFromMsg ((ofl_msg_header*)&msg, ++m_xid));
}

void 
OFSwitch13Controller::SocketRead (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  
  Ptr<Packet> packet;
  Address from;
  while ((packet = socket->RecvFrom (from)))
    {
      if (packet->GetSize () == 0)
        { //EOF
          break;
        }
      if (InetSocketAddress::IsMatchingType (from))
        {
          Ipv4Address ipv4 = InetSocketAddress::ConvertFrom(from).GetIpv4 ();
          NS_LOG_LOGIC ("At time " << Simulator::Now ().GetSeconds ()
                       << "s the OpenFlow Controller received "
                       <<  packet->GetSize () << " bytes from switch " << ipv4
                       << " port " << InetSocketAddress::ConvertFrom (from).GetPort ());
          
          SwitchsMap_t::iterator it = m_switchesMap.find (ipv4);
          NS_ASSERT_MSG (it != m_switchesMap.end (), "Unknown switch " << from); 
          
          ofpbuf *buffer = ofs::BufferFromPacket (packet, packet->GetSize ());
          ReceiveFromSwitch (it->second, buffer);
        }
    }
}

bool
OFSwitch13Controller::SocketRequest (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  NS_LOG_LOGIC ("Switch request connection from " << 
      InetSocketAddress::ConvertFrom (from).GetIpv4 ());
  return true;
}

void 
OFSwitch13Controller::SocketAccept (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);

  // Find the switch in our database
  Ipv4Address ipv4 = InetSocketAddress::ConvertFrom (from).GetIpv4 ();
  SwitchsMap_t::iterator it = m_switchesMap.find (ipv4);
  NS_ASSERT_MSG (it != m_switchesMap.end (), "Unregistered switch " << ipv4); 
  
  NS_LOG_LOGIC ("Switch request connection accepted from " << ipv4);
  SwitchInfo *sw = &it->second;
  s->SetRecvCallback (MakeCallback (&OFSwitch13Controller::SocketRead, this));
  sw->socket = s;
  sw->port = InetSocketAddress::ConvertFrom (from).GetPort ();
  
  // Handshake
  SendHello (*sw);
  RequestFeatures (*sw);
  RequestBarrier (*sw);

  if (!m_connectionCallback.IsNull ())
    {
      m_connectionCallback (*sw);
    }
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
 
} // namespace ns3
#endif // NS3_OFSWITCH13
