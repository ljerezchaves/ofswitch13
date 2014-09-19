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
//    .AddConstructor<OFSwitch13Controller> ()
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

int
OFSwitch13Controller::SendFlowModMsg (SwitchInfo swtch, const char* textCmd) 
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

  // Parse flow_mod dpctl command
  wordexp_t cmd;
  wordexp (textCmd, &cmd, 0);
  
  parse_flow_mod_args (cmd.we_wordv[0], msg); 
  if (cmd.we_wordc > 1) 
    {
      size_t i, j;
      size_t inst_num = 0;
      if (cmd.we_wordc > 2)
        {
          inst_num = cmd.we_wordc - 2;
          j = 2;
          parse_match (cmd.we_wordv[1], &(msg->match));
        }
      else 
        {
          if (msg->command == OFPFC_DELETE) 
            {
              inst_num = 0;
              parse_match (cmd.we_wordv[1], &(msg->match));
            } 
          else 
            {
              /**
               * We copy the value because we don't know if it is an
               * instruction or match.  If the match is empty, the argv is
               * modified causing errors to instructions parsing
               */
              char *cpy = (char*)malloc (strlen (cmd.we_wordv[1]) + 1);
              memset (cpy, 0x00, strlen (cmd.we_wordv[1]) + 1);
              memcpy (cpy, cmd.we_wordv[1], strlen (cmd.we_wordv[1])); 
              parse_match (cpy, &(msg->match));
              free (cpy);
              if (msg->match->length <= 4)
                {
                  inst_num = cmd.we_wordc - 1;
                  j = 1;
                }
            }
        }

      msg->instructions_num = inst_num;
      msg->instructions = (ofl_instruction_header**)xmalloc (sizeof (ofl_instruction_header*) * inst_num);
      for (i=0; i < inst_num; i++) 
        {
          parse_inst (cmd.we_wordv[j+i], &(msg->instructions[i]));
        }
    } 
  else 
    {
      make_all_match (&(msg->match));
    }
  wordfree (&cmd);

  // Create packet, free memory and send
  LogOflMsg ((ofl_msg_header*)msg);
  return SendToSwitch (swtch, ofs::PacketFromMsg ((ofl_msg_header*)msg, ++m_xid));
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

  // TODO: Armazenar em algum lugar os pings que foram enviados...
  LogOflMsg ((ofl_msg_header*)&msg);
  Ptr<Packet> pkt = ofs::PacketFromMsg ((ofl_msg_header*)&msg, ++m_xid);
  
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
OFSwitch13Controller::RequestFlowStats (SwitchInfo swtch)
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

  //TODO Parse arguments and match

  LogOflMsg ((ofl_msg_header*)&msg);
  return SendToSwitch (swtch, ofs::PacketFromMsg ((ofl_msg_header*)&msg, ++m_xid));
}

int
OFSwitch13Controller::RequestFlowAggregStats (SwitchInfo swtch)
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

  // TODO Parse arguments and match

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
  ofl_msg_free (msg, NULL/*dp->exp*/);
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
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*dp->exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleMsgEchoReply (ofl_msg_echo *msg, SwitchInfo swtch, uint64_t xid) 
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  
  // TODO Implement
  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*dp->exp*/);
  return 0;
}

ofl_err 
OFSwitch13Controller::HandleMsgBarrierReply (ofl_msg_header *msg, SwitchInfo swtch, uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  
  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*dp->exp*/);
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
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*dp->exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleMsgFeaturesReply (ofl_msg_features_reply *msg, SwitchInfo swtch, uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*dp->exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleMsgGetConfigReply (ofl_msg_get_config_reply *msg, SwitchInfo swtch, uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  
  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*dp->exp*/);
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
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*dp->exp*/);
  return 0;
}

ofl_err 
OFSwitch13Controller::HandleMsgAsyncReply (ofl_msg_async_config *msg, SwitchInfo swtch, uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  
  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*dp->exp*/);
  return 0;
}

ofl_err 
OFSwitch13Controller::HandleMsgMultipartReply (ofl_msg_multipart_reply_header *msg, SwitchInfo swtch, uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  // There are several types of multipart replies. Derived controlleres can
  // handle these messages as they wish.
  
  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*dp->exp*/);
  return 0;
}

ofl_err 
OFSwitch13Controller::HandleMsgRoleReply (ofl_msg_role_request *msg, SwitchInfo swtch, uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*dp->exp*/);
  return 0;
}
  
ofl_err 
OFSwitch13Controller::HandleMsgQueueGetConfigReply (ofl_msg_queue_get_config_reply *msg, SwitchInfo swtch, uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*dp->exp*/);
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
        ofl_msg_free (msg, NULL/*dp->exp*/);
      }
    }
  
  if (error)
    {
      NS_LOG_WARN ("Error processing OpenFlow message received from switch " << swtch.ipv4);
    }
  ofpbuf_delete (buffer);
  return error; 
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
