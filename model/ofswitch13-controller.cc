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

EchoInfo::EchoInfo (Ipv4Address ip)
{
  waiting = true;
  send = Simulator::Now ();
  destIp = ip;
}

Time
EchoInfo::GetRtt ()
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
NS_OBJECT_ENSURE_REGISTERED (OFSwitch13Controller);

OFSwitch13Controller::OFSwitch13Controller ()
{
  NS_LOG_FUNCTION (this);
  m_serverSocket = 0;
  m_xid = rand () & UINT32_MAX;
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
  ret =  m_switchesMap.insert (
      std::pair<Ipv4Address, SwitchInfo> (swInfo.ipv4, swInfo));
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

int
OFSwitch13Controller::DpctlCommand (SwitchInfo swtch, const std::string textCmd)
{
  int error = 0;
  char **argv;
  size_t argc;

  wordexp_t cmd;
  wordexp (textCmd.c_str (), &cmd, 0);
  argv = cmd.we_wordv;
  argc = cmd.we_wordc;

  if (strcmp (argv[0], "features") == 0)
    {
      NS_ASSERT_MSG (argc == 1, "Wrong argc " << argv[0]);
      error = RequestFeatures (swtch);
    }
  else if (strcmp (argv[0], "get-config") == 0)
    {
      NS_ASSERT_MSG (argc == 1, "Wrong argc " << argv[0]);
      error = RequestConfig (swtch);
    }
  else if (strcmp (argv[0], "table-features") == 0)
    {
      NS_ASSERT_MSG (argc == 1, "Wrong argc " << argv[0]);
      error = RequestTableFeatures (swtch);
    }
  else if (strcmp (argv[0], "group-features") == 0)
    {
      NS_ASSERT_MSG (argc == 1, "Wrong argc " << argv[0]);
      error = RequestGroupFeatures (swtch);
    }
  else if (strcmp (argv[0], "meter-features") == 0)
    {
      NS_ASSERT_MSG (argc == 1, "Wrong argc " << argv[0]);
      error = RequestMeterFeatures (swtch);
    }
  else if (strcmp (argv[0], "stats-desc") == 0)
    {
      NS_ASSERT_MSG (argc == 1, "Wrong argc " << argv[0]);
      error = RequestSwitchDesc (swtch);
    }
  else if (strcmp (argv[0], "stats-flow") == 0)
    {
      NS_ASSERT_MSG (argc >= 1 && argc <= 3, "Wrong argc " << argv[0]);
      error = RequestFlowStats (swtch, --argc, ++argv);
    }
  else if (strcmp (argv[0], "stats-aggr") == 0)
    {
      NS_ASSERT_MSG (argc >= 1 && argc <= 3, "Wrong argc " << argv[0]);
      error = RequestFlowAggr (swtch, --argc, ++argv);
    }
  else if (strcmp (argv[0], "stats-table") == 0)
    {
      NS_ASSERT_MSG (argc == 1, "Wrong argc " << argv[0]);
      error = RequestTableStats (swtch);
    }
  else if (strcmp (argv[0], "stats-port") == 0)
    {
      NS_ASSERT_MSG (argc == 1 || argc == 2, "Wrong argc " << argv[0]);
      error = RequestPortStats (swtch, --argc, ++argv);
    }
  else if (strcmp (argv[0], "stats-group") == 0)
    {
      NS_ASSERT_MSG (argc == 1 || argc == 2, "Wrong argc " << argv[0]);
      error = RequestGroupStats (swtch, --argc, ++argv);
    }
  else if (strcmp (argv[0], "stats-group-desc") == 0)
    {
      NS_ASSERT_MSG (argc == 1 || argc == 2, "Wrong argc " << argv[0]);
      error = RequestGroupDesc (swtch, --argc, ++argv);
    }
  else if (strcmp (argv[0], "stats-meter") == 0)
    {
      NS_ASSERT_MSG (argc == 1 || argc == 2, "Wrong argc " << argv[0]);
      error = RequestMeterStats (swtch, --argc, ++argv);
    }
  else if (strcmp (argv[0], "get-async") == 0)
    {
      NS_ASSERT_MSG (argc == 1, "Wrong argc " << argv[0]);
      error = RequestAsyncConfig (swtch);
    }
  else if (strcmp (argv[0], "port-desc") == 0)
    {
      NS_ASSERT_MSG (argc == 1, "Wrong argc " << argv[0]);
      error = RequestPortDesc (swtch);
    }
  else if (strcmp (argv[0], "meter-config") == 0)
    {
      NS_ASSERT_MSG (argc == 1 || argc == 2, "Wrong argc " << argv[0]);
      error = MeterConfig (swtch, --argc, ++argv);
    }
  else if (strcmp (argv[0], "set-config") == 0)
    {
      NS_ASSERT_MSG (argc == 2, "Wrong argc " << argv[0]);
      error = SetConfig (swtch, --argc, ++argv);
    }
  else if (strcmp (argv[0], "flow-mod") == 0)
    {
      NS_ASSERT_MSG (argc >= 2 && argc <= 9, "Wrong argc " << argv[0]);
      error = FlowMod (swtch, --argc, ++argv);
    }
  else if (strcmp (argv[0], "group-mod") == 0)
    {
      NS_ASSERT_MSG (argc >= 2 && argc <= UINT8_MAX, "Wrong argc " << argv[0]);
      error = GroupMod (swtch, --argc, ++argv);
    }
  else if (strcmp (argv[0], "meter-mod") == 0)
    {
      NS_ASSERT_MSG (argc >= 2 && argc <= UINT8_MAX, "Wrong argc " << argv[0]);
      error = MeterMod (swtch, --argc, ++argv);
    }
  else if (strcmp (argv[0], "port-mod") == 0)
    {
      NS_ASSERT_MSG (argc == 2, "Wrong argc " << argv[0]);
      error = PortMod (swtch, --argc, ++argv);
    }
  else if (strcmp (argv[0], "table-mod") == 0)
    {
      NS_ASSERT_MSG (argc == 2, "Wrong argc " << argv[0]);
      error = TableMod (swtch, --argc, ++argv);
    }
  // set-table-match ??

  wordfree (&cmd);
  return error;
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

int
OFSwitch13Controller::SendToSwitch (SwitchInfo swtch, ofl_msg_header *msg,
                                    uint32_t xid)
{
  NS_LOG_FUNCTION (this);

  char *msg_str = ofl_msg_to_string (msg, NULL);
  NS_LOG_DEBUG ("TX to switch: " << msg_str);
  free (msg_str);

  if (!xid)
    {
      xid = GetNextXid ();
    }

  Ptr<Socket> switchSocket = swtch.socket;
  return !switchSocket->Send (ofs::PacketFromMsg (msg, xid));
}

int
OFSwitch13Controller::SendHello (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_header msg;
  msg.type = OFPT_HELLO;

  return SendToSwitch (swtch, &msg);
}

int
OFSwitch13Controller::SendEcho (SwitchInfo swtch, size_t payloadSize)
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

  int error = SendToSwitch (swtch, (ofl_msg_header*)&msg, xid);

  if (payloadSize)
    {
      free (msg.data);
    }

  return error;
}

int
OFSwitch13Controller::SendBarrier (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_header msg;
  msg.type = OFPT_BARRIER_REQUEST;

  return SendToSwitch (swtch, &msg);
}

int
OFSwitch13Controller::RequestFeatures (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_header msg;
  msg.type = OFPT_FEATURES_REQUEST;

  return SendToSwitch (swtch, &msg);
}

int
OFSwitch13Controller::RequestConfig (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_header msg;
  msg.type = OFPT_GET_CONFIG_REQUEST;

  return SendToSwitch (swtch, &msg);
}

int
OFSwitch13Controller::RequestTableFeatures (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_multipart_request_table_features msg;
  msg.header.header.type = OFPT_MULTIPART_REQUEST;
  msg.header.type = OFPMP_TABLE_FEATURES;
  msg.header.flags = 0x0000;
  msg.tables_num = 0;
  msg.table_features = NULL;

  return SendToSwitch (swtch, (ofl_msg_header*)&msg);
}

int
OFSwitch13Controller::RequestGroupFeatures (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_multipart_request_header msg;
  msg.header.type = OFPT_MULTIPART_REQUEST;
  msg.type = OFPMP_GROUP_FEATURES;
  msg.flags = 0x0000;

  return SendToSwitch (swtch, (ofl_msg_header*)&msg);
}

int
OFSwitch13Controller::RequestMeterFeatures (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_multipart_request_header msg;
  msg.header.type = OFPT_MULTIPART_REQUEST;
  msg.type = OFPMP_METER_FEATURES;
  msg.flags = 0x0000;

  return SendToSwitch (swtch, (ofl_msg_header*)&msg);
}

int
OFSwitch13Controller::RequestSwitchDesc (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_multipart_request_header msg;
  msg.header.type = OFPT_MULTIPART_REQUEST;
  msg.type = OFPMP_DESC;
  msg.flags = 0x0000;

  return SendToSwitch (swtch, (ofl_msg_header*)&msg);
}

int
OFSwitch13Controller::RequestFlowStats (SwitchInfo swtch, int argc, char *argv[])
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

  return SendToSwitch (swtch, (ofl_msg_header*)&msg);
}

int
OFSwitch13Controller::RequestFlowAggr (SwitchInfo swtch, int argc, char *argv[])
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

  return SendToSwitch (swtch, (ofl_msg_header*)&msg);
}

int
OFSwitch13Controller::RequestTableStats (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_multipart_request_header msg;
  msg.header.type = OFPT_MULTIPART_REQUEST;
  msg.type = OFPMP_TABLE;
  msg.flags = 0x0000;

  return SendToSwitch (swtch, (ofl_msg_header*)&msg);
}

int
OFSwitch13Controller::RequestPortStats (SwitchInfo swtch, int argc, char *argv[])
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_multipart_request_port msg;
  msg.header.header.type = OFPT_MULTIPART_REQUEST;
  msg.header.type = OFPMP_PORT_STATS;
  msg.header.flags = 0x0000;
  msg.port_no = OFPP_ANY;

  if (argc > 0)
    {
      parse_port (argv[0], &msg.port_no);
    }

  return SendToSwitch (swtch, (ofl_msg_header*)&msg);
}

int
OFSwitch13Controller::RequestGroupStats (SwitchInfo swtch, int argc, char *argv[])
{
  NS_LOG_FUNCTION (swtch.ipv4);

  struct ofl_msg_multipart_request_group msg;
  msg.header.header.type = OFPT_MULTIPART_REQUEST;
  msg.header.type = OFPMP_GROUP;
  msg.header.flags = 0x0000;
  msg.group_id = OFPG_ALL;

  parse_group (argv[0], &msg.group_id);

  return SendToSwitch (swtch, (ofl_msg_header*)&msg);
}

int
OFSwitch13Controller::RequestGroupDesc (SwitchInfo swtch, int argc, char *argv[])
{
  NS_LOG_FUNCTION (swtch.ipv4);

  struct ofl_msg_multipart_request_group msg;
  msg.header.header.type = OFPT_MULTIPART_REQUEST;
  msg.header.type = OFPMP_GROUP_DESC;
  msg.header.flags = 0x0000;
  msg.group_id = OFPG_ALL;

  parse_group (argv[0], &msg.group_id);

  return SendToSwitch (swtch, (ofl_msg_header*)&msg);
}

int
OFSwitch13Controller::RequestMeterStats (SwitchInfo swtch, int argc, char *argv[])
{
  NS_LOG_FUNCTION (swtch.ipv4);

  struct ofl_msg_multipart_meter_request msg;
  msg.header.header.type = OFPT_MULTIPART_REQUEST;
  msg.header.type = OFPMP_METER;
  msg.header.flags = 0x0000;
  msg.meter_id = OFPM_ALL;

  parse_meter (argv[0], &msg.meter_id);

  return SendToSwitch (swtch, (ofl_msg_header*)&msg);
}

int
OFSwitch13Controller::RequestPortDesc (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_multipart_request_header msg;
  msg.header.type = OFPT_MULTIPART_REQUEST;
  msg.type = OFPMP_PORT_DESC;
  msg.flags = 0x0000;

  return SendToSwitch (swtch, (ofl_msg_header*)&msg);
}

int
OFSwitch13Controller::RequestAsyncConfig (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_async_config msg;
  msg.header.type = OFPT_GET_ASYNC_REQUEST;
  msg.config = NULL;

  return SendToSwitch (swtch, (ofl_msg_header*)&msg);
}

int
OFSwitch13Controller::MeterConfig (SwitchInfo swtch, int argc, char *argv[])
{
  NS_LOG_FUNCTION (swtch.ipv4);

  struct ofl_msg_multipart_meter_request msg;
  msg.header.header.type = OFPT_MULTIPART_REQUEST;
  msg.header.type = OFPMP_METER_CONFIG;
  msg.header.flags = 0x0000;
  msg.meter_id = OFPM_ALL;

  parse_meter (argv[0], &msg.meter_id);

  return SendToSwitch (swtch, (ofl_msg_header*)&msg);
}

int
OFSwitch13Controller::SetConfig (SwitchInfo swtch, int argc, char *argv[])
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_set_config msg;
  msg.header.type = OFPT_SET_CONFIG;
  msg.config = (ofl_config*)xmalloc (sizeof (ofl_config));
  msg.config->flags = OFPC_FRAG_NORMAL;
  msg.config->miss_send_len = OFP_DEFAULT_MISS_SEND_LEN;

  parse_config (argv[0], msg.config);

  return SendToSwitch (swtch, (ofl_msg_header*)&msg);
}

int
OFSwitch13Controller::FlowMod (SwitchInfo swtch, int argc, char *argv[])
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
              // We copy the value because we don't know if it is an
              // instruction or match.  If the match is empty, the argv is
              // modified causing errors to instructions parsing
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
      msg->instructions = (ofl_instruction_header**)xmalloc (inst_num * sizeof (ofl_instruction_header*));
      for (i = 0; i < inst_num; i++)
        {
          parse_inst (argv[j + i], &(msg->instructions[i]));
        }
    }
  else
    {
      make_all_match (&(msg->match));
    }

  return SendToSwitch (swtch, (ofl_msg_header*)msg);
}

int
OFSwitch13Controller::GroupMod (SwitchInfo swtch, int argc, char *argv[])
{
  ofl_msg_group_mod msg;
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
      msg.buckets = (ofl_bucket**)xmalloc (buckets_num * sizeof (ofl_bucket *));

      for (i = 0; i < buckets_num; i++)
        {
          msg.buckets[i] = (ofl_bucket*)xmalloc (sizeof (ofl_bucket));
          msg.buckets[i]->weight = 0;
          msg.buckets[i]->watch_port = OFPP_ANY;
          msg.buckets[i]->watch_group = OFPG_ANY;
          msg.buckets[i]->actions_num = 0;
          msg.buckets[i]->actions = NULL;

          parse_bucket (argv[i * 2 + 1], msg.buckets[i]);
          parse_actions (argv[i * 2 + 2], &(msg.buckets[i]->actions_num),
                         &(msg.buckets[i]->actions));
        }
    }

  return SendToSwitch (swtch, (ofl_msg_header*)&msg);
}

int
OFSwitch13Controller::MeterMod (SwitchInfo swtch, int argc, char *argv[])
{
  ofl_msg_meter_mod msg;
  msg.header.type = OFPT_METER_MOD;
  msg.command = OFPMC_ADD;
  msg.flags = OFPMF_KBPS;
  msg.meter_id = 0;
  msg.meter_bands_num = 0;
  msg.bands = NULL;

  parse_meter_mod_args (argv[0], &msg);

  if (argc > 1)
    {
      size_t i;
      size_t bands_num = argc - 1;
      msg.meter_bands_num = bands_num;
      msg.bands = (ofl_meter_band_header**)xmalloc (bands_num * sizeof (ofl_meter_band_header*));
      for (i = 0; i < bands_num; i++)
        {
          parse_band (argv[i + 1], &msg, &msg.bands[i]);
        }
    }

  return SendToSwitch (swtch, (ofl_msg_header*)&msg);
}

int
OFSwitch13Controller::PortMod (SwitchInfo swtch, int argc, char *argv[])
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

  return SendToSwitch (swtch, (ofl_msg_header*)&msg);
}

int
OFSwitch13Controller::TableMod (SwitchInfo swtch, int argc, char *argv[])
{
  NS_LOG_FUNCTION (swtch.ipv4);

  ofl_msg_table_mod msg;
  msg.header.type = OFPT_TABLE_MOD;
  msg.table_id = 0xff;
  msg.config = 0x00;

  parse_table_mod (argv[0], &msg);

  return SendToSwitch (swtch, (ofl_msg_header*)&msg);
}

ofl_err
OFSwitch13Controller::HandleEchoRequest (ofl_msg_echo *msg, SwitchInfo swtch,
                                         uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);

  // Just reply with echo response
  ofl_msg_echo reply;
  reply.header.type = OFPT_ECHO_REPLY;
  reply.data_length = msg->data_length;
  reply.data        = msg->data;

  SendToSwitch (swtch, (ofl_msg_header*)&reply, xid);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL /*exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleEchoReply (ofl_msg_echo *msg, SwitchInfo swtch,
                                       uint64_t xid)
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

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL /*exp*/);
  return 0;
}


ofl_err
OFSwitch13Controller::HandleError (ofl_msg_error *msg, SwitchInfo swtch,
                                   uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);

  // This base controller only logs the error to user
  char *str;
  str = ofl_msg_to_string ((ofl_msg_header*)msg, NULL);
  NS_LOG_ERROR ("OpenFlow error: " << str);
  free (str);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL /*exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleFeaturesReply (ofl_msg_features_reply *msg, SwitchInfo swtch,
                                           uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL /*exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleGetConfigReply (ofl_msg_get_config_reply *msg, SwitchInfo swtch,
                                            uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL /*exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleFlowRemoved (ofl_msg_flow_removed *msg, SwitchInfo swtch,
                                         uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);

  // All handlers must free the message when everything is ok
  ofl_msg_free_flow_removed (msg, true, NULL);
  return 0;
}

ofl_err
OFSwitch13Controller::HandlePortStatus (ofl_msg_port_status *msg, SwitchInfo swtch,
                                        uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL /*exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleAsyncReply (ofl_msg_async_config *msg,
                                        SwitchInfo swtch, uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL /*exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleMultipartReply (ofl_msg_multipart_reply_header *msg,
                                            SwitchInfo swtch, uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  // There are several types of multipart replies.
  // Derived controlleres can handle these messages as they wish.

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL /*exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleRoleReply (ofl_msg_role_request *msg,
                                       SwitchInfo swtch, uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL /*exp*/);
  return 0;
}

ofl_err
OFSwitch13Controller::HandleQueueGetConfigReply (ofl_msg_queue_get_config_reply *msg,
                                                 SwitchInfo swtch, uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL /*exp*/);
  return 0;
}


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

    // case OFPT_EXPERIMENTER:

    default:
      return ofl_error (OFPET_BAD_REQUEST, OFPGMFC_BAD_TYPE);
    }
}

void
OFSwitch13Controller::SocketRead (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);

  Ptr<Packet> packet;
  Address from;
  ofl_msg_header *msg;
  ofl_err error;
  uint32_t xid;
  while ((packet = socket->RecvFrom (from)))
    {
      if (packet->GetSize () == 0)
        { //EOF
          break;
        }
      if (InetSocketAddress::IsMatchingType (from))
        {
          Ipv4Address ipv4 = InetSocketAddress::ConvertFrom (from).GetIpv4 ();
          NS_LOG_LOGIC ("At time " << Simulator::Now ().GetSeconds ()
                                   << "s the OpenFlow Controller received "
                                   <<  packet->GetSize () << " bytes from switch " << ipv4
                                   << " port " << InetSocketAddress::ConvertFrom (from).GetPort ());

          SwitchsMap_t::iterator it = m_switchesMap.find (ipv4);
          NS_ASSERT_MSG (it != m_switchesMap.end (), "Unknown switch " << from);

          // Get the openflow buffer, unpack the message and send to handler
          ofpbuf *buffer = ofs::BufferFromPacket (packet, packet->GetSize ());
          error = ofl_msg_unpack ((uint8_t*)buffer->data, buffer->size, &msg, &xid, NULL);
          if (!error)
            {
              char *msg_str = ofl_msg_to_string (msg, NULL);
              NS_LOG_DEBUG ("Rx from switch: " << msg_str);
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
  SendBarrier (*sw);

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
