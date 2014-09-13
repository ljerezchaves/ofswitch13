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
#include "ns3/ofswitch13-helper.h"

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Controller");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (OFSwitch13Controller);

static void
LogOflMsg (struct ofl_msg_header *msg, bool isRx)
{
  char *str;
  str = ofl_msg_to_string (msg, NULL);
  if (isRx)
    {
      NS_LOG_INFO ("RX (swtc): " << str);
    }
  else
    {
      NS_LOG_INFO ("TX (swtc): " << str);
    }
  free (str);
}

/********** Public methods **********/

OFSwitch13Controller::OFSwitch13Controller ()
{
  NS_LOG_FUNCTION_NOARGS ();
  m_serverSocket = 0;
  m_helper = 0;
  m_xid = 0xff000000;
}

OFSwitch13Controller::~OFSwitch13Controller ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

TypeId 
OFSwitch13Controller::GetTypeId (void) 
{
  static TypeId tid = TypeId ("ns3::OFSwitch13Controller") 
    .SetParent<Object> ()
    .AddConstructor<OFSwitch13Controller> ()
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
  m_helper = 0;
  m_socketsMap.clear ();

  Application::DoDispose ();
}

void
OFSwitch13Controller::SetOFSwitch13Helper (Ptr<OFSwitch13Helper> helper)
{
  if (m_helper == 0)
    {
      m_helper = helper;
    }
}

int
OFSwitch13Controller::SendHelloMsg (Ptr<OFSwitch13NetDevice> swtch)
{
  // Create the internal hello message
  struct ofl_msg_header msg;
  msg.type = OFPT_HELLO;

  // Create packet, free memory and send
  LogOflMsg (&msg, false);
  Ptr<Packet> pkt = ofs::PacketFromMsg (&msg, ++m_xid);
  return SendToSwitch (pkt, swtch);
}

int
OFSwitch13Controller::SendFlowModMsg (Ptr<OFSwitch13NetDevice> swtch, const char* textCmd) 
{
  // Create the internal flow_mod message
  struct ofl_msg_flow_mod msgLocal;
  struct ofl_msg_flow_mod *msg = &msgLocal;
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
      msg->instructions = (struct ofl_instruction_header**)xmalloc (sizeof (struct ofl_instruction_header *) * inst_num);
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
  LogOflMsg ((ofl_msg_header*)msg, false);
  Ptr<Packet> pkt = ofs::PacketFromMsg ((ofl_msg_header*)msg, ++m_xid);
  return SendToSwitch (pkt, swtch);
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
      MakeCallback (&OFSwitch13Controller::HandleRead, this));
  m_serverSocket->SetAcceptCallback (
      MakeCallback (&OFSwitch13Controller::HandleRequest, this),
      MakeCallback (&OFSwitch13Controller::HandleAccept, this));
  m_serverSocket->SetCloseCallbacks (
      MakeCallback (&OFSwitch13Controller::HandlePeerClose, this),
      MakeCallback (&OFSwitch13Controller::HandlePeerError, this));
}

void
OFSwitch13Controller::StopApplication ()
{
  for (SocketsMap_t::iterator it = m_socketsMap.begin (); it != m_socketsMap.end (); it++)
    {
      it->second->Close ();
    }
  if (m_serverSocket) 
    {
      m_serverSocket->Close ();
      m_serverSocket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
    } 
  m_socketsMap.clear ();
}

ofp_type
OFSwitch13Controller::GetPacketType (ofpbuf* buffer)
{
  ofp_header* hdr = (ofp_header*)ofpbuf_try_pull (buffer, sizeof (ofp_header));
  ofp_type type = (ofp_type)hdr->type;
  ofpbuf_push_uninit (buffer, sizeof (ofp_header));
  return type;
}

void
OFSwitch13Controller::ReceiveFromSwitch (Ptr<OFSwitch13NetDevice> swtch, ofpbuf* buffer)
{
  NS_LOG_FUNCTION (this << swtch);
  NS_LOG_INFO ("Pacote tipo " << GetPacketType (buffer));
  // TODO: Não esquecer de liberar o buffer ao final
}

int
OFSwitch13Controller::SendToSwitch (Ptr<Packet> pkt, Ptr<OFSwitch13NetDevice> swtch)
{
  NS_LOG_FUNCTION (this << swtch);
  NS_ASSERT (m_helper);

  // Check for valid switch
  uint32_t index = m_helper->GetContainerIndex (swtch);
  if (index == UINT32_MAX)
    {
      NS_LOG_ERROR ("Can't send to this switch, not registered to this Controller.");
      return -1;
    }

  // Get switch socket
  SocketsMap_t::iterator sockIt = m_socketsMap.find (index);
  if (sockIt == m_socketsMap.end ())
    {
      NS_LOG_ERROR ("Can't send to this switch, no socket found.");
      return -1;
    }
  Ptr<Socket> switchSocket = sockIt->second;
  return switchSocket->Send (pkt);
}

void 
OFSwitch13Controller::HandleRead (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_ASSERT (m_helper);
  
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
          NS_LOG_LOGIC ("At time " << Simulator::Now ().GetSeconds ()
                       << "s the OpenFlow Controller received "
                       <<  packet->GetSize () << " bytes from switch "
                       << InetSocketAddress::ConvertFrom(from).GetIpv4 ()
                       << " port " << InetSocketAddress::ConvertFrom (from).GetPort ());
          
          // Get the corresponding swith device from address
          Ipv4Address ipv4Addr = InetSocketAddress::ConvertFrom (from).GetIpv4 ();
          uint32_t index = m_helper->GetContainerIndex (ipv4Addr);
          Ptr<OFSwitch13NetDevice> swtch = m_helper->GetSwitchDevice (index);

          struct ofpbuf *buffer = ofs::BufferFromPacket (packet, packet->GetSize ());
          ReceiveFromSwitch (swtch, buffer);
        }
    }
}

bool
OFSwitch13Controller::HandleRequest (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  NS_LOG_LOGIC ("Switch request connection from " << 
      InetSocketAddress::ConvertFrom (from).GetIpv4 ());
  return true;
}

void 
OFSwitch13Controller::HandleAccept (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from);
  NS_ASSERT (m_helper);

  Ipv4Address ipv4 = InetSocketAddress::ConvertFrom (from).GetIpv4 ();
  uint32_t idx = m_helper->GetContainerIndex (ipv4);
  NS_ASSERT_MSG (idx != UINT32_MAX, "Address not associated with registered switch.");
  
  NS_LOG_LOGIC ("Switch request connection accepted from " << ipv4);
  s->SetRecvCallback (MakeCallback (&OFSwitch13Controller::HandleRead, this));
  m_socketsMap[idx] = s;
  SendHelloMsg (m_helper->GetSwitchDevice (idx));
}

void 
OFSwitch13Controller::HandlePeerClose (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}
 
void 
OFSwitch13Controller::HandlePeerError (Ptr<Socket> socket)
{
  NS_LOG_WARN (this << socket);
}
 
} // namespace ns3
#endif // NS3_OFSWITCH13
