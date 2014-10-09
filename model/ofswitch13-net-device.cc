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

#include "ofswitch13-net-device.h"
#include "ofswitch13-interface.h"

#include "ns3/simulator.h"
#include "ns3/string.h"
#include "ns3/integer.h"
#include "ns3/uinteger.h"
#include "ns3/log.h"

#include "ns3/csma-net-device.h"
#include "ns3/ethernet-header.h"
#include "ns3/ethernet-trailer.h"
#include "ns3/arp-header.h"
#include "ns3/tcp-header.h"
#include "ns3/udp-header.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/arp-l3-protocol.h"
#include "ns3/inet-socket-address.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("OFSwitch13NetDevice");

/** 
 * As the integration of ofsoftswitch13 and ns3 involve overriding some C
 * functions, we are using a global map to store a pointer to all
 * OFSwitch13NetDevices in simulation, and allow faster object retrive by
 * datapath id. In this way, functions like dp_send_message can get the object
 * pointer and call SendToController method. 
 */
static std::map<uint64_t, Ptr<OFSwitch13NetDevice> > g_switchMap;

/** 
 * Insert a new openflow device in global map. This is called automatically
 * every time a new datapath is created in simulation. 
 * \param id The datapath id.
 * \param dev The Ptr<OFSwitch13NetDevice> pointer.
 */
static void 
RegisterDatapath (uint64_t id, Ptr<OFSwitch13NetDevice> dev)
{
  std::pair <std::map<uint64_t, Ptr<OFSwitch13NetDevice> >::iterator, bool> ret;
  ret = g_switchMap.insert (std::pair<uint64_t, Ptr<OFSwitch13NetDevice> > (id, dev));
  if (ret.second == false) 
    {
      NS_LOG_ERROR ("Error inserting datapath device into global map.");
    }
}

/** 
 * Remove an existing openflow device from global map. This is called automatically
 * every time a datapath is destroyed in simulation. 
 * \param id The datapath id.
 */
static void 
UnregisterDatapath (uint64_t id)
{
  std::map<uint64_t, Ptr<OFSwitch13NetDevice> >::iterator it;
  it = g_switchMap.find (id);
  if (it != g_switchMap.end ())
    {
      g_switchMap.erase (it);
    }
  else
    {
      NS_LOG_ERROR ("Error removing datapath device from global map.");
    }
}

/**
 * Retrieve and existing openflow device at global map by its datapath id 
 * \param id The datapath id.
 * \return The OpenFlow OFSwitch13NetDevice pointer.
 */
Ptr<OFSwitch13NetDevice>
GetDatapathDevice (uint64_t id)
{
  std::map<uint64_t, Ptr<OFSwitch13NetDevice> >::iterator it;
  it = g_switchMap.find (id);
  if (it != g_switchMap.end ())
    {
      return it->second;
    }
  else
    {
      NS_LOG_ERROR ("Error retrieving datapath device from global map.");
      return NULL;
    }
}

/**
 * A fast hash function used by hash map.
 * \see hash_int () in lib/hash.h
 */
uint32_t
HashInt (uint32_t x, uint32_t basis)
{
  x -= x << 6;
  x ^= x >> 17;
  x -= x << 9;
  x ^= x << 4;
  x += basis;
  x -= x << 3;
  x ^= x << 10;
  x ^= x >> 15;
  return x;
}

// ---- OpenFlow switch code -------------------------------
namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (OFSwitch13NetDevice);

// Initializing OFSwitch13NetDevice static members
uint64_t OFSwitch13NetDevice::m_globalDpId = 0;

/********** Public methods **********/
TypeId
OFSwitch13NetDevice::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OFSwitch13NetDevice")
    .SetParent<NetDevice> ()
    .AddConstructor<OFSwitch13NetDevice> ()
    .AddAttribute ("DatapathId",
                   "The identification of the OFSwitch13NetDevice/Datapath.",
                   TypeId::ATTR_GET,
                   UintegerValue (0),
                   MakeUintegerAccessor (&OFSwitch13NetDevice::m_dpId),
                   MakeUintegerChecker<uint64_t> ())
    .AddAttribute ("FlowTableDelay",
                   "Overhead for looking up in the flow table (Default: standard TCAM on an FPGA).",
                   TimeValue (NanoSeconds (30)),
                   MakeTimeAccessor (&OFSwitch13NetDevice::m_lookupDelay),
                   MakeTimeChecker ())
    .AddAttribute ("DatapathTimeout",
                   "The interval between timeout operations on pipeline.",
                   TimeValue (Seconds (0.5)),
                   MakeTimeAccessor (&OFSwitch13NetDevice::m_timeout),
                   MakeTimeChecker ())
    .AddAttribute ("EchoInterval",
                   "The interval between successive echo requests from switch.",
                   TimeValue (Seconds (20)),
                   MakeTimeAccessor (&OFSwitch13NetDevice::m_echo),
                   MakeTimeChecker ())
    .AddAttribute ("ControllerAddr",
                   "The controller InetSocketAddress, used to TCP communication.",
                   AddressValue (InetSocketAddress (Ipv4Address ("10.100.150.1"), 6653)),
                   MakeAddressAccessor (&OFSwitch13NetDevice::m_ctrlAddr),
                   MakeAddressChecker ())
  ;
  return tid;
}

OFSwitch13NetDevice::OFSwitch13NetDevice ()
  : m_dpId (++m_globalDpId),
    m_node (0),
    m_ctrlSocket (0),
    m_ifIndex (0),
    m_mtu (0x0000)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_INFO ("OpenFlow version " << OFP_VERSION);

  m_ctrlAddr = Address ();
  m_channel = CreateObject<BridgeChannel> ();
  SetAddress (Mac48Address::Allocate ()); 
 
  m_datapath = DatapathNew ();
  m_ports.reserve (DP_MAX_PORTS);
  RegisterDatapath (m_dpId, Ptr<OFSwitch13NetDevice> (this));
  Simulator::Schedule (m_timeout , &OFSwitch13NetDevice::DatapathTimeout, this, m_datapath);
}

OFSwitch13NetDevice::~OFSwitch13NetDevice ()
{
  NS_LOG_FUNCTION (this);
}

int 
OFSwitch13NetDevice::AddSwitchPort (Ptr<NetDevice> switchPort)
{
  NS_LOG_FUNCTION (this << switchPort);
  NS_LOG_INFO ("Adding port addr " << switchPort->GetAddress ());
  
  if (m_ports.size () >= DP_MAX_PORTS)
    {
      return EXFULL;
    }

  Ptr<CsmaNetDevice> csmaSwitchPort = switchPort->GetObject<CsmaNetDevice> ();
  if (!csmaSwitchPort)
    {
      NS_FATAL_ERROR ("NetDevice must be of CsmaNetDevice type.");
    }
  if (csmaSwitchPort->GetEncapsulationMode () != CsmaNetDevice::DIX)
    {
      NS_FATAL_ERROR ("CsmaNetDevice must use DIX encapsulation.");
    }

  // Update max mtu
  if (switchPort->GetMtu () > GetMtu ())
    {
      SetMtu (switchPort->GetMtu ());
    }

  int no = m_ports.size () + 1;
  ofs::Port p (switchPort, no);
  m_ports.push_back (p);
  m_datapath->ports_num++;
  NS_LOG_INFO ("Port # " << no);
  
  // Notify the controller that this port has been added
  ofl_msg_port_status msg;
  msg.header.type = OFPT_PORT_STATUS;
  msg.reason = OFPPR_ADD;
  msg.desc = p.conf;

  SendToController ((ofl_msg_header*)&msg);

  NS_LOG_LOGIC ("RegisterProtocolHandler for " << switchPort->GetInstanceTypeId ().GetName ());
  m_node->RegisterProtocolHandler (
      MakeCallback (&OFSwitch13NetDevice::ReceiveFromSwitchPort, this), 0, switchPort, true);
  m_channel->AddChannel (switchPort->GetChannel ());
  return 0;
}

int
OFSwitch13NetDevice::SendToController (ofl_msg_header *msg, const sender *sender)
{
  NS_LOG_FUNCTION (this);
  if (!m_ctrlSocket)
    {
      NS_LOG_WARN ("No controller connection. Discarding message... ");
      ofl_msg_free (msg, NULL);
      return -1;
    }
  
  char *msg_str = ofl_msg_to_string (msg, m_datapath->exp);
  NS_LOG_DEBUG ("TX to ctrl: " << msg_str);
  free (msg_str);

  uint32_t xid = sender ? sender->xid : GetNextXid ();
  ofpbuf *buffer = ofs::BufferFromMsg (msg, xid, m_datapath->exp);

  if (sender) 
    {
      // This is a reply... send back to the sender.
      return !m_ctrlSocket->Send (ofs::PacketFromBufferAndFree (buffer));
    } 
  else 
    {
      // This is an asynchronous message. Check for asynchronous configuration
      bool send = true;
      uint8_t msg_type;
      memcpy (&msg_type, ((char* ) buffer->data) + 1, sizeof (uint8_t));
      remote *r = CONTAINER_OF (list_front (&m_datapath->remotes), remote, node);
      
      // do not send to remotes with slave role apart from port status
      if (r->role == OFPCR_ROLE_EQUAL || r->role == OFPCR_ROLE_MASTER)
        {
          // Check if the message is enabled in the asynchronous configuration
          switch (msg_type)
            {
              case (OFPT_PACKET_IN):
                {
                  ofp_packet_in *p = (ofp_packet_in*)buffer->data;
                  if (((p->reason == OFPR_NO_MATCH)    && !(r->config.packet_in_mask[0] & 0x1)) ||
                      ((p->reason == OFPR_ACTION)      && !(r->config.packet_in_mask[0] & 0x2)) ||
                      ((p->reason == OFPR_INVALID_TTL) && !(r->config.packet_in_mask[0] & 0x4)))
                    {
                      send = false;
                    }
                  break;
                }
              case (OFPT_PORT_STATUS):
                {
                  ofp_port_status *p = (ofp_port_status*)buffer->data;
                  if (((p->reason == OFPPR_ADD)    && !(r->config.port_status_mask[0] & 0x1)) ||
                      ((p->reason == OFPPR_DELETE) && !(r->config.port_status_mask[0] & 0x2)) ||
                      ((p->reason == OFPPR_MODIFY) && !(r->config.packet_in_mask[0] & 0x4)))
                    {
                      send = false;
                    }
                }
              case (OFPT_FLOW_REMOVED):
                {
                  ofp_flow_removed *p= (ofp_flow_removed *)buffer->data;
                  if (((p->reason == OFPRR_IDLE_TIMEOUT) && !(r->config.port_status_mask[0] & 0x1)) ||
                      ((p->reason == OFPRR_HARD_TIMEOUT) && !(r->config.port_status_mask[0] & 0x2)) ||
                      ((p->reason == OFPRR_DELETE)       && !(r->config.packet_in_mask[0] & 0x4))   ||
                      ((p->reason == OFPRR_GROUP_DELETE) && !(r->config.packet_in_mask[0] & 0x8))   ||
                      ((p->reason == OFPRR_METER_DELETE) && !(r->config.packet_in_mask[0] & 0x10)))
                    {
                      send = false;
                    }
                }
            }
        }
      else 
        {
          // In this implementation we assume that a controller with role slave
          // is able to receive only port stats messages.
          if (r->role == OFPCR_ROLE_SLAVE && msg_type != OFPT_PORT_STATUS) 
            {
              send = false;
            }
          else 
            {
              struct ofp_port_status *p = (struct ofp_port_status*)buffer->data;
              if (((p->reason == OFPPR_ADD)    && !(r->config.port_status_mask[1] & 0x1)) ||
                  ((p->reason == OFPPR_DELETE) && !(r->config.port_status_mask[1] & 0x2)) ||
                  ((p->reason == OFPPR_MODIFY) && !(r->config.packet_in_mask[1] & 0x4)))
                {
                  send = false;
                }
            }
        }

      if (send)
        {
          return !m_ctrlSocket->Send (ofs::PacketFromBufferAndFree (buffer));
        }
      else 
        {
          ofpbuf_delete(buffer);
          return 0;
        }
    }
}

uint32_t
OFSwitch13NetDevice::GetNSwitchPorts (void) const
{
  return m_ports.size ();
}

uint64_t
OFSwitch13NetDevice::GetDatapathId (void) const
{
  return m_dpId;
}

uint32_t
OFSwitch13NetDevice::GetNextXid ()
{
  return ++m_xid;
}

void
OFSwitch13NetDevice::StartControllerConnection ()
{
  NS_LOG_FUNCTION (this);
  NS_ASSERT (!m_ctrlAddr.IsInvalid ());
  
  // Start a TCP connection to the controller
  if (!m_ctrlSocket)
    {
      int error = 0; 
      m_ctrlSocket = Socket::CreateSocket (GetNode (), TcpSocketFactory::GetTypeId ());
      error = m_ctrlSocket->Bind ();
      if (error)
        {
          NS_LOG_ERROR ("Error binding socket " << error);
          return;
        }
      
      error = m_ctrlSocket->Connect (InetSocketAddress::ConvertFrom (m_ctrlAddr));
      if (error)
        {
          NS_LOG_ERROR ("Error connecting socket " << error);
          return;
        }

      m_ctrlSocket->SetConnectCallback (
          MakeCallback (&OFSwitch13NetDevice::SocketCtrlSucceeded, this),
          MakeCallback (&OFSwitch13NetDevice::SocketCtrlFailed, this));
      return;
    }
  NS_LOG_ERROR ("Controller already set.");
}

// Inherited from NetDevice base class
void
OFSwitch13NetDevice::SetIfIndex (const uint32_t index)
{
  NS_LOG_FUNCTION (this);
  m_ifIndex = index;
}

uint32_t
OFSwitch13NetDevice::GetIfIndex (void) const
{
  NS_LOG_FUNCTION (this);
  return m_ifIndex;
}

Ptr<Channel>
OFSwitch13NetDevice::GetChannel (void) const
{
  NS_LOG_FUNCTION (this);
  return m_channel;
}

void
OFSwitch13NetDevice::SetAddress (Address address)
{
  NS_LOG_FUNCTION (this);
  m_address = Mac48Address::ConvertFrom (address);
  NS_LOG_INFO ("Switch addr " << m_address);
}

Address
OFSwitch13NetDevice::GetAddress (void) const
{
  NS_LOG_FUNCTION (this);
  return m_address;
}

bool
OFSwitch13NetDevice::SetMtu (const uint16_t mtu)
{
  NS_LOG_FUNCTION (this);
  m_mtu = mtu;
  return true;
}

uint16_t
OFSwitch13NetDevice::GetMtu (void) const
{
  NS_LOG_FUNCTION (this);
  return m_mtu;
}

bool
OFSwitch13NetDevice::IsLinkUp (void) const
{
  NS_LOG_FUNCTION (this);
  return true;
}

void
OFSwitch13NetDevice::AddLinkChangeCallback (Callback<void> callback)
{
}

bool
OFSwitch13NetDevice::IsBroadcast (void) const
{
  NS_LOG_FUNCTION (this);
  return true;
}

Address
OFSwitch13NetDevice::GetBroadcast (void) const
{
  NS_LOG_FUNCTION (this);
  return Mac48Address ("ff:ff:ff:ff:ff:ff");
}

bool
OFSwitch13NetDevice::IsMulticast (void) const
{
  NS_LOG_FUNCTION (this);
  return true;
}

Address
OFSwitch13NetDevice::GetMulticast (Ipv4Address multicastGroup) const
{
  NS_LOG_FUNCTION (this << multicastGroup);
  Mac48Address multicast = Mac48Address::GetMulticast (multicastGroup);
  return multicast;
}

Address
OFSwitch13NetDevice::GetMulticast (Ipv6Address addr) const
{
  NS_LOG_FUNCTION (this << addr);
  return Mac48Address::GetMulticast (addr);
}

bool
OFSwitch13NetDevice::IsPointToPoint (void) const
{
  NS_LOG_FUNCTION (this);
  return false;
}

bool
OFSwitch13NetDevice::IsBridge (void) const
{
  NS_LOG_FUNCTION (this);
  return true;
}

bool
OFSwitch13NetDevice::Send (Ptr<Packet> packet, const Address& dest, uint16_t protocolNumber)
{
  NS_LOG_FUNCTION (this);
  return SendFrom (packet, m_address, dest, protocolNumber);
}

bool
OFSwitch13NetDevice::SendFrom (Ptr<Packet> packet, const Address& src, const Address& dest, 
    uint16_t protocolNumber)
{
  NS_LOG_FUNCTION (this);
  return true;
}

Ptr<Node>
OFSwitch13NetDevice::GetNode (void) const
{
  NS_LOG_FUNCTION (this);
  return m_node;
}

void
OFSwitch13NetDevice::SetNode (Ptr<Node> node)
{
  NS_LOG_FUNCTION (this);
  m_node = node;
}

bool
OFSwitch13NetDevice::NeedsArp (void) const
{
  NS_LOG_FUNCTION (this);
  return true;
}

void
OFSwitch13NetDevice::SetReceiveCallback (NetDevice::ReceiveCallback cb)
{
  NS_LOG_FUNCTION (this);
  m_rxCallback = cb;
}

void
OFSwitch13NetDevice::SetPromiscReceiveCallback (NetDevice::PromiscReceiveCallback cb)
{
  NS_LOG_FUNCTION (this);
  m_promiscRxCallback = cb;
}

bool
OFSwitch13NetDevice::SupportsSendFrom () const
{
  NS_LOG_FUNCTION (this);
  return true;
}

/********** Private methods **********/
void
OFSwitch13NetDevice::DoDispose ()
{
  NS_LOG_FUNCTION (this);
  
  // No need to notify the controller that this port has been deleted
  for (ofs::Ports_t::iterator b = m_ports.begin (), e = m_ports.end (); b != e; b++)
    {
      b->netdev = 0;
      ofl_structs_free_port (b->conf);
      free (b->stats);
    }
  m_ports.clear ();
  m_echoMap.clear ();
  
  m_channel = 0;
  m_node = 0;
  m_ctrlSocket = 0;

  // FIXME Theses methods may cause errors... check
  pipeline_destroy (m_datapath->pipeline);
  group_table_destroy (m_datapath->groups);
  meter_table_destroy (m_datapath->meters);

  UnregisterDatapath (m_dpId);
  NetDevice::DoDispose ();
}

datapath*
OFSwitch13NetDevice::DatapathNew ()
{
  datapath* dp = (datapath*)xmalloc (sizeof (datapath));

  dp->mfr_desc = (char*)xmalloc (DESC_STR_LEN); 
  dp->hw_desc = (char*)xmalloc (DESC_STR_LEN);
  dp->sw_desc = (char*)xmalloc (DESC_STR_LEN);
  dp->dp_desc = (char*)xmalloc (DESC_STR_LEN);
  dp->serial_num = (char*)xmalloc (DESC_STR_LEN);
  strncpy (dp->mfr_desc, "The ns-3 team", DESC_STR_LEN);
  strncpy (dp->hw_desc, "N/A", DESC_STR_LEN);
  strncpy (dp->sw_desc, "ns3 OpenFlow datapath version 1.3", DESC_STR_LEN);
  strncpy (dp->dp_desc, "ofsoftswitch13 (from CPqD)", DESC_STR_LEN);
  strncpy (dp->serial_num, "1.1", DESC_STR_LEN);

  dp->id = m_dpId;
  list_init (&dp->remotes);

  // unused
    dp->generation_id = -1;
    dp->listeners = NULL;
    dp->n_listeners = 0;
    dp->listeners_aux = NULL;
    dp->n_listeners_aux = 0;
  // unused

  dp->last_timeout = time_now ();
  
  dp->buffers = dp_buffers_create (dp); 
  dp->pipeline = pipeline_create (dp);
  dp->groups = group_table_create (dp);
  dp->meters = meter_table_create (dp);
  
  dp->config.flags = OFPC_FRAG_NORMAL; // IP fragments with no special handling
  dp->config.miss_send_len = 128;      // send first 128 bytes to controller 
                                       // use OFPCML_NO_BUFFER to send hole ptk
  // unused
    dp->max_queues = 0;
    dp->local_port = NULL;
  // unused
  
  dp->ports_num = 0;
  dp->exp = NULL;
  
  return dp;
}

void
OFSwitch13NetDevice::DatapathTimeout (datapath* dp)
{
  meter_table_add_tokens (dp->meters);
  
  // Check flow entry timeout
  for (int i = 0; i < PIPELINE_TABLES; i++) 
    {
      flow_table_timeout (dp->pipeline->tables[i]);
    }

  // Check for changes in port status
  for (size_t i = 0; i < m_ports.size (); i++)
    {
      ofs::Port *p = &m_ports[i];
      if (PortLiveUpdate (p))
        {
          NS_LOG_DEBUG ("Port configuration has changed. Notifying the controller...");
          ofl_msg_port_status msg;
          msg.header.type = OFPT_PORT_STATUS;
          msg.reason = OFPPR_MODIFY;
          msg.desc = p->conf;

          SendToController ((ofl_msg_header*)&msg);
        }
    }

  Simulator::Schedule (m_timeout , &OFSwitch13NetDevice::DatapathTimeout, this, dp);
  dp->last_timeout = time_now ();
}

void
OFSwitch13NetDevice::DatapathSendEchoRequest ()
{
  NS_LOG_FUNCTION (this);
  
  // Send echo message
  ofl_msg_echo msg;
  msg.header.type = OFPT_ECHO_REQUEST;
  msg.data_length = 0;
  msg.data        = 0;
 
  ofs::EchoInfo echo (InetSocketAddress::ConvertFrom (m_ctrlAddr).GetIpv4 ());
  m_echoMap.insert (std::pair<uint64_t, ofs::EchoInfo> (m_xid, echo));
  SendToController ((ofl_msg_header*)&msg);
  
  Simulator::Schedule (m_echo, &OFSwitch13NetDevice::DatapathSendEchoRequest, this);
}

ofs::Port*
OFSwitch13NetDevice::PortGetOfsPort (Ptr<NetDevice> dev)
{
  NS_LOG_FUNCTION (this << dev);
  for (size_t i = 0; i < m_ports.size (); i++)
    {
      if (m_ports[i].netdev == dev)
        {
          return &m_ports[i];
        }
    }
  NS_LOG_ERROR ("No port found!");
  return NULL;
}

ofs::Port*
OFSwitch13NetDevice::PortGetOfsPort (uint32_t no)
{
  NS_LOG_FUNCTION (this << no);
  NS_ASSERT_MSG (no > 0 && no <= m_ports.size (), "Invalid port number");

  if (m_ports[no-1].port_no == no)
    {
      return &m_ports[no-1];
    }
  
  for (size_t i = 0; i < m_ports.size (); i++)
    {
      if (m_ports[i].port_no == no)
        {
          return &m_ports[i];
        }
    }
  NS_LOG_ERROR ("No port found!");
  return NULL;
}

int
OFSwitch13NetDevice::PortLiveUpdate (ofs::Port *p)
{
  uint32_t orig_config = p->conf->config;
  uint32_t orig_state = p->conf->state;

  // Port is always enabled
  p->conf->config &= ~OFPPC_PORT_DOWN;

  if (p->netdev->IsLinkUp ())
    {
       p->conf->state &= ~OFPPS_LINK_DOWN;
    }
  else
    {
       p->conf->state |= OFPPS_LINK_DOWN;
    }

  return ((orig_config != p->conf->config) || 
          (orig_state !=  p->conf->state));
}

void 
OFSwitch13NetDevice::PortStatsUpdate (ofs::Port *p)
{
  p->stats->duration_sec  =  (time_msec() - p->created) / 1000;
  p->stats->duration_nsec = ((time_msec() - p->created) % 1000) * 1000;
}

ofl_err
OFSwitch13NetDevice::PortMultipartStats (datapath *dp, 
    ofl_msg_multipart_request_port *msg, const sender *sender)
{
  NS_LOG_FUNCTION (this);
  
  ofs::Port *port;
  size_t i = 0;

  ofl_msg_multipart_reply_port reply;
  reply.header.header.type = OFPT_MULTIPART_REPLY;
  reply.header.type  = OFPMP_PORT_STATS;
  reply.header.flags = 0x0000;
  
  if (msg->port_no == OFPP_ANY) 
    {
      reply.stats_num = GetNSwitchPorts ();
      reply.stats = (ofl_port_stats**)xmalloc (sizeof (ofl_port_stats*) * reply.stats_num);

      // Using port number (not position in vector)
      for (i = 1; i <= GetNSwitchPorts (); i++)
        {
          port = PortGetOfsPort (i);
          PortStatsUpdate (port);
          reply.stats[i-1] = port->stats;
        }
    } 
  else 
    {
      port = PortGetOfsPort (msg->port_no);
      if (port != NULL && port->netdev != NULL) 
        {
          reply.stats_num = 1;
          reply.stats = (ofl_port_stats**)xmalloc (sizeof (ofl_port_stats*));
          PortStatsUpdate (port);
          reply.stats[0] = port->stats;
        }
    }
  SendToController ((ofl_msg_header*)&reply, sender);

  free (reply.stats);
  ofl_msg_free ((ofl_msg_header*)msg, dp->exp);
  return 0;
}

ofl_err
OFSwitch13NetDevice::PortMultipartDesc (datapath *dp, 
    ofl_msg_multipart_request_header *msg, const sender *sender)
{
  NS_LOG_FUNCTION (this);
  
  ofs::Port *port;
  size_t i = 0;
  
  ofl_msg_multipart_reply_port_desc reply;
  reply.header.header.type = OFPT_MULTIPART_REPLY;
  reply.header.type  = OFPMP_PORT_DESC;
  reply.header.flags = 0x0000;
  reply.stats_num    = GetNSwitchPorts ();
  reply.stats = (ofl_port**)xmalloc (sizeof (ofl_port*) * reply.stats_num);
  
  // Using port number (not position in vector)
  for (i = 1; i <= GetNSwitchPorts (); i++)
    {
      port = PortGetOfsPort (i);
      reply.stats[i-1] = port->conf;
    }
  SendToController ((ofl_msg_header*)&reply, sender);
  
  free (reply.stats);
  ofl_msg_free ((ofl_msg_header*)msg, dp->exp);
  return 0;
}

ofl_err
OFSwitch13NetDevice::PortHandlePortMod (datapath *dp, ofl_msg_port_mod *msg, 
    const sender *sender) 
{
  NS_LOG_FUNCTION (this);
  
  ofs::Port *p = PortGetOfsPort (msg->port_no);
  if (p == NULL) 
    {
      return ofl_error (OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_PORT);
    }

  // Make sure the port id hasn't changed since this was sent
  uint8_t p_addr[ETH_ADDR_LEN];
  p->netdev->GetAddress ().CopyTo (p_addr);
  if (memcmp (msg->hw_addr, p_addr, ETH_ADDR_LEN) != 0) 
    {
      return ofl_error (OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_HW_ADDR);
    }

  if (msg->mask) 
    {
      p->conf->config &= ~msg->mask;
      p->conf->config |= msg->config & msg->mask;
      if ((p->conf->state & OFPPS_LINK_DOWN) || 
          (p->conf->config & OFPPC_PORT_DOWN)) 
        {
          // Port not live
          p->conf->state &= ~OFPPS_LIVE;
        } 
      else 
        {
          // Port is live
          p->conf->state |= OFPPS_LIVE;
        }
    }

  // Notify the controller that the port status has changed
  ofl_msg_port_status reply;
  reply.header.type = OFPT_PORT_STATUS;
  reply.reason = OFPPR_MODIFY; 
  reply.desc = p->conf;
  
  SendToController ((ofl_msg_header*)&reply, sender);

  ofl_msg_free ((ofl_msg_header*)msg, dp->exp);
  return 0;
}

void
OFSwitch13NetDevice::ReceiveFromSwitchPort (Ptr<NetDevice> netdev, 
    Ptr<const Packet> packet, uint16_t protocol, const Address &src, 
    const Address &dst, PacketType packetType)
{
  NS_LOG_FUNCTION (this);
  
  Mac48Address src48 = Mac48Address::ConvertFrom (src);
  Mac48Address dst48 = Mac48Address::ConvertFrom (dst);
  
  NS_LOG_LOGIC ("Switch id " << this->GetNode()->GetId() << 
                " received packet type " << packetType << 
                " with uid " << packet->GetUid () <<
                " from " << src48 << " looking for " << dst48);

  // For all kinds of packetType we receive, we hit the promiscuous sniffer
  if (!m_promiscRxCallback.IsNull ())
    {
      m_promiscRxCallback (this, packet, protocol, src, dst, packetType);
    }

  // This method is called after the Csma switch port received the packet. The
  // CsmaNetDevice has already classified the packetType.
  switch (packetType)
    {
      // For PACKET_BROADCAST or PACKET_MULTICAST, forward the packet up AND let
      // the pipeline process it to get it forwarded.
      case PACKET_BROADCAST:
      case PACKET_MULTICAST:
        m_rxCallback (this, packet, protocol, src);
        break;

      // For PACKET_OTHERHOST or PACKET_HOST check if it is addressed to this
      // switch to forward it up OR let the pipeline process it.  
      case PACKET_HOST:
      case PACKET_OTHERHOST:
        if (dst48 == m_address)
          {
            // Packets addressed only to this switch will skip OpenFlow pipeline.
            m_rxCallback (this, packet, protocol, src);
            return;
          }
        break;
    }

  // Preparing the pipeline process...
  // Get the input port and check configuration
  ofs::Port* inPort = PortGetOfsPort (netdev);
  NS_ASSERT_MSG (inPort != NULL, "This device is not registered as a switch port");
  if (inPort->conf->config & ((OFPPC_NO_RECV | OFPPC_PORT_DOWN) != 0)) 
    {
      NS_LOG_WARN ("This port is down or inoperating. Discarding packet");
      return;
    }

  // Adding the ethernet header back to the packet. It was removed by
  // CsmaNetDevice but we need L2 information for the pipeline. It will be
  // removed when outputing the packet by SendToSwitchPort method.
  Ptr<Packet> pktCopy = packet->Copy ();
  AddEthernetHeader (pktCopy, src48, dst48, protocol);

  // Buffering the packet and creating the internal openflow packet structure
  // from buffer. Allocate buffer with some headroom to add headers in
  // forwarding to the controller or adding a vlan tag, plus an extra 2 bytes
  // to allow IP headers to be aligned on a 4-byte boundary.
  uint32_t headRoom = 128 + 2;
  uint32_t bodyRoom = netdev->GetMtu () + VLAN_ETH_HEADER_LEN;
  ofpbuf *buffer = ofs::BufferFromPacket (pktCopy, bodyRoom, headRoom);
  struct packet *pkt = packet_create (m_datapath, inPort->stats->port_no, 
      buffer, false);

  // Update port stats
  inPort->stats->rx_packets++;
  inPort->stats->rx_bytes += buffer->size;

  // Runs the packet through the pipeline
  Simulator::Schedule (m_lookupDelay, &OFSwitch13NetDevice::PipelineProcessPacket, 
      this, m_datapath->pipeline, pkt);
}

void
OFSwitch13NetDevice::AddEthernetHeader (Ptr<Packet> packet, Mac48Address source, 
    Mac48Address dest, uint16_t protocolNumber)
{
  NS_LOG_FUNCTION (packet << source << dest << protocolNumber);

  EthernetHeader header (false);
  header.SetSource (source);
  header.SetDestination (dest);

  EthernetTrailer trailer;
  if (packet->GetSize () < 46)
    {
      uint8_t buffer[46];
      memset (buffer, 0, 46);
      Ptr<Packet> padd = Create<Packet> (buffer, 46 - packet->GetSize ());
      packet->AddAtEnd (padd);
    }

  header.SetLengthType (protocolNumber);
  packet->AddHeader (header);

  if (Node::ChecksumEnabled ())
    {
      trailer.EnableFcs (true);
    }
  trailer.CalcFcs (packet);
  packet->AddTrailer (trailer);
}

bool
OFSwitch13NetDevice::SendToSwitchPort (packet *pkt, ofs::Port *port)
{
  NS_LOG_FUNCTION (this);
  
  if (port == 0 || port->netdev == 0)
    {
      NS_LOG_ERROR ("can't forward to invalid port.");
      return false;
    }
  
  if ((port->conf->config & ((OFPPC_NO_RECV | OFPPC_PORT_DOWN))) == 0)
    {
      // Removing the ethernet header and trailer from packet, which will be
      // included again by CsmaNetDevice
      Ptr<Packet> packet = ofs::PacketFromInternalPacket (pkt);
      EthernetTrailer trailer;
      packet->RemoveTrailer (trailer);
      
      EthernetHeader header;
      packet->RemoveHeader (header);

      bool status = port->netdev->SendFrom (packet, header.GetSource (),
          header.GetDestination (), header.GetLengthType ());
      if (status)
        {
          port->stats->tx_packets++;
          port->stats->tx_bytes += packet->GetSize ();
        }
      else
        {
          port->stats->tx_dropped++;
        }
      return status;
    }
  NS_LOG_ERROR ("can't forward to bad port " << port->port_no);
  return false;
}

bool
OFSwitch13NetDevice::FloodToSwitchPorts (packet *pkt)
{
  ofs::Port *p;
  for (uint32_t i = 1; i <= GetNSwitchPorts (); i++)
    {
      p = PortGetOfsPort (i);
      if (p->port_no == pkt->in_port)
        {
          continue;
        }
      SendToSwitchPort (pkt, p);
    }
  return true;
}

void
OFSwitch13NetDevice::PipelineProcessPacket (pipeline* pl, packet* pkt)
{
  NS_LOG_FUNCTION (this << packet_to_string (pkt));
  
  flow_entry *entry;
  flow_table *table, *next_table;
  
  // Check ttl
  if (!packet_handle_std_is_ttl_valid (pkt->handle_std)) 
    {
      if ((pl->dp->config.flags & OFPC_INVALID_TTL_TO_CONTROLLER) != 0) 
        {
          NS_LOG_WARN ("Packet has invalid TTL, sending to controller.");
          PipelineSendPacketIn (pl, pkt, 0, OFPR_INVALID_TTL, UINT64_MAX);
        } 
      else 
        {
          NS_LOG_WARN ("Packet has invalid TTL, dropping.");
        }
      packet_destroy (pkt);
      return;
    }
  
  // Look for a match in flow tables
  next_table = pl->tables[0];
  while (next_table != NULL) 
    {
      NS_LOG_DEBUG ("trying table " << (short)next_table->stats->table_id);
  
      pkt->table_id = next_table->stats->table_id;
      table = next_table;
      next_table = NULL;
  
      NS_LOG_DEBUG ("searching table entry for packet match: " <<  
          ofl_structs_match_to_string ((ofl_match_header*)&(pkt->handle_std->match), 
              pl->dp->exp));
  
      entry = flow_table_lookup (table, pkt);
      if (entry != NULL) 
        {
          NS_LOG_DEBUG ("found matching entry: " << 
              ofl_structs_flow_stats_to_string (entry->stats, pkt->dp->exp));
       
          pkt->handle_std->table_miss = ((entry->stats->priority) == 0 && 
                                         (entry->match->length <= 4));
          PipelineExecuteEntry (pl, entry, &next_table, &pkt);
          
          // Packet could be destroyed by a meter instruction
          if (!pkt)
            {
              return;
            }
  
          if (next_table == NULL) 
            {
              // Pipeline end. Execute actions and free packet
              ActionSetExecute (pkt->action_set, pkt, UINT64_MAX);
              packet_destroy (pkt);
              return;
            }
        } 
      else 
        {
          // OpenFlow 1.3 default behavior on a table miss
          NS_LOG_DEBUG ("No matching entry found. Dropping packet.");
          packet_destroy (pkt);
          return;
        }
    }
  NS_LOG_ERROR ("Reached outside of pipeline processing cycle.");
}

void
OFSwitch13NetDevice::PipelineExecuteEntry (pipeline* pl, flow_entry *entry,
    flow_table **next_table, packet **pkt)
{
   NS_LOG_FUNCTION (this);
  
  // Instructions, when present, will be executed in the following order:
  // Meter, Apply-Actions, Clear-Actions, Write-Actions, Write-Metadata, and
  // Goto-Table.
  size_t i;
  ofl_instruction_header *inst;

  for (i=0; i < entry->stats->instructions_num; i++) 
    {
      // Packet was dropped by some instruction or action*/
      if(!(*pkt))
        {
          return;
        }
      
      inst = entry->stats->instructions[i];
      switch (inst->type) 
        {
          case OFPIT_GOTO_TABLE: 
            {
              ofl_instruction_goto_table *gi = (ofl_instruction_goto_table*)inst;
              *next_table = pl->tables[gi->table_id];
              break;
            }
          case OFPIT_WRITE_METADATA: 
            {
              ofl_instruction_write_metadata *wi = (ofl_instruction_write_metadata*)inst;
              ofl_match_tlv *f;

              packet_handle_std_validate ((*pkt)->handle_std);
              
              // Search field on the description of the packet.
              HMAP_FOR_EACH_WITH_HASH (f, ofl_match_tlv, hmap_node, 
                  HashInt (OXM_OF_METADATA, 0), &(*pkt)->handle_std->match.match_fields)
                {
                  uint64_t *metadata = (uint64_t*) f->value;
                  *metadata = (*metadata & ~wi->metadata_mask) | 
                              (wi->metadata & wi->metadata_mask);
                  NS_LOG_DEBUG ("Executing write metadata: " << *metadata);
                }
              break;
            }
          case OFPIT_WRITE_ACTIONS: 
            {
              ofl_instruction_actions *wa = (ofl_instruction_actions*)inst;
              action_set_write_actions ((*pkt)->action_set, wa->actions_num, wa->actions);
              break;
            }
          case OFPIT_APPLY_ACTIONS: 
            {
              ofl_instruction_actions *ia = (ofl_instruction_actions*)inst;
              ActionsListExecute ((*pkt), ia->actions_num, ia->actions, entry->stats->cookie);
              break;
            }
          case OFPIT_CLEAR_ACTIONS: 
            {
              action_set_clear_actions ((*pkt)->action_set);
              break;
            }
          case OFPIT_METER: 
            {
              ofl_instruction_meter *im = (ofl_instruction_meter*)inst;
              meter_table_apply (pl->dp->meters, pkt, im->meter_id);
              break;
            }
          case OFPIT_EXPERIMENTER: 
            {
              // dp_exp_inst((*pkt), (ofl_instruction_experimenter*)inst);
              break;
            }
        }
    }
}

ofl_err
OFSwitch13NetDevice::PipelineHandleFlowMod (pipeline *pl, ofl_msg_flow_mod *msg, 
    const sender *sender)
{
  NS_LOG_FUNCTION (this);
  
  // Modifications to a flow table from the controller are done with the
  // OFPT_FLOW_MOD message (including add, modify or delete).
  // \see ofsoftswitch13 pipeline_handle_flow_mod () at udatapath/pipeline.c
  // and flow_table_flow_mod () at udatapath/flow_table.c
  ofl_err error;
  size_t i;
  bool match_kept, insts_kept;
  match_kept = false;
  insts_kept = false;
  
  // Sort by execution oder
  qsort (msg->instructions, msg->instructions_num, 
      sizeof (ofl_instruction_header*), inst_compare);
  
  // Validate actions in flow_mod
  for (i = 0; i < msg->instructions_num; i++) 
    {
      if (msg->instructions[i]->type == OFPIT_APPLY_ACTIONS || 
          msg->instructions[i]->type == OFPIT_WRITE_ACTIONS) 
        {
          ofl_instruction_actions *ia = (ofl_instruction_actions*)msg->instructions[i];
  
          error = ActionsValidate (pl->dp, (size_t)ia->actions_num, ia->actions);
          if (error) 
            {
              return error;
            }
          error = dp_actions_check_set_field_req (msg, ia->actions_num, ia->actions);
          if (error) 
            {
              return error;
            }
        }
      // Reject goto in the last table.
      if ((msg->table_id == (PIPELINE_TABLES - 1)) && 
          (msg->instructions[i]->type == OFPIT_GOTO_TABLE))
        {
          return ofl_error (OFPET_BAD_INSTRUCTION, OFPBIC_UNSUP_INST);
        }
    }
  
  if (msg->table_id == 0xff) 
    {
      // Note: the result of using table_id = 0xff is undefined in the spec.
      // For now it is accepted for delete commands, meaning to delete from
      // all tables 
      if (msg->command == OFPFC_DELETE || 
          msg->command == OFPFC_DELETE_STRICT) 
        {
          size_t i;
          error = 0;
          for (i = 0; i < PIPELINE_TABLES; i++) 
            {
              error = flow_table_flow_mod (pl->tables[i], msg, &match_kept, &insts_kept);
              if (error) 
                {
                  break;
                }
            }
          if (error) 
            {
              return error;
            } 
          else 
            {
              ofl_msg_free_flow_mod (msg, !match_kept, !insts_kept, pl->dp->exp);
              return 0;
            }
        }
      else
        {
          return ofl_error (OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_TABLE_ID);
        }
    }
  else
    {
      // Execute flow modification at proper table
      error = flow_table_flow_mod (pl->tables[msg->table_id], msg, &match_kept, &insts_kept); 
      if (error) 
        {
          return error;
        }
      
      if ((msg->command == OFPFC_ADD || msg->command == OFPFC_MODIFY || 
           msg->command == OFPFC_MODIFY_STRICT) && msg->buffer_id != NO_BUFFER) 
        {
          // Run buffered message through pipeline
          packet *pkt;
          pkt = dp_buffers_retrieve (pl->dp->buffers, msg->buffer_id);
          if (pkt != NULL) 
            {
              PipelineProcessPacket (pl, pkt);
            } 
          else 
            {
              NS_LOG_ERROR ("The buffer flow_mod referred to was empty " << 
                  msg->buffer_id);
            }
        }
      
      // All handlers must free the message when everything is ok
      ofl_msg_free_flow_mod (msg, !match_kept, !insts_kept, pl->dp->exp);
      return 0;
    }
}

int
OFSwitch13NetDevice::PipelineSendPacketIn (pipeline* pl, packet *pkt, 
    uint8_t tableId, ofp_packet_in_reason reason, uint64_t cookie)
{
  NS_LOG_FUNCTION (this); 
  
  ofl_msg_packet_in msg;
  msg.header.type = OFPT_PACKET_IN;
  msg.total_len = pkt->buffer->size;
  msg.reason = reason;
  msg.table_id = tableId;
  msg.data = (uint8_t*)pkt->buffer->data;
  msg.cookie = cookie;

  if (pl->dp->config.miss_send_len != OFPCML_NO_BUFFER)
    {
      dp_buffers_save (pl->dp->buffers, pkt);
      msg.buffer_id = pkt->buffer_id;
      msg.data_length = MIN (pl->dp->config.miss_send_len, pkt->buffer->size);
    }
  else 
    {
      msg.buffer_id = OFP_NO_BUFFER;
      msg.data_length = pkt->buffer->size;
    }

  if (!pkt->handle_std->valid)
    {
      packet_handle_std_validate (pkt->handle_std);
    }
  msg.match = (ofl_match_header*)&pkt->handle_std->match;
 
  return SendToController ((ofl_msg_header*)&msg);
}

void
OFSwitch13NetDevice::ActionsListExecute (packet *pkt, size_t actions_num,
    ofl_action_header **actions, uint64_t cookie) 
{
  NS_LOG_FUNCTION (this);
  
  size_t i;
  for (i=0; i < actions_num; i++) 
    {
      dp_execute_action (pkt, actions[i]);
      if (pkt->out_group != OFPG_ANY) 
        {
          uint32_t group = pkt->out_group;
          pkt->out_group = OFPG_ANY;
          NS_LOG_DEBUG ("Group action; executing group " << group);
          GroupTableExecute (pkt->dp->groups, pkt, group); 
        } 
      else if (pkt->out_port != OFPP_ANY) 
        {
          uint32_t port = pkt->out_port;
          uint32_t queue = pkt->out_queue;
          uint16_t max_len = pkt->out_port_max_len;
          pkt->out_port = OFPP_ANY;
          pkt->out_port_max_len = 0;
          pkt->out_queue = 0;
          NS_LOG_DEBUG ("Port list action; sending to port " << port);
          ActionOutputPort (pkt, port, queue, max_len, cookie);
        }
    }
}

void
OFSwitch13NetDevice::ActionSetExecute (action_set *set, packet *pkt,  
    uint64_t cookie)
{
  NS_LOG_FUNCTION (this);
  
  action_set_entry *entry, *next;

  LIST_FOR_EACH_SAFE (entry, next, action_set_entry, node, &set->actions) 
    {
      dp_execute_action (pkt, entry->action);
      list_remove (&entry->node);
      free (entry);

      // According to the spec. if there was a group action, 
      // the output port action should be ignored
      if (pkt->out_group != OFPG_ANY) 
        {
          uint32_t group_id = pkt->out_group;
          pkt->out_group = OFPG_ANY;
          action_set_clear_actions (pkt->action_set);
          GroupTableExecute (pkt->dp->groups, pkt, group_id);
          return;
        } 
      else if (pkt->out_port != OFPP_ANY) 
        {
          uint32_t port = pkt->out_port;
          uint32_t queue = pkt->out_queue;
          uint16_t max_len = pkt->out_port_max_len;
          pkt->out_port = OFPP_ANY;
          pkt->out_port_max_len = 0;
          pkt->out_queue = 0;
          action_set_clear_actions (pkt->action_set);
          
          NS_LOG_DEBUG ("Port set action; sending to port " << port);
          ActionOutputPort (pkt, port, queue, max_len, cookie);
          return;
        }
    }
}

void
OFSwitch13NetDevice::ActionOutputPort (packet *pkt, uint32_t out_port,
    uint32_t out_queue, uint16_t max_len, uint64_t cookie) 
{
  NS_LOG_FUNCTION (this);
  
  switch (out_port) 
    {
      case (OFPP_TABLE): 
        if (pkt->packet_out) 
          {
            pkt->packet_out = false;
            PipelineProcessPacket (pkt->dp->pipeline, pkt);
          } 
        else 
          {
            NS_LOG_WARN ("Trying to resubmit packet to pipeline.");
          }
        break;
      case (OFPP_IN_PORT):
        {
          ofs::Port *p = PortGetOfsPort (pkt->in_port);
          SendToSwitchPort (pkt, p);
          break;
        }
      case (OFPP_CONTROLLER): 
        {
          PipelineSendPacketIn (pkt->dp->pipeline, pkt, pkt->table_id, 
              (pkt->handle_std->table_miss ? OFPR_NO_MATCH : OFPR_ACTION), cookie);
          break;
        }
      case (OFPP_FLOOD):
      case (OFPP_ALL): 
        {
          FloodToSwitchPorts (pkt);
          break;
        }
      case (OFPP_NORMAL):
      case (OFPP_LOCAL):
      default: 
        if (pkt->in_port == out_port) 
          {
            NS_LOG_WARN ("Can't directly forward to input port.");
          } 
        else 
          {
            NS_LOG_DEBUG ("Outputting packet on port " << out_port);
            ofs::Port *p = PortGetOfsPort (out_port);
            SendToSwitchPort (pkt, p);
          }
    }
}

ofl_err 
OFSwitch13NetDevice::ActionsValidate (datapath *dp, size_t num, 
    ofl_action_header **actions)
{
  NS_LOG_FUNCTION (this);
  
  for (size_t i = 0; i < num; i++) 
    {
      if (actions[i]->type == OFPAT_OUTPUT) 
        {
          ofl_action_output *ao = (ofl_action_output*)actions[i];
          if (ao->port <= OFPP_MAX && !(PortGetOfsPort (ao->port) != NULL)) 
            {
              NS_LOG_WARN ("Output action for invalid port " << ao->port);
              return ofl_error (OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT);
            }
        }
      
      if (actions[i]->type == OFPAT_GROUP) 
        {
          ofl_action_group *ag = (ofl_action_group*)actions[i];
          if (ag->group_id <= OFPG_MAX && 
              group_table_find (dp->groups, ag->group_id) == NULL) 
            {
              NS_LOG_WARN ("Group action for invalid group " << ag->group_id);
              return ofl_error (OFPET_BAD_ACTION, OFPBAC_BAD_OUT_GROUP);
            }
        }
      
    }
  return 0;
}

void 
OFSwitch13NetDevice::GroupTableExecute (group_table *table, packet *packet, 
    uint32_t group_id)
{
  group_entry *entry;
  entry = group_table_find (table, group_id);

  if (entry == NULL) 
    {
      NS_LOG_WARN ("Trying to execute non-existing group " << group_id);
      return;
    }
  GroupEntryExecute (entry, packet);
}
  
void 
OFSwitch13NetDevice::GroupEntryExecute (group_entry *entry, packet *pkt)
{
  NS_LOG_DEBUG ("Executing group " << entry->stats->group_id);
  
  // NOTE: Packet is copied for all buckets now (even if there is only one).
  // This allows execution of the original packet onward. It is not clear
  // whether that is allowed or not according to the spec. though.
  size_t i;
  switch (entry->desc->type) 
    {
      case (OFPGT_ALL):
        {
          for (i = 0; i < entry->desc->buckets_num; i++) 
            {
              GroupEntryExecuteBucket (entry, pkt, i);
            }
          break;
        }
      case (OFPGT_SELECT):
        {
          i = select_from_select_group (entry);
          if ((int)i != -1)
            {
              GroupEntryExecuteBucket (entry, pkt, i);
            } 
          else 
            {
              NS_LOG_WARN ("No bucket in group.");
            }
          break;
        }
      case (OFPGT_INDIRECT): 
        {
          if (entry->desc->buckets_num > 0) 
            {
              GroupEntryExecuteBucket (entry, pkt, 0);
            } 
          else 
            {
              NS_LOG_WARN ("No bucket in group.");
            }
          break;
        }
      case (OFPGT_FF): 
        {
          i = select_from_ff_group (entry);
          if ((int)i != -1)
            {
              GroupEntryExecuteBucket (entry, pkt, i);
            } 
          else 
            {
              NS_LOG_WARN ("No bucket in group.");
            }
          break;
        }
      default: 
        NS_LOG_WARN ("Trying to execute unknown group type " << 
            entry->desc->type << " in group " << entry->stats->group_id);
    }
}

void 
OFSwitch13NetDevice::GroupEntryExecuteBucket (group_entry *entry, packet *pkt, size_t i)
{
  // Currently packets are always cloned. However it should be possible to see
  // if cloning is necessary, or not, based on bucket actions.
  ofl_bucket *bucket = entry->desc->buckets[i];
  packet *p = packet_clone (pkt);

  char *s = ofl_structs_bucket_to_string (bucket, entry->dp->exp);
  NS_LOG_DEBUG ("Writing bucket: " << s);
  free (s);

  action_set_write_actions (p->action_set, bucket->actions_num, bucket->actions);

  entry->stats->byte_count += p->buffer->size;
  entry->stats->packet_count++;
  entry->stats->counters[i]->byte_count += p->buffer->size;
  entry->stats->counters[i]->packet_count++;

  // Cookie field is set UINT64_MAX because we 
  // cannot associate to any particular flow
  ActionSetExecute (p->action_set, p, UINT64_MAX);
  packet_destroy (p);
}

ofl_err 
OFSwitch13NetDevice::GroupHandleGroupMod (group_table *table, ofl_msg_group_mod *msg, 
    const sender *sender)
{
  NS_LOG_FUNCTION (this);
  
  // Modifications to group table from the controller are done with the
  // OFPT_FLOW_MOD message (including add, modify or delete).
  // \see group_table_handle_group_mod () at udatapath/group_table.c
  ofl_err error;
  size_t i;

  for (i = 0; i< msg->buckets_num; i++) 
    {
      error = ActionsValidate (table->dp, msg->buckets[i]->actions_num, 
          msg->buckets[i]->actions);
      if (error) 
        {
          return error;
        }
    }

  switch (msg->command) 
    {
      case (OFPGC_ADD):
        return group_table_add (table, msg);
      
      case (OFPGC_MODIFY):
        return group_table_modify (table, msg);

      case (OFPGC_DELETE):
        return group_table_delete (table, msg);

      default:
        return ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
    }
}

ofl_err
OFSwitch13NetDevice::HandleControlMessage (datapath *dp, ofl_msg_header *msg, 
    const sender *sender)
{ 
  NS_LOG_FUNCTION (this);

  // Only some control message handlers were reimplemented. The other still use
  // existing library functions.
  switch (msg->type)
    {
      case OFPT_ECHO_REPLY:
        return HandleMsgEchoReply (dp, (ofl_msg_echo*)msg, sender);
      
      case OFPT_PACKET_OUT:
        return HandleMsgPacketOut (dp, (ofl_msg_packet_out*)msg, sender);
      
      case OFPT_FLOW_MOD:
        return PipelineHandleFlowMod (dp->pipeline, (ofl_msg_flow_mod*)msg, sender); 
      
      case OFPT_GROUP_MOD:
        return GroupHandleGroupMod (dp->groups, (ofl_msg_group_mod*)msg, sender);
      
      case OFPT_PORT_MOD:
        return PortHandlePortMod (dp, (ofl_msg_port_mod*)msg, sender);
      
      case OFPT_MULTIPART_REQUEST:
        return HandleControlMultipartRequest (dp, 
            (ofl_msg_multipart_request_header*)msg, sender);
      
      // Currently not supported
      case OFPT_EXPERIMENTER:
      case OFPT_ROLE_REQUEST:
      case OFPT_QUEUE_GET_CONFIG_REQUEST:
        return ofl_error (OFPET_BAD_REQUEST, OFPGMFC_BAD_TYPE);

      default: 
        return handle_control_msg (dp, msg, sender);
    }
}

ofl_err 
OFSwitch13NetDevice::HandleControlMultipartRequest (datapath *dp, 
    ofl_msg_multipart_request_header *msg, const sender *sender)
{
  NS_LOG_FUNCTION (this);

  // Only port_stats e port_desc need to be reimplemented
  switch (msg->type) 
    {
      case (OFPMP_PORT_STATS): 
        return PortMultipartStats (dp, (ofl_msg_multipart_request_port*)msg, sender); 
      
      case OFPMP_PORT_DESC:
        return PortMultipartDesc (dp, msg, sender);
      
      default: 
        return handle_control_stats_request (dp, msg, sender);
    }
}


ofl_err
OFSwitch13NetDevice::HandleMsgEchoReply (datapath *dp, ofl_msg_echo *msg, 
    const sender *sender) 
{
  NS_LOG_FUNCTION (this);
 
  ofs::EchoMsgMap_t::iterator it = m_echoMap.find (sender->xid);
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
  ofl_msg_free ((ofl_msg_header*)msg, dp->exp);
  return 0;
}

ofl_err
OFSwitch13NetDevice::HandleMsgPacketOut (datapath *dp, ofl_msg_packet_out *msg, 
    const sender *sender) 
{
  NS_LOG_FUNCTION (this);
  
  packet *pkt;
  int error;

  error = ActionsValidate (dp, msg->actions_num, msg->actions);
  if (error) 
    {
      return error;
    }

  if (msg->buffer_id == NO_BUFFER) 
    {
      ofpbuf *buf;
      buf = ofpbuf_new (0);
      ofpbuf_use (buf, msg->data, msg->data_length);
      ofpbuf_put_uninit (buf, msg->data_length);
      pkt = packet_create (dp, msg->in_port, buf, true);
    } 
  else 
    {
      // NOTE: in this case packet should not have data
      pkt = dp_buffers_retrieve (dp->buffers, msg->buffer_id);
    }

  if (pkt == NULL) 
    {
      // This might be a wrong req., or a timed out buffer
      return ofl_error (OFPET_BAD_REQUEST, OFPBRC_BUFFER_EMPTY);
    }
  
  ActionsListExecute (pkt, msg->actions_num, msg->actions, UINT64_MAX);
  packet_destroy (pkt);
  
  // All handlers must free the message when everything is ok
  ofl_msg_free_packet_out (msg, false, dp->exp);
  return 0;
}

void 
OFSwitch13NetDevice::SocketCtrlRead (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  Ptr<Packet> packet;
  Address from;
  ofl_msg_header *msg;
  ofl_err error;

  while ((packet = socket->RecvFrom (from)))
    {
      if (packet->GetSize () == 0)
        { //EOF
          break;
        }
      if (InetSocketAddress::IsMatchingType (from))
        {
          NS_LOG_LOGIC ("At time " << Simulator::Now ().GetSeconds ()
                       << "s the OpenFlow switch received "
                       <<  packet->GetSize () << " bytes from controller "
                       << InetSocketAddress::ConvertFrom(from).GetIpv4 ()
                       << " port " << InetSocketAddress::ConvertFrom (from).GetPort ());

          // Get the openflow buffer, unpack the message and send to handler
          ofpbuf *buffer = ofs::BufferFromPacket (packet, packet->GetSize ());
          
          // Gets the single remote in datapath (first in list).
          struct sender sender;
          sender.remote = CONTAINER_OF (list_front (&m_datapath->remotes), remote, node);
          sender.conn_id = 0; // No auxiliary connections 

          error = ofl_msg_unpack ((uint8_t*)buffer->data, buffer->size, &msg, 
                      &sender.xid, m_datapath->exp);

          if (!error)
            {
              char *msg_str = ofl_msg_to_string (msg, m_datapath->exp);
              NS_LOG_DEBUG ("Rx from ctrl: " << msg_str);
              free (msg_str);
              
              error = HandleControlMessage (m_datapath, msg, &sender);
              if (error)
                {
                  // NOTE: It is assumed that if a handler returns with error,
                  // it did not use any part of the control message, thus it
                  // can be freed up. If no error is returned however, the
                  // message must be freed inside the handler (because the
                  // handler might keep parts of the message) 
                  ofl_msg_free (msg, m_datapath->exp);
                }
            }
          if (error)
            {
              NS_LOG_WARN ("Error processing OpenFlow message received from controller.");
              // Notify the controller
              ofl_msg_error err;
              err.header.type = OFPT_ERROR;
              err.type = (ofp_error_type)ofl_error_type (error);
              err.code = ofl_error_code (error);
              err.data_length = buffer->size;
              err.data = (uint8_t*)buffer->data;
              
              SendToController ((ofl_msg_header*)&err, &sender);
            }
          ofpbuf_delete (buffer);
        }
    }
}

void
OFSwitch13NetDevice::SocketCtrlSucceeded (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_LOGIC ("Controller accepted connection request!");
  socket->SetRecvCallback (MakeCallback (&OFSwitch13NetDevice::SocketCtrlRead, this));

  // Randomize local xid
  m_xid = rand () & UINT32_MAX;

  // Save remote info in datapath
  remote_create (m_datapath, NULL, NULL);

  // Send Hello message
  ofl_msg_header msg;
  msg.type = OFPT_HELLO;
  SendToController (&msg);
  
  // Schedule first echo message
  Simulator::Schedule (m_echo, &OFSwitch13NetDevice::DatapathSendEchoRequest, this);
}

void
OFSwitch13NetDevice::SocketCtrlFailed (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_ERROR ("Controller did not accepted connection request!");
}

} // ------------- namespace ns3 -------------
#endif // NS3_OFSWITCH13
