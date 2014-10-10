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
#include "ns3/integer.h"             
#include "ns3/uinteger.h"            
#include "ns3/log.h"                 
#include "ns3/ethernet-header.h"     
#include "ns3/ethernet-trailer.h"    
#include "ns3/tcp-header.h"          
#include "ns3/inet-socket-address.h"
                                     
using namespace ns3;                 
                                     
NS_LOG_COMPONENT_DEFINE ("OFSwitch13NetDevice");
                                     
/**                                  
 * As the integration of ofsoftswitch13 and ns3 involve overriding some C
 * functions, we are using a global map to store a pointer to all
 * OFSwitch13NetDevices objects in simulation, and allow faster object retrive
 * by datapath id. In this way, functions like dp_send_message /
 * dp_ports_output can get the object pointer and call SendToController
 * SendToSwitchPort methods. 
 */
static std::map<uint64_t, Ptr<OFSwitch13NetDevice> > g_switchMap;

/** 
 * Insert a new openflow device in global map. Called by device constructor.
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
 * Remove an existing openflow device from global map. Called by DoDispose.
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
 * Retrieve and existing openflow device object by its datapath id 
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

// ---- OpenFlow port code -------------------------------
uint32_t 
OfPort::PortGetFeatures ()
{
  DataRateValue drv;
  DataRate dr;
  Ptr<CsmaChannel> channel = DynamicCast<CsmaChannel> (netdev->GetChannel ());
  channel->GetAttribute("DataRate", drv);
  dr = drv.Get ();

  uint32_t feat = 0x00000000;
  feat |= OFPPF_COPPER;
  feat |= OFPPF_AUTONEG;

  if (dr == DataRate ("10Mbps"))
    {
      feat |= OFPPF_10MB_FD;
    }
  else if (dr == DataRate ("100Mbps"))
    {
      feat |= OFPPF_100MB_FD;
    }
  else if (dr == DataRate ("1Gbps"))
    {
      feat |= OFPPF_1GB_FD;
    }
  else if (dr == DataRate ("10Gbps"))
    {
      feat |= OFPPF_10GB_FD;
    }
  else if (dr == DataRate ("40Gbps"))
    {
      feat |= OFPPF_40GB_FD;
    }
  else if (dr == DataRate ("100Gbps"))
    {
      feat |= OFPPF_100GB_FD;
    }
  else if (dr == DataRate ("1Tbps"))
    {
      feat |= OFPPF_1TB_FD;
    }
  else
    {
      feat |= OFPPF_OTHER;
    }
  return feat;
}

OfPort::OfPort (datapath *dp, Ptr<NetDevice> dev)
{
  netdev = dev;
  portNo = ++(dp->ports_num);;
  swPort = &dp->ports[portNo];

  memset (swPort, '\0', sizeof *swPort);
  
  swPort->dp = dp;
  swPort->ns3port = this;
    
  swPort->conf = (ofl_port*)xmalloc (sizeof (ofl_port));
  memset (swPort->conf, 0x00, sizeof (ofl_port));
  swPort->conf->port_no = portNo;
  swPort->conf->name = (char*)xmalloc (OFP_MAX_PORT_NAME_LEN);
  snprintf (swPort->conf->name, OFP_MAX_PORT_NAME_LEN, "Port %d", portNo);
  netdev->GetAddress ().CopyTo (swPort->conf->hw_addr);
  swPort->conf->config = 0x00000000;
  swPort->conf->state = 0x00000000 | OFPPS_LIVE;
  swPort->conf->curr = PortGetFeatures ();
  swPort->conf->advertised = PortGetFeatures ();
  swPort->conf->supported = PortGetFeatures ();
  // swPort->conf->peer = PortGetFeatures ();
  swPort->conf->curr_speed = port_speed (swPort->conf->curr);
  swPort->conf->max_speed = port_speed (swPort->conf->supported);

  dp_port_live_update (swPort);

  swPort->stats = (ofl_port_stats*)xmalloc (sizeof (ofl_port_stats));
  memset (swPort->stats, 0x00, sizeof (ofl_port_stats));
  swPort->stats->port_no = portNo;
  swPort->flags |= SWP_USED;
 
  // To avoid a null check failure in dp_swPorts_handle_stats_request_swPort (), 
  // we are pointing swPort->netdev to ns3::NetDevice, but it may? not be used. 
  swPort->netdev = (struct netdev*)PeekPointer (dev);
  swPort->max_queues = NETDEV_MAX_QUEUES;
  swPort->num_queues = 0; // No queue supswPort by now
  swPort->created = time_msec ();

  memset (swPort->queues, 0x00, sizeof (swPort->queues));

  list_push_back (&dp->port_list, &swPort->node);
}

OfPort::~OfPort ()
{
  netdev = 0;
  ofl_structs_free_port (swPort->conf);
  free (swPort->stats);
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
                   TimeValue (Seconds (60)),
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
 
  m_ports.reserve (DP_MAX_PORTS);
  m_datapath = DatapathNew ();
  RegisterDatapath (m_dpId, Ptr<OFSwitch13NetDevice> (this));
  Simulator::Schedule (m_timeout , &OFSwitch13NetDevice::DatapathTimeout, this, m_datapath);
}

OFSwitch13NetDevice::~OFSwitch13NetDevice ()
{
  NS_LOG_FUNCTION (this);
}

int 
OFSwitch13NetDevice::AddSwitchPort (Ptr<NetDevice> portDevice)
{
  NS_LOG_FUNCTION (this << portDevice);
  NS_LOG_INFO ("Adding port addr " << portDevice->GetAddress ());
  
  if (GetNSwitchPorts () >= DP_MAX_PORTS)
    {
      return EXFULL;
    }

  Ptr<CsmaNetDevice> csmaPortDevice = portDevice->GetObject<CsmaNetDevice> ();
  if (!csmaPortDevice)
    {
      NS_FATAL_ERROR ("NetDevice must be of CsmaNetDevice type.");
    }
  if (csmaPortDevice->GetEncapsulationMode () != CsmaNetDevice::DIX)
    {
      NS_FATAL_ERROR ("CsmaNetDevice must use DIX encapsulation.");
    }

  // Update max mtu
  if (portDevice->GetMtu () > GetMtu ())
    {
      SetMtu (portDevice->GetMtu ());
    }

  Ptr<OfPort> ofPort = Create<OfPort> (m_datapath, csmaPortDevice);
  m_ports.push_back (ofPort);
 
  // Notify the controller that this port has been added
  ofl_msg_port_status msg;
  msg.header.type = OFPT_PORT_STATUS;
  msg.reason = OFPPR_ADD;
  msg.desc = ofPort->swPort->conf;
  SendToController ((ofl_msg_header*)&msg);

  NS_LOG_LOGIC ("RegisterProtocolHandler for " << portDevice->GetInstanceTypeId ().GetName ());
  m_node->RegisterProtocolHandler (
      MakeCallback (&OFSwitch13NetDevice::ReceiveFromSwitchPort, this), 0, portDevice, true);
  m_channel->AddChannel (portDevice->GetChannel ());
  return 0;
}

int
OFSwitch13NetDevice::SendToController (ofl_msg_header *msg, const sender *sender)
{
  NS_LOG_FUNCTION (this);
  if (!m_ctrlSocket)
    {
      NS_LOG_WARN ("No controller connection. Discarding message... ");
      // ofl_msg_free (msg, NULL);
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
  return m_datapath->ports_num;
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
  
  m_channel = 0;
  m_node = 0;
  m_ctrlSocket = 0;
  m_ports.clear ();
  
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
  dp->last_timeout = time_now ();
  list_init (&dp->remotes);

  // unused
    dp->generation_id = -1;
    dp->listeners = NULL;
    dp->n_listeners = 0;
    dp->listeners_aux = NULL;
    dp->n_listeners_aux = 0;
  // unused
  
  memset (dp->ports, 0x00, sizeof (dp->ports));
  dp->local_port = NULL;

  dp->buffers = dp_buffers_create (dp); 
  dp->pipeline = pipeline_create (dp);
  dp->groups = group_table_create (dp);
  dp->meters = meter_table_create (dp);
    
  list_init (&dp->port_list);
  dp->ports_num = 0;
  dp->max_queues = 0; // No queue support by now
  dp->exp = NULL;
  
  dp->config.flags = OFPC_FRAG_NORMAL; // IP fragments with no special handling
  dp->config.miss_send_len = OFP_DEFAULT_MISS_SEND_LEN; // 128 bytes 
                          // OFPCML_NO_BUFFER           // entire ptk  
  return dp;
}

void
OFSwitch13NetDevice::DatapathTimeout (datapath* dp)
{
  meter_table_add_tokens (dp->meters);
  pipeline_timeout (dp->pipeline);

  // Check for changes in links (port) status
  Ptr<OfPort> ns3Port;
  uint32_t orig_state;
  for (size_t i = 1; i < GetNSwitchPorts (); i++)
    {
      ns3Port = PortGetOfPort (i);
      orig_state = ns3Port->swPort->conf->state;
      if (ns3Port->netdev->IsLinkUp ())
        {
          ns3Port->swPort->conf->state &= ~OFPPS_LINK_DOWN;
        }
      else
        {
          ns3Port->swPort->conf->state |= OFPPS_LINK_DOWN;
        }
      dp_port_live_update (ns3Port->swPort);
  
      if (orig_state != ns3Port->swPort->conf->state)
        {
          NS_LOG_DEBUG ("Port status has changed. Notifying the controller...");
          ofl_msg_port_status msg;
          msg.header.type = OFPT_PORT_STATUS;
          msg.reason = OFPPR_MODIFY;
          msg.desc = ns3Port->swPort->conf;

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
 
  SendToController ((ofl_msg_header*)&msg);
  Simulator::Schedule (m_echo, &OFSwitch13NetDevice::DatapathSendEchoRequest, this);
}

Ptr<OfPort>
OFSwitch13NetDevice::PortGetOfPort (Ptr<NetDevice> dev)
{
  NS_LOG_FUNCTION (this << dev);
  for (size_t i = 0; i < m_ports.size (); i++)
    {
      if (m_ports[i]->netdev == dev)
        {
          return m_ports[i];
        }
    }
  NS_LOG_ERROR ("No port found!");
  return NULL;
}

Ptr<OfPort>
OFSwitch13NetDevice::PortGetOfPort (uint32_t no)
{
  NS_LOG_FUNCTION (this << no);
  NS_ASSERT_MSG (no > 0 && no <= m_ports.size (), "Invalid port number");

  if (m_ports[no-1]->portNo == no)
    {
      return m_ports[no-1];
    }
  
  for (size_t i = 0; i < m_ports.size (); i++)
    {
      if (m_ports[i]->portNo == no)
        {
          return m_ports[i];
        }
    }
  NS_LOG_ERROR ("No port found!");
  return NULL;
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
  Ptr<OfPort> inPort = PortGetOfPort (netdev);
  NS_ASSERT_MSG (inPort != NULL, "This device is not registered as a switch port");
  if (inPort->swPort->conf->config & ((OFPPC_NO_RECV | OFPPC_PORT_DOWN) != 0)) 
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
  struct packet *pkt = packet_create (m_datapath, inPort->portNo, buffer, false);

  // Update port stats
  inPort->swPort->stats->rx_packets++;
  inPort->swPort->stats->rx_bytes += buffer->size;

  // Runs the packet through the pipeline
  Simulator::Schedule (m_lookupDelay, pipeline_process_packet, m_datapath->pipeline, pkt);
//  Simulator::Schedule (m_lookupDelay, &OFSwitch13NetDevice::PipelineProcessPacket, 
//      this, m_datapath->pipeline, pkt);
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
OFSwitch13NetDevice::SendToSwitchPort (ofpbuf *buffer, uint32_t portNo, uint32_t queueNo)
{
  // No queue support by now
  NS_LOG_FUNCTION (this);
  
  Ptr<OfPort> port = PortGetOfPort (portNo);
  if (port == 0 || port->netdev == 0)
    {
      NS_LOG_ERROR ("can't forward to invalid port.");
      return false;
    }
  sw_port *swPort = port->swPort;
  
  if ((swPort->conf->config & ((OFPPC_NO_RECV | OFPPC_PORT_DOWN))) == 0)
    {
      // Removing the ethernet header and trailer from packet, which will be
      // included again by CsmaNetDevice
      Ptr<Packet> packet = ofs::PacketFromBuffer (buffer);
      EthernetTrailer trailer;
      packet->RemoveTrailer (trailer);
      
      EthernetHeader header;
      packet->RemoveHeader (header);

      bool status = port->netdev->SendFrom (packet, header.GetSource (),
          header.GetDestination (), header.GetLengthType ());
      if (status)
        {
          swPort->stats->tx_packets++;
          swPort->stats->tx_bytes += packet->GetSize ();
        }
      else
        {
          swPort->stats->tx_dropped++;
        }
      return status;
    }
  NS_LOG_ERROR ("can't forward to bad port " << port->portNo);
  return false;
}

ofl_err
OFSwitch13NetDevice::HandleControlMessage (datapath *dp, ofl_msg_header *msg, 
    const sender *sender)
{ 
  NS_LOG_FUNCTION (this);

  switch (msg->type)
    {
      // Currently not supported. Return error.
      case OFPT_EXPERIMENTER:
      case OFPT_ROLE_REQUEST:
      case OFPT_QUEUE_GET_CONFIG_REQUEST:
        return ofl_error (OFPET_BAD_REQUEST, OFPGMFC_BAD_TYPE);

      // For others, let the lib handle them
      default: 
        return handle_control_msg (dp, msg, sender);
    }
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
