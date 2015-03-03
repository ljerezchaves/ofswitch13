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
#include "ns3/string.h"
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
  std::pair<uint64_t, Ptr<OFSwitch13NetDevice> > entry (id, dev);
  std::pair<std::map<uint64_t, Ptr<OFSwitch13NetDevice> >::iterator, bool> ret;
  ret = g_switchMap.insert (entry);
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
      return 0;
    }
}

// ---- OpenFlow port code -------------------------------
namespace ns3 {

OFPort::OFPort (datapath *dp, Ptr<NetDevice> dev)
{
  // Internal members
  m_netdev = dev;
  m_portNo = ++(dp->ports_num);
  m_swPort = &dp->ports[m_portNo];

  memset (m_swPort, '\0', sizeof *m_swPort);

  m_swPort->dp = dp;
  m_swPort->conf = (ofl_port*)xmalloc (sizeof (ofl_port));
  memset (m_swPort->conf, 0x00, sizeof (ofl_port));
  m_swPort->conf->port_no = m_portNo;
  m_swPort->conf->name = (char*)xmalloc (OFP_MAX_PORT_NAME_LEN);
  snprintf (m_swPort->conf->name, OFP_MAX_PORT_NAME_LEN, "Port %d", m_portNo);
  m_netdev->GetAddress ().CopyTo (m_swPort->conf->hw_addr);
  m_swPort->conf->config = 0x00000000;
  m_swPort->conf->state = 0x00000000 | OFPPS_LIVE;
  m_swPort->conf->curr = PortGetFeatures ();
  m_swPort->conf->advertised = PortGetFeatures ();
  m_swPort->conf->supported = PortGetFeatures ();
  // m_swPort->conf->peer = PortGetFeatures ();
  m_swPort->conf->curr_speed = port_speed (m_swPort->conf->curr);
  m_swPort->conf->max_speed = port_speed (m_swPort->conf->supported);

  dp_port_live_update (m_swPort);

  m_swPort->stats = (ofl_port_stats*)xmalloc (sizeof (ofl_port_stats));
  memset (m_swPort->stats, 0x00, sizeof (ofl_port_stats));
  m_swPort->stats->port_no = m_portNo;
  m_swPort->flags |= SWP_USED;

  // To avoid a null check failure in
  // dp_m_swPorts_handle_stats_request_m_swPort (), we are pointing
  // m_swPort->netdev to ns3::NetDevice, but it will not be used.
  m_swPort->netdev = (struct netdev*)PeekPointer (dev);
  m_swPort->max_queues = NETDEV_MAX_QUEUES;
  m_swPort->num_queues = 0; // No queue support by now
  m_swPort->created = time_msec ();

  memset (m_swPort->queues, 0x00, sizeof (m_swPort->queues));

  list_push_back (&dp->port_list, &m_swPort->node);
}

OFPort::~OFPort ()
{
  m_netdev = 0;
  ofl_structs_free_port (m_swPort->conf);
  free (m_swPort->stats);
}

uint32_t
OFPort::PortGetFeatures ()
{
  DataRateValue drv;
  DataRate dr;
  Ptr<CsmaChannel> channel = DynamicCast<CsmaChannel> (m_netdev->GetChannel ());
  channel->GetAttribute ("DataRate", drv);
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
  else if (dr == DataRate ("1000Gbps"))
    {
      feat |= OFPPF_1TB_FD;
    }
  else
    {
      feat |= OFPPF_OTHER;
    }
  return feat;
}

bool
OFPort::PortUpdateState ()
{
  uint32_t orig_state = m_swPort->conf->state;
  if (m_netdev->IsLinkUp ())
    {
      m_swPort->conf->state &= ~OFPPS_LINK_DOWN;
    }
  else
    {
      m_swPort->conf->state |= OFPPS_LINK_DOWN;
    }
  dp_port_live_update (m_swPort);
  return (orig_state != m_swPort->conf->state);
}

// ---- OpenFlow switch code -------------------------------
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
                   "Overhead for looking up in the flow table "
                   "(Default: standard TCAM on an FPGA).",
                   TimeValue (NanoSeconds (30)),
                   MakeTimeAccessor (&OFSwitch13NetDevice::m_lookupDelay),
                   MakeTimeChecker ())
    .AddAttribute ("DatapathTimeout",
                   "The interval between timeout operations on pipeline.",
                   TimeValue (MilliSeconds (100)),
                   MakeTimeAccessor (&OFSwitch13NetDevice::m_timeout),
                   MakeTimeChecker ())
    .AddAttribute ("ControllerAddr",
                   "The controller InetSocketAddress.",
                   AddressValue (InetSocketAddress (Ipv4Address ("10.100.150.1"), 6653)),
                   MakeAddressAccessor (&OFSwitch13NetDevice::m_ctrlAddr),
                   MakeAddressChecker ())
    .AddAttribute ("LibLogLevel",
                   "Set the ofsoftswitch13 library logging level."
                   "Use 'none' to turn logging off. "
                   "Use 'all' to maximum verbosity. "
                   "You can also use a custom ofsoftswitch13 verbosity level.",
                   StringValue ("none"),
                   MakeStringAccessor (&OFSwitch13NetDevice::SetLibLogLevel),
                   MakeStringChecker ())
  ;
  return tid;
}

OFSwitch13NetDevice::OFSwitch13NetDevice ()
{
  NS_LOG_FUNCTION (this);
  NS_LOG_INFO ("OpenFlow version " << OFP_VERSION);

  m_dpId = ++m_globalDpId;
  m_node = 0;
  m_ctrlSocket = 0;
  m_ctrlAddr = Address ();
  m_ifIndex = 0;
  m_datapath = DatapathNew ();
  RegisterDatapath (m_dpId, Ptr<OFSwitch13NetDevice> (this));
  Simulator::Schedule (m_timeout, &OFSwitch13NetDevice::DatapathTimeout, 
                       this, m_datapath);
}

OFSwitch13NetDevice::~OFSwitch13NetDevice ()
{
  NS_LOG_FUNCTION (this);
}

uint32_t
OFSwitch13NetDevice::AddSwitchPort (Ptr<NetDevice> portDevice)
{
  NS_LOG_FUNCTION (this << portDevice);
  NS_LOG_INFO ("Adding port addr " << portDevice->GetAddress ());

  if (GetNSwitchPorts () >= DP_MAX_PORTS)
    {
      return 0;
    }

  Ptr<CsmaNetDevice> csmaPortDevice = portDevice->GetObject<CsmaNetDevice> ();
  if (!csmaPortDevice)
    {
      NS_FATAL_ERROR ("NetDevice must be of CsmaNetDevice type.");
    }

  // Create the port for this device
  Ptr<OFPort> ofPort = Create<OFPort> (m_datapath, csmaPortDevice);
  std::pair<uint32_t, Ptr<OFPort> > noEntry (ofPort->m_portNo, ofPort);
  std::pair<Ptr<NetDevice>, Ptr<OFPort> > devEntry (ofPort->m_netdev, ofPort);
  m_portsByNo.insert (noEntry);
  m_portsByDev.insert (devEntry);

  // Notify the controller that this port has been added
  ofl_msg_port_status msg;
  msg.header.type = OFPT_PORT_STATUS;
  msg.reason = OFPPR_ADD;
  msg.desc = ofPort->m_swPort->conf;
  dp_send_message (m_datapath, (ofl_msg_header*)&msg, 0);

  // Register a trace sink for this csmaPorDevice to get packets received from
  // device to send to pipeline.
  csmaPortDevice->TraceConnectWithoutContext ("OpenFlowRx", 
      MakeCallback (&OFSwitch13NetDevice::ReceiveFromSwitchPort, this));
  return ofPort->m_portNo;
}

int
OFSwitch13NetDevice::SendToController (ofpbuf *buffer, remote *remote)
{
  // FIXME No support for more than one controller connection by now.
  // So, just ignoring remote information and sending to our single socket.
  if (!m_ctrlSocket)
    {
      NS_LOG_WARN ("No controller connection. Discarding message... ");
      return -1;
    }

  Ptr<Packet> pkt = ofs::PacketFromBuffer (buffer);

  // Check for available space in TCP buffer before sending the packet
  if (m_ctrlSocket->GetTxAvailable () < pkt->GetSize ())
    {
      NS_FATAL_ERROR ("Unavailable space to send OpenFlow message");
    }

  return !m_ctrlSocket->Send (pkt);
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

void
OFSwitch13NetDevice::SetLibLogLevel (std::string log)
{
  NS_LOG_FUNCTION (this << log);

  if (log != "none")
    {
      set_program_name ("ns3-ofswitch13");
      vlog_init ();
      if (log == "all")
        {
          vlog_set_verbosity (0);
        }
      else
        {
          vlog_set_verbosity (log.c_str ());
        }
    }
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
      m_ctrlSocket = Socket::CreateSocket (GetNode (), 
                                           TcpSocketFactory::GetTypeId ());
      m_ctrlSocket->SetAttribute ("SegmentSize", UintegerValue (8900));

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
  return 0;
}

// This is a openflow device, so we really don't need any kind of address
// information. We simply ignore it.
void
OFSwitch13NetDevice::SetAddress (Address address)
{
  NS_LOG_FUNCTION (this);
}

Address
OFSwitch13NetDevice::GetAddress (void) const
{
  NS_LOG_FUNCTION (this);
  return Address ();
}

// No need to keep mtu, as we can query the port device for it.
bool
OFSwitch13NetDevice::SetMtu (const uint16_t mtu)
{
  NS_LOG_FUNCTION (this);
  return true;
}

uint16_t
OFSwitch13NetDevice::GetMtu (void) const
{
  NS_LOG_FUNCTION (this);
  return 0xffff;
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
  return false;
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
  return false;
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
  return false;
}

// This is a openflow device, so we don't send packets from here. Instead, we
// use port netdevices to do this.
bool
OFSwitch13NetDevice::Send (Ptr<Packet> packet, const Address& dest,
                           uint16_t protocolNumber)
{
  NS_LOG_FUNCTION (this);
  return false;
}

bool
OFSwitch13NetDevice::SendFrom (Ptr<Packet> packet, const Address& src,
                               const Address& dest, uint16_t protocolNumber)
{
  NS_LOG_FUNCTION (this);
  return false;
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
  return false;
}

// This is a openflow device, so we don't expect packets addressed to this
// node. So, there is no need for receive callbacks. Install a new device on
// this node to send/receive packets to/from it (and don't add this device as
// switch port). This is the principle for communication between switch and
// controller.
void
OFSwitch13NetDevice::SetReceiveCallback (NetDevice::ReceiveCallback cb)
{
  NS_LOG_FUNCTION (this);
}

void
OFSwitch13NetDevice::SetPromiscReceiveCallback (NetDevice::PromiscReceiveCallback cb)
{
  NS_LOG_FUNCTION (this);
}

bool
OFSwitch13NetDevice::SupportsSendFrom () const
{
  NS_LOG_FUNCTION (this);
  return false;
}

/********** Private methods **********/
void
OFSwitch13NetDevice::DoDispose ()
{
  NS_LOG_FUNCTION (this);

  UnregisterDatapath (m_dpId);

  m_node = 0;
  m_ctrlSocket = 0;
  m_portsByNo.clear ();
  m_portsByDev.clear ();

  pipeline_destroy (m_datapath->pipeline);
  group_table_destroy (m_datapath->groups);
  meter_table_destroy (m_datapath->meters);

  NetDevice::DoDispose ();
}

datapath*
OFSwitch13NetDevice::DatapathNew ()
{
  NS_LOG_FUNCTION (this);

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
  dp->listeners = 0;
  dp->n_listeners = 0;
  dp->listeners_aux = 0;
  dp->n_listeners_aux = 0;
  // unused

  memset (dp->ports, 0x00, sizeof (dp->ports));
  dp->local_port = 0;

  dp->buffers = dp_buffers_create (dp);
  dp->pipeline = pipeline_create (dp);
  dp->groups = group_table_create (dp);
  dp->meters = meter_table_create (dp);

  list_init (&dp->port_list);
  dp->ports_num = 0;
  dp->max_queues = 0; // No queue support by now
  dp->exp = 0;

  dp->config.flags = OFPC_FRAG_NORMAL; // IP fragments with no special handling
  dp->config.miss_send_len = OFP_DEFAULT_MISS_SEND_LEN; // 128 bytes
  return dp;
}

void
OFSwitch13NetDevice::DatapathTimeout (datapath* dp)
{
  NS_LOG_FUNCTION (this << dp->id);

  meter_table_add_tokens (dp->meters);
  pipeline_timeout (dp->pipeline);

  // Check for changes in links (port) status
  PortNoMap_t::iterator it;
  for (it = m_portsByNo.begin (); it != m_portsByNo.end (); it++)
    {
      if (it->second->PortUpdateState ())
        {
          NS_LOG_DEBUG ("Port status has changed. Notifying the controller.");
          ofl_msg_port_status msg;
          msg.header.type = OFPT_PORT_STATUS;
          msg.reason = OFPPR_MODIFY;
          msg.desc = it->second->m_swPort->conf;
          dp_send_message (dp, (ofl_msg_header*)&msg, 0);
        }
    }

  dp->last_timeout = time_now ();
  Simulator::Schedule (m_timeout, &OFSwitch13NetDevice::DatapathTimeout, this, dp);
}

Ptr<OFPort>
OFSwitch13NetDevice::PortGetOFPort (uint32_t no)
{
  NS_LOG_FUNCTION (this << no);

  PortNoMap_t::iterator it;
  it = m_portsByNo.find (no);
  if (it != m_portsByNo.end ())
    {
      return it->second;
    }
  else
    {
      NS_LOG_ERROR ("No port found!");
      return 0;
    }
}

void
OFSwitch13NetDevice::ReceiveFromSwitchPort (Ptr<NetDevice> netdev,
                                            Ptr<Packet> packet)
{
  NS_LOG_FUNCTION (this);

  // Preparing the packet for pipeline.
  // Get the input port for this device and check configuration.
  PortDevMap_t::iterator it;
  it = m_portsByDev.find (netdev);
  if (it == m_portsByDev.end ())
    {
      NS_LOG_WARN ("This device is not registered as a switch port");
      return;
    }

  Ptr<OFPort> inPort = it->second;
  if (inPort->m_swPort->conf->config & ((OFPPC_NO_RECV | OFPPC_PORT_DOWN) != 0))
    {
      NS_LOG_WARN ("This port is down or inoperating. Discarding packet");
      return;
    }

  // Creating the internal openflow packet structure from ns-3 packet
  // Allocate buffer with some extra space for openflow packet modifications. 
  uint32_t headRoom = 128 + 2;
  uint32_t bodyRoom = netdev->GetMtu () + VLAN_ETH_HEADER_LEN;
  ofpbuf *buffer = ofs::BufferFromPacket (packet, bodyRoom, headRoom);
  struct packet *pkt = packet_create (m_datapath, inPort->m_portNo, 
                                      buffer, false);
  pkt->ns3_uid = packet->GetUid ();
  
  // Update port stats
  inPort->m_swPort->stats->rx_packets++;
  inPort->m_swPort->stats->rx_bytes += buffer->size;

  // Save the ns-3 packet pointer and run the packet through the pipeline
  SavePipelinePacket (packet);
  Simulator::Schedule (m_lookupDelay, pipeline_process_packet, 
                       m_datapath->pipeline, pkt);
}

bool
OFSwitch13NetDevice::SendToSwitchPort (ofpbuf *buffer, uint32_t portNo, 
                                       uint32_t queueNo)
{
  // No queue support by now
  NS_LOG_FUNCTION (this);

  Ptr<OFPort> port = PortGetOFPort (portNo);
  if (port == 0 || port->m_netdev == 0)
    {
      NS_LOG_ERROR ("can't forward to invalid port.");
      return false;
    }

  if (!(port->m_swPort->conf->config & (OFPPC_PORT_DOWN)))
    {
      // Removing the ethernet header and trailer from packet, which will be
      // included again by CsmaNetDevice
      Ptr<Packet> packet = ofs::PacketFromBuffer (buffer);
      EthernetTrailer trailer;
      packet->RemoveTrailer (trailer);
      EthernetHeader header;
      packet->RemoveHeader (header);

      // No queue support by now
      bool status = port->m_netdev->SendFrom (packet, header.GetSource (),
                                              header.GetDestination (),
                                              header.GetLengthType ());
      if (status)
        {
          port->m_swPort->stats->tx_packets++;
          port->m_swPort->stats->tx_bytes += packet->GetSize ();
        }
      else
        {
          port->m_swPort->stats->tx_dropped++;
        }
      return status;
    }
  // No need to delete buffer, it is deleted along with the packet in caller.
  NS_LOG_ERROR ("can't forward to bad port " << port->m_portNo);
  return false;
}

void
OFSwitch13NetDevice::SocketCtrlRead (Ptr<Socket> socket)
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
          NS_ASSERT_MSG (rxBytesAvailable >= 8, 
                         "At least 8 bytes must be available for read");

          // Receive the OpenFlow header and get the OpenFlow message size
          ofp_header header;
          pendingPacket = socket->RecvFrom (sizeof (ofp_header), 0, from);
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
                        "s the OpenFlow switch " << GetDatapathId () <<
                        " received " << pendingPacket->GetSize () <<
                        " bytes from controller " << ipv4 <<
                        " socket " << socket <<
                        " port " << InetSocketAddress::ConvertFrom (from).GetPort ());

          ofl_msg_header *msg;
          ofl_err error;

          // FIXME No suuport for multiple controllers by now.
          // Gets the remote structure for this controller connection.
          // As we currently support only one controller, it's the first in list.
          struct sender sender;
          sender.remote = CONTAINER_OF (list_front (&m_datapath->remotes), 
                                        remote, node);
          sender.conn_id = 0; // No auxiliary connections

          // Get the openflow buffer, unpack the message and send to handler
          ofpbuf *buffer = ofs::BufferFromPacket (pendingPacket, 
                                                  pendingPacket->GetSize ());
          error = ofl_msg_unpack ((uint8_t*)buffer->data, buffer->size, &msg,
                                  &sender.xid, m_datapath->exp);
          if (!error)
            {
              char *msg_str = ofl_msg_to_string (msg, m_datapath->exp);
              NS_LOG_DEBUG ("Rx from ctrl: " << msg_str);
              free (msg_str);

              error = handle_control_msg (m_datapath, msg, &sender);
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
              NS_LOG_ERROR ("Error processing OpenFlow message from controller.");
              // Notify the controller
              ofl_msg_error err;
              err.header.type = OFPT_ERROR;
              err.type = (ofp_error_type)ofl_error_type (error);
              err.code = ofl_error_code (error);
              err.data_length = buffer->size;
              err.data = (uint8_t*)buffer->data;
              dp_send_message (m_datapath, (ofl_msg_header*)&err, &sender);
            }
          ofpbuf_delete (buffer);
        }
      pendingPacket = 0;
      pendingBytes = 0;

      // Repeat until socket buffer gets emtpy
    }
  while (socket->GetRxAvailable ());
}

void
OFSwitch13NetDevice::SocketCtrlSucceeded (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_LOGIC ("Controller accepted connection request!");
  socket->SetRecvCallback (MakeCallback (&OFSwitch13NetDevice::SocketCtrlRead, this));

  // Save connection information to remotes list in datapath
  remote_create (m_datapath, 0, 0);

  // Send Hello message
  ofl_msg_header msg;
  msg.type = OFPT_HELLO;
  dp_send_message (m_datapath, &msg, 0);
}

void
OFSwitch13NetDevice::SocketCtrlFailed (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_ERROR ("Controller did not accepted connection request!");
}

void 
OFSwitch13NetDevice::SavePipelinePacket (Ptr<Packet> packet)
{
  NS_LOG_FUNCTION (this << packet->GetUid ());
  
  std::pair <uint64_t, Ptr<Packet> > entry (packet->GetUid (), packet);
  std::pair <UidPacketMap_t::iterator, bool> ret;
  ret = m_pktsPipeline.insert (entry);
  if (ret.second == false)
    {
      NS_FATAL_ERROR ("Packet " << packet->GetUid () << " already in switch " 
                      << GetDatapathId () << " pipeline.");
    }
}
 
Ptr<Packet> 
OFSwitch13NetDevice::RemovePipelinePacket (uint64_t packetUid)
{
  NS_LOG_FUNCTION (this << packetUid);
  
  Ptr<Packet> packet = 0;
  UidPacketMap_t::iterator it = m_pktsPipeline.find (packetUid);
  if (it != m_pktsPipeline.end ())
    {
      packet = it->second;
      m_pktsPipeline.erase (it);
    }
  return packet;
}

} // namespace ns3
#endif // NS3_OFSWITCH13
