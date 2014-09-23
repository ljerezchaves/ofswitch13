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

NS_LOG_COMPONENT_DEFINE ("OFSwitch13NetDevice");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (OFSwitch13NetDevice);

static uint64_t
GenerateId ()
{
  uint8_t ea[ETH_ADDR_LEN];
  eth_addr_random (ea);
  return eth_addr_to_uint64 (ea);
}

static uint32_t 
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

static void
LogOflMsg (ofl_msg_header *msg, bool isRx=false)
{
  char *str;
  str = ofl_msg_to_string (msg, NULL);
  if (isRx)
    {
      NS_LOG_INFO ("RX from ctrl: " << str);
    }
  else
    {
      NS_LOG_INFO ("TX to ctrl: " << str);
    }
  free (str);
}


/********** Public methods **********/
TypeId
OFSwitch13NetDevice::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OFSwitch13NetDevice")
    .SetParent<NetDevice> ()
    .AddConstructor<OFSwitch13NetDevice> ()
    .AddAttribute ("ID",
                   "The identification of the OFSwitch13NetDevice/Datapath.",
                   UintegerValue (GenerateId ()),
                   MakeUintegerAccessor (&OFSwitch13NetDevice::SetDatapathId),
                   MakeUintegerChecker<uint64_t> ())
    .AddAttribute ("FlowTableLookupDelay",
                   "Overhead for looking up in the flow table (Default: standard TCAM on an FPGA).",
                   TimeValue (NanoSeconds (30)),
                   MakeTimeAccessor (&OFSwitch13NetDevice::m_lookupDelay),
                   MakeTimeChecker ())
    .AddAttribute ("DatapathTimeout",
                   "The interval between timeout operations on pipeline.",
                   TimeValue (Seconds (1)),
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
  : m_xid (0xff000000),
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
}

OFSwitch13NetDevice::~OFSwitch13NetDevice ()
{
  NS_LOG_FUNCTION (this);
}

const char *
OFSwitch13NetDevice::GetManufacturerDescription ()
{
  return "The ns-3 team";
}

const char *
OFSwitch13NetDevice::GetHardwareDescription ()
{
  return "N/A";
}

const char *
OFSwitch13NetDevice::GetSoftwareDescription ()
{
  return "Simulated OpenFlow Switch datapath version 1.3";
}

const char *
OFSwitch13NetDevice::GetSerialNumber ()
{
  return "1";
}

const char *
OFSwitch13NetDevice::GetDatapathDescrtiption ()
{
  return "N/A";
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
  NS_LOG_INFO ("Port # " << no);
  
  // Notify the controller that this port has been added
  if (m_ctrlSocket)
    {
      ofl_msg_port_status msg;
      msg.header.type = OFPT_PORT_STATUS;
      msg.reason = OFPPR_ADD;
      msg.desc = p.conf;

      Ptr<Packet> packet = ofs::PacketFromMsg ((ofl_msg_header*)&msg, ++m_xid);
      LogOflMsg ((ofl_msg_header*)&msg);
      SendToController (packet);
    }

  NS_LOG_LOGIC ("RegisterProtocolHandler for " << switchPort->GetInstanceTypeId ().GetName ());
  m_node->RegisterProtocolHandler (
      MakeCallback (&OFSwitch13NetDevice::ReceiveFromSwitchPort, this), 0, switchPort, true);
  m_channel->AddChannel (switchPort->GetChannel ());
  return 0;
}

uint32_t
OFSwitch13NetDevice::GetNSwitchPorts (void) const
{
  return m_ports.size ();
}

uint64_t
OFSwitch13NetDevice::GetDatapathId (void) const
{
  return m_datapath->id;
}

void
OFSwitch13NetDevice::SetDatapathId (uint64_t id)
{
  NS_ASSERT (m_datapath);
  m_datapath->id = id;
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

  // FIXME Issue #22 pipeline_destroy (m_datapath->pipeline);

  NetDevice::DoDispose ();
}

datapath*
OFSwitch13NetDevice::DatapathNew ()
{
  datapath* dp = (datapath*)xmalloc (sizeof (datapath));

  dp->mfr_desc   = (char*)xmalloc (DESC_STR_LEN); 
  dp->hw_desc    = (char*)xmalloc (DESC_STR_LEN);
  dp->sw_desc    = (char*)xmalloc (DESC_STR_LEN);
  dp->dp_desc    = (char*)xmalloc (DESC_STR_LEN);
  dp->serial_num = (char*)xmalloc (DESC_STR_LEN);
  strcpy (dp->mfr_desc ,  GetManufacturerDescription ());
  strcpy (dp->hw_desc,    GetHardwareDescription ());
  strcpy (dp->sw_desc,    GetSoftwareDescription ());
  strcpy (dp->dp_desc,    GetDatapathDescrtiption ());
  strcpy (dp->serial_num, GetSerialNumber ());

  // Not used
  dp->generation_id = -1;
  dp->listeners = NULL;
  dp->n_listeners = 0;
  dp->listeners_aux = NULL;
  dp->n_listeners_aux = 0;
  
  dp->id = 0; //FIXME
  dp->last_timeout = Simulator::Now ().GetTimeStep ();
  
  dp->buffers = dp_buffers_create (dp); 
  dp->pipeline = pipeline_create (dp);
  dp->groups = group_table_create (dp);
  //dp->meters = meter_table_create (dp);
  
  dp->config.flags = OFPC_FRAG_NORMAL; // IP fragments with no special handling
  dp->config.miss_send_len = 128;      // send first 128 bytes to controller 
                                       // use OFPCML_NO_BUFFER to send hole ptk
  dp->exp = NULL;

  // Not used
  dp->ports_num = 0;
  dp->max_queues = 0;
  dp->local_port = NULL;

  Simulator::Schedule (m_timeout , &OFSwitch13NetDevice::DatapathTimeout, this, dp);
  
  m_ports.reserve (DP_MAX_PORTS+1);

  return dp;
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

  // Port is always enabled (NetDevice is always enabled)
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
  Time alive = Simulator::Now () - Time (p->created);
  p->stats->duration_sec  = (uint32_t)alive.ToInteger (Time::S);
  alive -= Time::FromInteger (p->stats->duration_sec, Time::S); 
  p->stats->duration_nsec = (uint32_t)alive.ToInteger (Time::NS);
}

int
OFSwitch13NetDevice::ReceiveFromController (ofpbuf* buffer)
{ 
  NS_LOG_FUNCTION (this);
  NS_ASSERT (buffer);

  uint32_t xid;
  ofl_msg_header *msg;
  ofl_err error;
  
  error = ofl_msg_unpack ((uint8_t*)buffer->data, buffer->size, &msg, &xid, NULL/*&ofl_exp*/);
  if (!error)
    {
      LogOflMsg ((ofl_msg_header*)msg, true/*Rx*/);
      /* Dispatches control messages to appropriate handler functions. */
      datapath *dp = m_datapath;
      switch (msg->type)
        {
          case OFPT_HELLO:
            error = HandleMsgHello (dp, msg, xid);
            break;
          case OFPT_ERROR:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          case OFPT_ECHO_REQUEST:
            error = HandleMsgEchoRequest (dp, (ofl_msg_echo*)msg, xid);
            break;
          case OFPT_ECHO_REPLY:
            error = HandleMsgEchoReply (dp, (ofl_msg_echo*)msg, xid);
            break;
          case OFPT_EXPERIMENTER:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
            //dp_exp_message(dp, (struct ofl_msg_experimenter *)msg, sender); // TODO
            break;

          /* Switch configuration messages. */
          case OFPT_FEATURES_REQUEST:
            error = HandleMsgFeaturesRequest (dp, msg, xid);
            break;
          case OFPT_FEATURES_REPLY:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          case OFPT_GET_CONFIG_REQUEST:
            error = HandleMsgGetConfigRequest (dp, msg, xid);
            break;
          case OFPT_GET_CONFIG_REPLY:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          case OFPT_SET_CONFIG:
            error = HandleMsgSetConfig (dp, (ofl_msg_set_config*)msg, xid);
            break;

          /* Asynchronous messages. */
          case OFPT_PACKET_IN:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          case OFPT_FLOW_REMOVED:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          case OFPT_PORT_STATUS:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;

          /* Controller command messages. */
          case OFPT_GET_ASYNC_REQUEST:
            error = HandleMsgGetAsyncRequest (dp, (ofl_msg_async_config*)msg, xid);
            break;     
          case OFPT_SET_ASYNC:
            error = HandleMsgSetAsync (dp, (ofl_msg_async_config*)msg, xid);
            break;       
          case OFPT_GET_ASYNC_REPLY:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          case OFPT_PACKET_OUT:
            error = HandleMsgPacketOut (dp, (ofl_msg_packet_out*)msg, xid);
            break;
          case OFPT_FLOW_MOD:
            error = HandleMsgFlowMod (dp, (ofl_msg_flow_mod*)msg, xid); 
            break;
          //case OFPT_GROUP_MOD:
          //  error = group_table_handle_group_mod (dp->groups, (ofl_msg_group_mod*)msg, sender);
          //  break;
          case OFPT_PORT_MOD:
            error = HandleMsgPortMod (dp, (ofl_msg_port_mod*)msg, xid);
            break;
          case OFPT_TABLE_MOD:
            error = HandleMsgTableMod (dp, (ofl_msg_table_mod*)msg, xid);
            break;

          /* Statistics messages. */
          case OFPT_MULTIPART_REQUEST:
            error = HandleMsgMultipartRequest (dp, (ofl_msg_multipart_request_header*)msg, xid);
            break;
          case OFPT_MULTIPART_REPLY:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;

          /* Barrier messages. */
          case OFPT_BARRIER_REQUEST:
            error = HandleMsgBarrierRequest (dp, msg, xid);
            break;
          case OFPT_BARRIER_REPLY:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          
          /* Role messages. */
          //case OFPT_ROLE_REQUEST:
          //  error = dp_handle_role_request (dp, (ofl_msg_role_request*)msg, sender);
          //  break;
          case OFPT_ROLE_REPLY:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;

          /* Queue Configuration messages. */
          //case OFPT_QUEUE_GET_CONFIG_REQUEST:
          //  error = dp_ports_handle_queue_get_config_request (dp, 
          //           (ofl_msg_queue_get_config_request*)msg, sender);
          //  break;
          case OFPT_QUEUE_GET_CONFIG_REPLY:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          //case OFPT_METER_MOD:
          //  error = meter_table_handle_meter_mod (dp->meters, 
          //              (ofl_msg_meter_mod*)msg, sender);
          //  break;            
          
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
        ofl_msg_free (msg, dp->exp);
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
      
      Ptr<Packet> packet = ofs::PacketFromMsg ((ofl_msg_header*)&err, xid);
      LogOflMsg ((ofl_msg_header*)&msg);
      SendToController (packet);
    }
  ofpbuf_delete (buffer);
  return error; 
}

int
OFSwitch13NetDevice::SendToController (Ptr<Packet> packet)
{
  NS_LOG_FUNCTION (this);
  NS_ASSERT (m_ctrlSocket);

  return m_ctrlSocket->Send (packet);
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

  /**
   * This method is called after the Csma switch port received the packet. The
   * CsmaNetDevice has already classified the packetType.
   */
  switch (packetType)
    {
      /**
       * For PACKET_BROADCAST or PACKET_MULTICAST, forward the packet up AND let
       * the pipeline process it to get it forwarded.
       */
      case PACKET_BROADCAST:
      case PACKET_MULTICAST:
        m_rxCallback (this, packet, protocol, src);
        break;

      /**
       * For PACKET_OTHERHOST or PACKET_HOST check if it is addressed to this
       * switch to forward it up OR let the pipeline process it.  
       */
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

  /** Preparing the pipeline process... **/

  // Get the input port and check configuration
  ofs::Port* inPort = PortGetOfsPort (netdev);
  NS_ASSERT_MSG (inPort != NULL, "This device is not registered as a switch port");
  if (inPort->conf->config & ((OFPPC_NO_RECV | OFPPC_PORT_DOWN) != 0)) 
    {
      NS_LOG_WARN ("This port is down or inoperating. Discarding packet");
      return;
    }

  /**
   * Adding the ethernet header back to the packet. It was removed by
   * CsmaNetDevice but we need L2 information for the pipeline. It will be
   * removed when outputing the packet by SendToSwitchPort method.
   */
  Ptr<Packet> pktCopy = packet->Copy ();
  AddEthernetHeader (pktCopy, src48, dst48, protocol);

  /**
   * Buffering the packet and creating the internal openflow packet structure
   * from buffer. Allocate buffer with some headroom to add headers in
   * forwarding to the controller or adding a vlan tag, plus an extra 2 bytes
   * to allow IP headers to be aligned on a 4-byte boundary.
   */
  uint32_t headRoom = 128 + 2;
  uint32_t bodyRoom = netdev->GetMtu () + VLAN_ETH_HEADER_LEN;
  ofpbuf *buffer = ofs::BufferFromPacket (pktCopy, bodyRoom, headRoom);
  struct packet *pkt = ofs::InternalPacketFromBuffer (m_datapath, 
      inPort->stats->port_no, buffer, false);

  // Update port stats
  inPort->stats->rx_packets++;
  inPort->stats->rx_bytes += buffer->size;

  // Runs the packet through the pipeline
  Simulator::Schedule (m_lookupDelay, &OFSwitch13NetDevice::PipelineProcessPacket, this, 
      m_datapath->pipeline, pkt);
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
      /**
       * Removing the ethernet header and trailer from packet, which will be
       * included again by CsmaNetDevice
       */
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
          Ptr<Packet> ns3pkt = CreatePacketIn (pl, pkt, 0, OFPR_INVALID_TTL, UINT64_MAX);
          SendToController (ns3pkt);  // FIXME check
        } 
      else 
        {
          NS_LOG_WARN ("Packet has invalid TTL, dropping.");
        }
      InternalPacketDestroy (pkt);
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
  
      entry = FlowTableLookup (table, pkt);
      if (entry != NULL) 
        {
          NS_LOG_DEBUG ("found matching entry: " << 
              ofl_structs_flow_stats_to_string (entry->stats, pkt->dp->exp));
       
          pkt->handle_std->table_miss = ((entry->stats->priority) == 0 && 
                                         (entry->match->length <= 4));
          PipelineExecuteEntry (pl, entry, &next_table, &pkt);
          
          /* Packet could be destroyed by a meter instruction */
          if (!pkt)
            {
              return;
            }
  
          if (next_table == NULL) 
            {
              // Pipeline end. Execute actions and free packet
              ActionSetExecute (pkt, pkt->action_set, UINT64_MAX);
              InternalPacketDestroy (pkt);
              return;
            }
        } 
      else 
        {
          /* OpenFlow 1.3 default behavior on a table miss */
          NS_LOG_DEBUG ("No matching entry found. Dropping packet.");
          InternalPacketDestroy (pkt);
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
  
 /** 
   * Instructions, when present, will be executed in the following order:
   * Meter, Apply-Actions, Clear-Actions, Write-Actions, Write-Metadata, and
   * Goto-Table.
   **/
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
              
              /* Search field on the description of the packet. */
              HMAP_FOR_EACH_WITH_HASH (f, ofl_match_tlv, hmap_node, 
                  HashInt (OXM_OF_METADATA, 0), &(*pkt)->handle_std->match.match_fields)
                {
                  uint64_t *metadata = (uint64_t*) f->value;
                  *metadata = (*metadata & ~wi->metadata_mask) | (wi->metadata & wi->metadata_mask);
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
              // FIXME No meter support by now
              // ofl_instruction_meter *im = (ofl_instruction_meter*)inst;
              // meter_table_apply(pl->dp->meters, pkt , im->meter_id);
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

void
OFSwitch13NetDevice::DatapathTimeout (datapath* dp)
{
  // FIXME No meter support by now
  // meter_table_add_tokens (dp->meters);
  
  // Check flow entry timeout
  for (int i = 0; i < PIPELINE_TABLES; i++) 
    {
      FlowTableTimeout (dp->pipeline->tables[i]);
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

          Ptr<Packet> packet = ofs::PacketFromMsg ((ofl_msg_header*)&msg, ++m_xid);
          LogOflMsg ((ofl_msg_header*)&msg);
          SendToController (packet);
        }
    }

  Simulator::Schedule (m_timeout , &OFSwitch13NetDevice::DatapathTimeout, this, dp);
  dp->last_timeout = Simulator::Now ().GetTimeStep ();
}

int32_t
OFSwitch13NetDevice::BuffersSave (dp_buffers *dpb, packet *pkt)
{
  NS_LOG_FUNCTION (this);
  
  packet_buffer *p;
  uint32_t id;

  /* if packet is already in buffer, do not save again */
  if (pkt->buffer_id != NO_BUFFER) 
    {
      if (BuffersIsAlive (dpb, pkt->buffer_id)) 
        {
          return pkt->buffer_id;
        }
    }

  dpb->buffer_idx = (dpb->buffer_idx + 1) & PKT_BUFFER_MASK;

  p = &dpb->buffers[dpb->buffer_idx];
  if (p->pkt != NULL) 
    {
      if (Simulator::Now () < Time (p->timeout))
        {
          return NO_BUFFER;
        } 
      else 
        {
          p->pkt->buffer_id = NO_BUFFER;
          InternalPacketDestroy (p->pkt);
        }
    }

  /* Don't use maximum cookie value since the all-bits-1 id is special. */
  if (++p->cookie >= (1u << PKT_COOKIE_BITS) - 1)
    {
      p->cookie = 0;
    }

  Time expire = Simulator::Now () + Time ("2s");
  p->timeout = (time_t)expire.GetTimeStep (); 
  
  p->pkt = pkt;
  id = dpb->buffer_idx | (p->cookie << PKT_BUFFER_BITS);
  pkt->buffer_id  = id;

  return id;
}

bool
OFSwitch13NetDevice::BuffersIsAlive (dp_buffers *dpb, uint32_t id)
{
  NS_LOG_FUNCTION (this);
  
  packet_buffer *p = &dpb->buffers [id & PKT_BUFFER_MASK];
  return ((p->cookie == id >> PKT_BUFFER_BITS) && 
          (Simulator::Now () < Time (p->timeout)));
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
          // FIXME No group support by now
          // group_table_execute(pkt->dp->groups, pkt, group); 
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
OFSwitch13NetDevice::ActionSetExecute (packet *pkt, action_set *set, 
    uint64_t cookie)
{
  NS_LOG_FUNCTION (this);
  
  action_set_entry *entry, *next;

  LIST_FOR_EACH_SAFE (entry, next, action_set_entry, node, &set->actions) 
    {
      dp_execute_action (pkt, entry->action);
      list_remove (&entry->node);
      free (entry);

      /* According to the spec. if there was a group action, the output
       * port action should be ignored */
      if (pkt->out_group != OFPG_ANY) 
        {
          // FIXME No group support by now
          // uint32_t group_id = pkt->out_group;
          // pkt->out_group = OFPG_ANY;
          // action_set_clear_actions (pkt->action_set);
          // group_table_execute (pkt->dp->groups, pkt, group_id);
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
          Ptr<Packet> ns3pkt = CreatePacketIn (pkt->dp->pipeline, pkt, pkt->table_id, 
              (pkt->handle_std->table_miss ? OFPR_NO_MATCH : OFPR_ACTION), cookie);
          SendToController (ns3pkt);
          break;
        }
      case (OFPP_FLOOD):
      case (OFPP_ALL): 
        {
          ofs::Port *p;
          // Send to all ports except input // FIXME Criar SendToAllSwitchPorts
          for (uint32_t i = 1; i <= GetNSwitchPorts (); i++)
            {
              p = PortGetOfsPort (i);
              if (p->port_no == pkt->in_port)
                {
                  continue;
                }
              SendToSwitchPort (pkt, p);
            }
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
OFSwitch13NetDevice::ActionValidate (datapath *dp, size_t num, ofl_action_header **actions)
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

ofl_err
OFSwitch13NetDevice::FlowTableAdd (flow_table *table, ofl_msg_flow_mod *mod, 
    bool check_overlap, bool *match_kept, bool *insts_kept) 
{
  NS_LOG_FUNCTION (this);
  
  // Note: new entries will be placed behind those with equal priority
  flow_entry *entry, *new_entry;

  LIST_FOR_EACH (entry, flow_entry, match_node, &table->match_entries) 
    {
      if (check_overlap && flow_entry_overlaps (entry, mod)) 
        {
          return ofl_error (OFPET_FLOW_MOD_FAILED, OFPFMFC_OVERLAP);
        }

      /* if the entry equals, replace the old one */
      if (flow_entry_matches (entry, mod, true/*strict*/, false/*check_cookie*/)) 
        {
          new_entry = FlowEntryCreate (table->dp, table, mod);
          *match_kept = true;
          *insts_kept = true;

          /* NOTE: no flow removed message should be generated according to spec. */
          list_replace (&new_entry->match_node, &entry->match_node);
          list_remove (&entry->hard_node);
          list_remove (&entry->idle_node);
          flow_entry_destroy (entry);
          add_to_timeout_lists (table, new_entry);
          return 0;
        }

      if (mod->priority > entry->stats->priority) 
        {
          break;
        }
    }

  if (table->stats->active_count == FLOW_TABLE_MAX_ENTRIES) 
    {
      return ofl_error (OFPET_FLOW_MOD_FAILED, OFPFMFC_TABLE_FULL);
    }
  table->stats->active_count++;

  new_entry = FlowEntryCreate (table->dp, table, mod);
  *match_kept = true;
  *insts_kept = true;

  list_insert (&entry->match_node, &new_entry->match_node);
  add_to_timeout_lists (table, new_entry);

  return 0;
}

ofl_err 
OFSwitch13NetDevice::FlowTableDelete (flow_table *table, ofl_msg_flow_mod *mod,
    bool strict)
{
  NS_LOG_FUNCTION (this);
  
  flow_entry *entry, *next;

  LIST_FOR_EACH_SAFE (entry, next, flow_entry, match_node, &table->match_entries) 
    {
      if ((mod->out_port  == OFPP_ANY || flow_entry_has_out_port (entry, mod->out_port)) &&
          (mod->out_group == OFPG_ANY || flow_entry_has_out_group (entry, mod->out_group)) &&
           flow_entry_matches (entry, mod, strict, true/*check_cookie*/)) 
        {
           FlowEntryRemove (entry, OFPRR_DELETE);
        }
    }
  return 0;
}

ofl_err 
OFSwitch13NetDevice::FlowTableFlowMod (flow_table *table, ofl_msg_flow_mod *mod, 
      bool *match_kept, bool *insts_kept)
{
  switch (mod->command) 
    {
      case (OFPFC_ADD): 
        {
          bool overlap = ((mod->flags & OFPFF_CHECK_OVERLAP) != 0);
          return FlowTableAdd (table, mod, overlap, match_kept, insts_kept);
        }
      case (OFPFC_MODIFY): 
        {
          return flow_table_modify (table, mod, false, insts_kept);
        }
      case (OFPFC_MODIFY_STRICT): 
        {
          return flow_table_modify (table, mod, true, insts_kept);
        }
      case (OFPFC_DELETE): 
        {
          return FlowTableDelete (table, mod, false);
        }
      case (OFPFC_DELETE_STRICT): 
        {
          return FlowTableDelete (table, mod, true);
        }
      default: 
        {
          return ofl_error (OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_COMMAND);
        }
    }
}

flow_entry* 
OFSwitch13NetDevice::FlowTableLookup (flow_table *table, packet *pkt)
{
  flow_entry *entry;

  table->stats->lookup_count++;

  LIST_FOR_EACH (entry, flow_entry, match_node, &table->match_entries) 
    {
      ofl_match_header *m;
      m = entry->match == NULL ? entry->stats->match : entry->match;

      /* select appropriate handler, based on match type of flow entry. */
      switch (m->type) 
        {
          case (OFPMT_OXM): 
            {
              if (packet_handle_std_match (pkt->handle_std, (ofl_match *)m)) 
                {
                  if (!entry->no_byt_count)
                    {
                      entry->stats->byte_count += pkt->buffer->size;
                    }
                  if (!entry->no_pkt_count)
                    {
                      entry->stats->packet_count++;
                    }
                  entry->last_used = Simulator::Now ().GetTimeStep ();
                  table->stats->matched_count++;
                  return entry;
                }
              break;
            }
          default: 
            {
              NS_LOG_WARN ("Trying to process flow entry with unknown match type " << m->type);
            }
        }
    }
  return NULL;
}

void
OFSwitch13NetDevice::FlowTableTimeout (flow_table *table) 
{
  struct flow_entry *entry, *next;

  /** 
   * NOTE: hard timeout entries are ordered by the time they should be removed
   * at, so if one is not removed, the rest will not be either. 
   */
  LIST_FOR_EACH_SAFE (entry, next, struct flow_entry, hard_node, &table->hard_entries) 
    {
      if (!FlowEntryHardTimeout (entry)) 
        {
          break;
        }
    }

  LIST_FOR_EACH_SAFE (entry, next, struct flow_entry, idle_node, &table->idle_entries) 
    {
      FlowEntryIdleTimeout (entry);
    }
}

void 
OFSwitch13NetDevice::FlowTableStats (flow_table *table, ofl_msg_multipart_request_flow *msg, 
      ofl_flow_stats ***stats, size_t *stats_size, size_t *stats_num)
{
  flow_entry *entry;

  LIST_FOR_EACH (entry, flow_entry, match_node, &table->match_entries) 
    {
      if ((msg->out_port == OFPP_ANY || flow_entry_has_out_port (entry, msg->out_port)) &&
          (msg->out_group == OFPG_ANY || flow_entry_has_out_group (entry, msg->out_group)) &&
          match_std_nonstrict ((ofl_match*)msg->match,
                               (ofl_match*)entry->stats->match)) 
        {

          FlowEntryUpdate (entry);
          if ((*stats_size) == (*stats_num)) 
            {
              (*stats) = (ofl_flow_stats**) xrealloc (*stats, 
                         (sizeof (ofl_flow_stats*)) * (*stats_size) * 2);
              *stats_size *= 2;
            }
          (*stats)[(*stats_num)] = entry->stats;
          (*stats_num)++;
        }
    }
}

void
OFSwitch13NetDevice::FlowEntryRemove (flow_entry *entry, uint8_t reason)
{
  NS_LOG_FUNCTION (this);

  if (entry->send_removed)
    {
      FlowEntryUpdate (entry);
        {
          NS_LOG_DEBUG ("Flow entry expired. Notifying the controller...");
          ofl_msg_flow_removed msg;
          msg.header.type = OFPT_FLOW_REMOVED;
          msg.reason = (ofp_flow_removed_reason)reason;
          msg.stats  = entry->stats;

          Ptr<Packet> packet = ofs::PacketFromMsg ((ofl_msg_header*)&msg, ++m_xid);
          LogOflMsg ((ofl_msg_header*)&msg);
          SendToController (packet);
        }
    }

  list_remove (&entry->match_node);
  list_remove (&entry->hard_node);
  list_remove (&entry->idle_node);
  entry->table->stats->active_count--;
 
  // FIXME No group support by now no metter support
  // del_group_refs (entry);
  // del_meter_refs (entry);
  ofl_structs_free_flow_stats (entry->stats, entry->dp->exp);
  free (entry);
}

flow_entry* 
OFSwitch13NetDevice::FlowEntryCreate (datapath *dp, flow_table *table, 
    ofl_msg_flow_mod *mod)
{
  flow_entry *entry;
  uint64_t now;
  
  now = Simulator::Now ().GetTimeStep ();

  entry = (flow_entry*)xmalloc (sizeof (flow_entry));
  entry->dp    = dp;
  entry->table = table;

  entry->stats = (ofl_flow_stats*)xmalloc (sizeof (ofl_flow_stats));
  entry->stats->table_id      = mod->table_id;
  entry->stats->duration_sec  = 0;
  entry->stats->duration_nsec = 0;
  entry->stats->priority      = mod->priority;
  entry->stats->idle_timeout  = mod->idle_timeout;  // stored in seconds
  entry->stats->hard_timeout  = mod->hard_timeout;  // stored in seconds
  entry->stats->cookie        = mod->cookie;
  entry->no_pkt_count = ((mod->flags & OFPFF_NO_PKT_COUNTS) != 0 );
  entry->no_byt_count = ((mod->flags & OFPFF_NO_BYT_COUNTS) != 0 ); 
  
  if (entry->no_pkt_count)
    {
      entry->stats->packet_count = 0xffffffffffffffff;
    }
  else
    {
      entry->stats->packet_count = 0;
    }

  if (entry->no_byt_count)
    {
      entry->stats->byte_count = 0xffffffffffffffff;
    }
  else
    {
      entry->stats->byte_count = 0;
    }

  entry->stats->match            = mod->match;
  entry->stats->instructions_num = mod->instructions_num;
  entry->stats->instructions     = mod->instructions;

  entry->match = mod->match;

  entry->created = now;  // timestep
  entry->remove_at = 0;  // timestep
  if (mod->hard_timeout)
    {
      Time out = Time (now) + Time::FromInteger (mod->hard_timeout, Time::S);
      entry->remove_at = out.GetTimeStep ();
    }
  entry->last_used = now;  // timestep
  entry->send_removed = ((mod->flags & OFPFF_SEND_FLOW_REM) != 0);
  list_init (&entry->match_node);
  list_init (&entry->idle_node);
  list_init (&entry->hard_node);

  // FIXME No group support by now
  // list_init (&entry->group_refs);
  // init_group_refs (entry);

  // FIXME No metter support by now
  // list_init (&entry->meter_refs);
  // init_meter_refs (entry);

  return entry;
}

bool 
OFSwitch13NetDevice::FlowEntryIdleTimeout (flow_entry *entry)
{
  bool timeout = (entry->stats->idle_timeout != 0) && 
                 (Simulator::Now () > (Time (entry->last_used) + 
                                       Time::FromInteger (entry->stats->idle_timeout, Time::S)));
  
  if (timeout) 
    {
      FlowEntryRemove (entry, OFPRR_IDLE_TIMEOUT);
    }
  return timeout;
}

bool 
OFSwitch13NetDevice::FlowEntryHardTimeout (flow_entry *entry)
{
  bool timeout = (entry->remove_at != 0) && (Simulator::Now () > Time (entry->remove_at));

  if (timeout) 
    {
      FlowEntryRemove (entry, OFPRR_HARD_TIMEOUT);
    }
  return timeout;
}

void
OFSwitch13NetDevice::FlowEntryUpdate (flow_entry *entry) 
{
  Time alive = Simulator::Now () - Time (entry->created);
  entry->stats->duration_sec  = (uint32_t)alive.ToInteger (Time::S);
  alive -= Time::FromInteger (entry->stats->duration_sec, Time::S); 
  entry->stats->duration_nsec = (uint32_t)alive.ToInteger (Time::NS);
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

Ptr<Packet> 
OFSwitch13NetDevice::CreatePacketIn (pipeline* pl, packet *pkt, uint8_t tableId,
    ofp_packet_in_reason reason, uint64_t cookie)
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
      BuffersSave (pl->dp->buffers, pkt);
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
 
  LogOflMsg ((ofl_msg_header*)&msg);
  return ofs::PacketFromMsg ((ofl_msg_header*)&msg, ++m_xid);
}

void 
OFSwitch13NetDevice::InternalPacketDestroy (packet *pkt)
{
  /* If packet is saved in a buffer, do not destroy it,
   * if buffer is still valid */
   
  if (pkt->buffer_id != NO_BUFFER) 
    {
      if (BuffersIsAlive (pkt->dp->buffers, pkt->buffer_id)) 
        {
          return;
        }
      else 
        {
          dp_buffers_discard (pkt->dp->buffers, pkt->buffer_id, false);
        }
    }

  action_set_destroy (pkt->action_set);
  ofpbuf_delete (pkt->buffer);
  packet_handle_std_destroy (pkt->handle_std);
  free (pkt);
}


void
OFSwitch13NetDevice::SendEchoRequest ()
{
  NS_LOG_FUNCTION (this);
  
  // Send echo message
  ofl_msg_echo msg;
  msg.header.type = OFPT_ECHO_REQUEST;
  msg.data_length = 0;
  msg.data        = 0;
 
  uint64_t xid = ++m_xid;
  ofs::EchoInfo echo (InetSocketAddress::ConvertFrom (m_ctrlAddr).GetIpv4 ());
  m_echoMap.insert (std::pair<uint64_t, ofs::EchoInfo> (xid, echo));

  LogOflMsg ((ofl_msg_header*)&msg);
  Ptr<Packet> pkt = ofs::PacketFromMsg ((ofl_msg_header*)&msg, xid);
  SendToController (pkt);

  // TODO: start a timer and wait for a reply

  Simulator::Schedule (m_echo, &OFSwitch13NetDevice::SendEchoRequest, this);
}

ofl_err
OFSwitch13NetDevice::HandleMsgHello (datapath *dp, ofl_msg_header *msg, 
    uint64_t xid) 
{
  NS_LOG_FUNCTION (this);
  // Nothing to do: the ofsoftswitch13 already checks for OpenFlow version when
  // unpacking the message
  
  // All handlers must free the message when everything is ok
  ofl_msg_free (msg, dp->exp);
  return 0;
}

ofl_err
OFSwitch13NetDevice::HandleMsgEchoRequest (datapath *dp, ofl_msg_echo *msg, 
    uint64_t xid) 
{
  NS_LOG_FUNCTION (this);
  
  ofl_msg_echo reply;
  reply.header.type = OFPT_ECHO_REPLY;
  reply.data_length = msg->data_length;
  reply.data        = msg->data;
  
  Ptr<Packet> pkt = ofs::PacketFromMsg ((ofl_msg_header*)&reply, xid);
  LogOflMsg ((ofl_msg_header*)&reply);
  SendToController (pkt);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, dp->exp);
  return 0;
}

ofl_err
OFSwitch13NetDevice::HandleMsgEchoReply (datapath *dp, ofl_msg_echo *msg, 
    uint64_t xid) 
{
  NS_LOG_FUNCTION (this);
 
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
  ofl_msg_free ((ofl_msg_header*)msg, dp->exp);
  return 0;
}

ofl_err
OFSwitch13NetDevice::HandleMsgFeaturesRequest (datapath *dp, ofl_msg_header *msg, 
    uint64_t xid)
{
  NS_LOG_FUNCTION (this);
  
  ofl_msg_features_reply reply;
  reply.header.type  = OFPT_FEATURES_REPLY;
  reply.datapath_id  = GetDatapathId ();
  reply.n_buffers    = dp_buffers_size (dp->buffers);
  reply.n_tables     = PIPELINE_TABLES;
  reply.auxiliary_id = 0; // FIXME No auxiliary connection support by now
  reply.capabilities = DP_SUPPORTED_CAPABILITIES;
  reply.reserved     = 0x00000000;

  Ptr<Packet> pkt = ofs::PacketFromMsg ((ofl_msg_header*)&reply, xid);
  LogOflMsg ((ofl_msg_header*)&reply);
  SendToController (pkt);
  
  // All handlers must free the message when everything is ok
  ofl_msg_free (msg, dp->exp);
  return 0;
}

ofl_err
OFSwitch13NetDevice::HandleMsgGetConfigRequest (datapath *dp, ofl_msg_header *msg, 
    uint64_t xid)
{
  NS_LOG_FUNCTION (this);
  
  ofl_msg_get_config_reply reply;
  reply.header.type = OFPT_GET_CONFIG_REPLY;
  reply.config      = &dp->config;

  Ptr<Packet> pkt = ofs::PacketFromMsg ((ofl_msg_header*)&reply, xid);
  LogOflMsg ((ofl_msg_header*)&reply);
  SendToController (pkt);
  
  // All handlers must free the message when everything is ok
  ofl_msg_free (msg, dp->exp);
  return 0;
}

ofl_err
OFSwitch13NetDevice::HandleMsgSetConfig (datapath *dp, ofl_msg_set_config *msg, 
    uint64_t xid)
{
  NS_LOG_FUNCTION (this);
  
  uint16_t flags;

  flags = msg->config->flags & OFPC_FRAG_MASK;
  if ((flags & OFPC_FRAG_MASK) != OFPC_FRAG_NORMAL
      && (flags & OFPC_FRAG_MASK) != OFPC_FRAG_DROP) {
      flags = (flags & ~OFPC_FRAG_MASK) | OFPC_FRAG_DROP;
  }

  dp->config.flags = flags;
  dp->config.miss_send_len = msg->config->miss_send_len;
  
  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, dp->exp);
  return 0;
}

ofl_err
OFSwitch13NetDevice::HandleMsgPacketOut (datapath *dp, ofl_msg_packet_out *msg, 
    uint64_t xid) 
{
  NS_LOG_FUNCTION (this);
  
  packet *pkt;
  int error;

  error = ActionValidate (dp, msg->actions_num, msg->actions);
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
      pkt = ofs::InternalPacketFromBuffer (dp, msg->in_port, buf, true);
    } 
  else 
    {
      /* NOTE: in this case packet should not have data */
      pkt = dp_buffers_retrieve (dp->buffers, msg->buffer_id);
    }

  if (pkt == NULL) 
    {
      /* This might be a wrong req., or a timed out buffer */
      return ofl_error (OFPET_BAD_REQUEST, OFPBRC_BUFFER_EMPTY);
    }
  
  ActionsListExecute (pkt, msg->actions_num, msg->actions, UINT64_MAX);
  InternalPacketDestroy (pkt);
  
  // All handlers must free the message when everything is ok
  ofl_msg_free_packet_out (msg, false, dp->exp);
  return 0;
}

ofl_err
OFSwitch13NetDevice::HandleMsgFlowMod (datapath *dp, ofl_msg_flow_mod *msg, 
    uint64_t xid)
{
  NS_LOG_FUNCTION (this);
  
  /**
   * Modifications to a flow table from the controller are done with the
   * OFPT_FLOW_MOD message (including add, modify or delete).
   * \see ofsoftswitch13 pipeline_handle_flow_mod () at udatapath/pipeline.c
   * and flow_table_flow_mod () at udatapath/flow_table.c
   */
  pipeline *pl = dp->pipeline;
  ofl_err error;
  size_t i;
  bool match_kept, insts_kept;
  match_kept = false;
  insts_kept = false;
  
  /*Sort by execution oder*/
  qsort (msg->instructions, msg->instructions_num, 
      sizeof (ofl_instruction_header*), inst_compare);
  
  // Validate actions in flow_mod
  for (i = 0; i < msg->instructions_num; i++) 
    {
      if (msg->instructions[i]->type == OFPIT_APPLY_ACTIONS || 
          msg->instructions[i]->type == OFPIT_WRITE_ACTIONS) 
        {
          ofl_instruction_actions *ia = (ofl_instruction_actions*)msg->instructions[i];
  
          error = ActionValidate (dp, (size_t)ia->actions_num, ia->actions);
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
      /* Reject goto in the last table. */
      if ((msg->table_id == (PIPELINE_TABLES - 1)) && 
          (msg->instructions[i]->type == OFPIT_GOTO_TABLE))
        {
          return ofl_error (OFPET_BAD_INSTRUCTION, OFPBIC_UNSUP_INST);
        }
    }
  
  if (msg->table_id == 0xff) 
    {
      /** 
       * Note: the result of using table_id = 0xff is undefined in the spec.
       * For now it is accepted for delete commands, meaning to delete from
       * all tables 
       */
      if (msg->command == OFPFC_DELETE || 
          msg->command == OFPFC_DELETE_STRICT) 
        {
          size_t i;
          error = 0;
          for (i = 0; i < PIPELINE_TABLES; i++) 
            {
              error = FlowTableFlowMod (pl->tables[i], msg, &match_kept, &insts_kept);
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
      error = FlowTableFlowMod (pl->tables[msg->table_id], msg, &match_kept, &insts_kept); 
      if (error) 
        {
          return error;
        }
      
      if ((msg->command == OFPFC_ADD || msg->command == OFPFC_MODIFY || 
           msg->command == OFPFC_MODIFY_STRICT) && msg->buffer_id != NO_BUFFER) 
        {
          /* run buffered message through pipeline */
          packet *pkt;
          pkt = dp_buffers_retrieve (dp->buffers, msg->buffer_id);
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
      ofl_msg_free_flow_mod (msg, !match_kept, !insts_kept, dp->exp);
      return 0;
    }
}

ofl_err
OFSwitch13NetDevice::HandleMsgPortMod (datapath *dp, ofl_msg_port_mod *msg, 
    uint64_t xid) 
{
  NS_LOG_FUNCTION (this);
  
  ofs::Port *p = PortGetOfsPort (msg->port_no);
  if (p == NULL) 
    {
      return ofl_error (OFPET_PORT_MOD_FAILED, OFPPMFC_BAD_PORT);
    }

  /* Make sure the port id hasn't changed since this was sent */
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
          /* Port not live */
          p->conf->state &= ~OFPPS_LIVE;
        } 
      else 
        {
          /* Port is live */
          p->conf->state |= OFPPS_LIVE;
        }
    }

  /* Notify the controller that the port status has changed */
  ofl_msg_port_status reply;
  reply.header.type = OFPT_PORT_STATUS;
  reply.reason = OFPPR_MODIFY; 
  reply.desc = p->conf;

  Ptr<Packet> pkt = ofs::PacketFromMsg ((ofl_msg_header*)&reply, ++m_xid);
  LogOflMsg ((ofl_msg_header*)&reply);
  SendToController (pkt);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, dp->exp);
  return 0;
}

ofl_err
OFSwitch13NetDevice::HandleMsgTableMod (datapath *dp, ofl_msg_table_mod *msg, 
    uint64_t xid) 
{
  NS_LOG_FUNCTION (this);
  
  if (msg->table_id == 0xff) 
    {
      size_t i;
      for (i = 0; i < PIPELINE_TABLES; i++) {
          dp->pipeline->tables[i]->features->config = msg->config;
      }
    }
  else 
    {
      dp->pipeline->tables[msg->table_id]->features->config = msg->config;
    }

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, dp->exp);
  return 0;
}

ofl_err 
OFSwitch13NetDevice::HandleMsgMultipartRequest (datapath *dp, 
    ofl_msg_multipart_request_header *msg, uint64_t xid)
{
  NS_LOG_FUNCTION (this);
  
  switch (msg->type) 
    {
      case (OFPMP_DESC): 
        return MultipartMsgDesc (dp, msg, xid);

      case (OFPMP_FLOW):
        return MultipartMsgFlow (dp, (ofl_msg_multipart_request_flow*)msg, xid);
      
      case (OFPMP_AGGREGATE): 
        return MultipartMsgAggregate (dp, (ofl_msg_multipart_request_flow*)msg, xid);
      
      case (OFPMP_TABLE): 
        return MultipartMsgTable (dp, msg, xid);
      
      case (OFPMP_TABLE_FEATURES):
        return MultipartMsgTableFeatures (dp, msg, xid);
      
      case (OFPMP_PORT_STATS): 
        return MultipartMsgPortStats (dp, (ofl_msg_multipart_request_port*)msg, xid); 
      
      case (OFPMP_QUEUE): 
        //return dp_ports_handle_stats_request_queue(dp, (ofl_msg_multipart_request_queue*)msg, sender);
      
      case (OFPMP_GROUP): 
        //return group_table_handle_stats_request_group(dp->groups, (ofl_msg_multipart_request_group*)msg, sender);
      
      case (OFPMP_GROUP_DESC): 
        //return group_table_handle_stats_request_group_desc(dp->groups, msg, sender);
      
      case (OFPMP_GROUP_FEATURES):
        //return group_table_handle_stats_request_group_features(dp->groups, msg, sender);
      
      case (OFPMP_METER):
        //return meter_table_handle_stats_request_meter(dp->meters,(ofl_msg_multipart_meter_request*)msg, sender);
      
      case (OFPMP_METER_CONFIG):
        //return meter_table_handle_stats_request_meter_conf(dp->meters,(ofl_msg_multipart_meter_request*)msg, sender);        
      
      case OFPMP_METER_FEATURES:
        //return meter_table_handle_features_request(dp->meters, msg, sender);
      
      case OFPMP_PORT_DESC:
        return MultipartMsgPortDesc (dp, msg, xid);        
      
      case (OFPMP_EXPERIMENTER): 
        //return dp_exp_stats(dp, (ofl_msg_multipart_request_experimenter*)msg, sender);
      
      default: 
        return ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_MULTIPART);
    }
}

ofl_err
OFSwitch13NetDevice::HandleMsgBarrierRequest (datapath *dp, ofl_msg_header *msg, 
    uint64_t xid) 
{
  NS_LOG_FUNCTION (this);
  
  /**
   * Note: the implementation is single-threaded, so a barrier request can
   * simply be replied. // FIXME  Issue #19
   */
  ofl_msg_header reply;
  reply.type = OFPT_BARRIER_REPLY;

  Ptr<Packet> pkt = ofs::PacketFromMsg (&reply, xid);
  LogOflMsg (&reply);
  SendToController (pkt);

  // All handlers must free the message when everything is ok
  ofl_msg_free (msg, dp->exp);
  return 0;
}

ofl_err
OFSwitch13NetDevice::HandleMsgGetAsyncRequest (datapath *dp, 
    ofl_msg_async_config *msg, uint64_t xid) 
{
  NS_LOG_FUNCTION (this);
  
  ofl_msg_async_config reply;
  reply.header.type = OFPT_GET_ASYNC_REPLY;
  reply.config = &m_asyncConfig;

  Ptr<Packet> pkt = ofs::PacketFromMsg ((ofl_msg_header*)&reply, xid);
  LogOflMsg ((ofl_msg_header*)&reply);
  SendToController (pkt);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, dp->exp);
  return 0;
}

ofl_err
OFSwitch13NetDevice::HandleMsgSetAsync (datapath *dp, 
    ofl_msg_async_config *msg, uint64_t xid) 
{
  NS_LOG_FUNCTION (this);
  
  memcpy (&m_asyncConfig, msg->config, sizeof (ofl_async_config));

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, dp->exp);
  return 0;
}

ofl_err
OFSwitch13NetDevice::MultipartMsgDesc (datapath *dp, 
    ofl_msg_multipart_request_header *msg, uint64_t xid)
{
  NS_LOG_FUNCTION (this);
 
  ofl_msg_reply_desc reply;
  reply.header.header.type = OFPT_MULTIPART_REPLY;
  reply.header.type  = OFPMP_DESC;
  reply.header.flags = 0x0000;
  reply.mfr_desc     = dp->mfr_desc;
  reply.hw_desc      = dp->hw_desc;
  reply.sw_desc      = dp->sw_desc;
  reply.serial_num   = dp->serial_num;
  reply.dp_desc      = dp->dp_desc;

  Ptr<Packet> pkt = ofs::PacketFromMsg ((ofl_msg_header*)&reply, xid);
  LogOflMsg ((ofl_msg_header*)&reply);
  SendToController (pkt);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, dp->exp);
  return 0;
}

ofl_err
OFSwitch13NetDevice::MultipartMsgFlow (datapath *dp, 
    ofl_msg_multipart_request_flow *msg, uint64_t xid)
{
  NS_LOG_FUNCTION (this);
  
  ofl_flow_stats **stats = (ofl_flow_stats**)xmalloc ( sizeof(ofl_flow_stats*));
  size_t stats_size = 1;
  size_t stats_num = 0;

  if (msg->table_id == 0xff) 
    {
      size_t i;
      for (i=0; i<PIPELINE_TABLES; i++) 
        {
          FlowTableStats (dp->pipeline->tables[i], msg, 
              &stats, &stats_size, &stats_num);
        }
    } 
  else 
    {
      FlowTableStats (dp->pipeline->tables[msg->table_id], 
          msg, &stats, &stats_size, &stats_num);
    }

  ofl_msg_multipart_reply_flow reply;
  reply.header.header.type = OFPT_MULTIPART_REPLY;
  reply.header.type = OFPMP_FLOW;
  reply.header.flags = 0x0000;
  reply.stats = stats;
  reply.stats_num = stats_num;

  Ptr<Packet> pkt = ofs::PacketFromMsg ((ofl_msg_header*)&reply, xid);
  LogOflMsg ((ofl_msg_header*)&reply);
  SendToController (pkt);
  free(stats);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, dp->exp);
  return 0;
}

ofl_err
OFSwitch13NetDevice::MultipartMsgAggregate (datapath *dp, 
    ofl_msg_multipart_request_flow *msg, uint64_t xid)
{
  NS_LOG_FUNCTION (this);
  
  ofl_msg_multipart_reply_aggregate reply;
  reply.header.header.type = OFPT_MULTIPART_REPLY;
  reply.header.type = OFPMP_AGGREGATE;
  reply.header.flags = 0x0000;
  reply.packet_count = 0;
  reply.byte_count   = 0;
  reply.flow_count   = 0;

  if (msg->table_id == 0xff) 
    {
      size_t i;
      for (i=0; i<PIPELINE_TABLES; i++) {
          flow_table_aggregate_stats (dp->pipeline->tables[i], msg, 
              &reply.packet_count, &reply.byte_count, &reply.flow_count);
      }
    } 
  else 
    {
      flow_table_aggregate_stats (dp->pipeline->tables[msg->table_id], 
          msg, &reply.packet_count, &reply.byte_count, &reply.flow_count);
    }

  Ptr<Packet> pkt = ofs::PacketFromMsg ((ofl_msg_header*)&reply, xid);
  LogOflMsg ((ofl_msg_header*)&reply);
  SendToController (pkt);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, dp->exp);
  return 0;
}

ofl_err
OFSwitch13NetDevice::MultipartMsgTable (datapath *dp, 
    ofl_msg_multipart_request_header *msg, uint64_t xid)
{
  NS_LOG_FUNCTION (this);
  
  ofl_msg_multipart_reply_table reply;
  reply.header.header.type = OFPT_MULTIPART_REPLY;
  reply.header.type = OFPMP_TABLE;
  reply.header.flags = 0x0000;
  reply.stats_num = PIPELINE_TABLES;
  reply.stats = (ofl_table_stats**)xmalloc (sizeof (ofl_table_stats*) * PIPELINE_TABLES);

  for (size_t i = 0; i < PIPELINE_TABLES; i++) 
    {
      reply.stats[i] = dp->pipeline->tables[i]->stats;
    }

  Ptr<Packet> pkt = ofs::PacketFromMsg ((ofl_msg_header*)&reply, xid);
  LogOflMsg ((ofl_msg_header*)&reply);
  SendToController (pkt);

  // All handlers must free the message when everything is ok
  free (reply.stats);
  ofl_msg_free ((ofl_msg_header*)msg, dp->exp);
  return 0;
}

ofl_err
OFSwitch13NetDevice::MultipartMsgTableFeatures (datapath *dp, 
    ofl_msg_multipart_request_header *msg, uint64_t xid) 
{
  NS_LOG_FUNCTION (this);
  
  // FIXME Implement this Issue #14
  return ofl_error (OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_TABLE);
  //return 0;
}

ofl_err
OFSwitch13NetDevice::MultipartMsgPortStats (datapath *dp, 
    ofl_msg_multipart_request_port *msg, uint64_t xid)
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

  Ptr<Packet> pkt = ofs::PacketFromMsg ((ofl_msg_header*)&reply, xid);
  LogOflMsg ((ofl_msg_header*)&reply);
  SendToController (pkt);

  // All handlers must free the message when everything is ok
  free (reply.stats);
  ofl_msg_free ((ofl_msg_header*)msg, dp->exp);
  return 0;
}

ofl_err
OFSwitch13NetDevice::MultipartMsgPortDesc (datapath *dp, 
    ofl_msg_multipart_request_header *msg, uint64_t xid)
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
  
  Ptr<Packet> pkt = ofs::PacketFromMsg ((ofl_msg_header*)&reply, xid);
  LogOflMsg ((ofl_msg_header*)&reply);
  SendToController (pkt);
  
  // All handlers must free the message when everything is ok
  free (reply.stats);
  ofl_msg_free ((ofl_msg_header*)msg, dp->exp);
  return 0;
}

void 
OFSwitch13NetDevice::SocketCtrlRead (Ptr<Socket> socket)
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
          NS_LOG_LOGIC ("At time " << Simulator::Now ().GetSeconds ()
                       << "s the OpenFlow switch received "
                       <<  packet->GetSize () << " bytes from controller "
                       << InetSocketAddress::ConvertFrom(from).GetIpv4 ()
                       << " port " << InetSocketAddress::ConvertFrom (from).GetPort ());

          // Create and process the openflow buffer
          ofpbuf *buffer = ofs::BufferFromPacket (packet, packet->GetSize ());
          ReceiveFromController (buffer);
        }
    }
}

void
OFSwitch13NetDevice::SocketCtrlSucceeded (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_LOGIC ("Controller accepted connection request!");
  socket->SetRecvCallback (MakeCallback (&OFSwitch13NetDevice::SocketCtrlRead, this));

  // Randomize xid
  m_xid = HashInt (m_xid, GetDatapathId () & UINT32_MAX);

  // Send Hello message
  ofl_msg_header msg;
  msg.type = OFPT_HELLO;
  LogOflMsg (&msg);
  Ptr<Packet> pkt = ofs::PacketFromMsg (&msg, ++m_xid);
  SendToController (pkt);
  
  // Schedule first echo message
  Simulator::Schedule (m_echo, &OFSwitch13NetDevice::SendEchoRequest, this);
}

void
OFSwitch13NetDevice::SocketCtrlFailed (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_ERROR ("Controller did not accepted connection request!");
}

} // namespace ns3
#endif // NS3_OFSWITCH13
