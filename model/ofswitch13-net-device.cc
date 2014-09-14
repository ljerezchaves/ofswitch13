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
LogOflMsg (struct ofl_msg_header *msg, bool isRx=false)
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
                   MakeUintegerAccessor (&OFSwitch13NetDevice::m_id),
                   MakeUintegerChecker<uint64_t> ())
    .AddAttribute ("FlowTableLookupDelay",
                   "Overhead for looking up in the flow table (Default: standard TCAM on an FPGA).",
                   TimeValue (NanoSeconds (30)),
                   MakeTimeAccessor (&OFSwitch13NetDevice::m_lookupDelay),
                   MakeTimeChecker ())
    .AddAttribute ("PipelineTimeout",
                   "The interval between timeout operations on pipeline.",
                   TimeValue (Seconds (1)),
                   MakeTimeAccessor (&OFSwitch13NetDevice::m_timeout),
                   MakeTimeChecker ())
    .AddAttribute ("ControlerAddr",
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
  NS_LOG_FUNCTION_NOARGS ();
  NS_LOG_INFO ("OpenFlow version " << OFP_VERSION);

  m_ctrlAddr = Address ();
  m_channel = CreateObject<BridgeChannel> ();
  SetAddress (Mac48Address::Allocate ()); 
 
  // Initializing the datapath, as in dp_net at udatapath/datapath.c
  time_init ();
  nblink_initialize(); 
  
  m_ports.reserve (DP_MAX_PORTS+1);
  
  m_pipeline = (struct pipeline*)xmalloc (sizeof (struct pipeline));
  for (size_t i=0; i<PIPELINE_TABLES; i++) 
    {
      m_pipeline->tables[i] = FlowTableCreate (i);
    }
  
  m_config.flags = OFPC_FRAG_NORMAL;
  m_config.miss_send_len = OFPCML_NO_BUFFER; // sent whole packet to the controller.
  
  m_lastTimeout = Simulator::Now ();
  Simulator::Schedule (m_timeout , &OFSwitch13NetDevice::PipelineTimeout, this);

  // FIXME Remover isso se nao for preciso
  // Create the buffers
  // m_buffers = (struct dp_buffers*)xmalloc (sizeof (struct dp_buffers));
  // m_buffers->dp = NULL;
  // m_buffers->buffer_idx  = (size_t)-1;
  // m_buffers->buffers_num = N_PKT_BUFFERS;
  // for (size_t i=0; i<N_PKT_BUFFERS; i++) 
  //   {
  //     m_buffers->buffers[i].pkt     = NULL;
  //     m_buffers->buffers[i].cookie  = UINT32_MAX;
  //     m_buffers->buffers[i].timeout = 0;
  //   }
}

OFSwitch13NetDevice::~OFSwitch13NetDevice ()
{
  NS_LOG_FUNCTION_NOARGS ();
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
      struct ofl_msg_port_status msg;
      msg.header.type = OFPT_PORT_STATUS;
      msg.reason = OFPPR_ADD;
      msg.desc = p.conf;

      Ptr<Packet> packet = ofs::PacketFromMsg ((ofl_msg_header*)&msg, ++m_xid);
      LogOflMsg ((ofl_msg_header*)&msg);
      SendToController (packet);
    }

  NS_LOG_LOGIC ("RegisterProtocolHandler for " << switchPort->GetInstanceTypeId ().GetName ());
  m_node->RegisterProtocolHandler (MakeCallback (&OFSwitch13NetDevice::ReceiveFromSwitchPort, this), 0, switchPort, true);
  m_channel->AddChannel (switchPort->GetChannel ());
  return 0;
}

uint32_t
OFSwitch13NetDevice::GetNSwitchPorts (void) const
{
  return m_ports.size ();
}

void
OFSwitch13NetDevice::StartControllerConnection ()
{
  NS_ASSERT (!m_ctrlAddr.IsInvalid ());
  
  // Start a TCP connection to the controller
  if (!m_ctrlSocket)
    {
      m_ctrlSocket = Socket::CreateSocket (GetNode (), TcpSocketFactory::GetTypeId ());
      m_ctrlSocket->Bind ();
      m_ctrlSocket->Connect (InetSocketAddress::ConvertFrom (m_ctrlAddr));
      m_ctrlSocket->SetConnectCallback (
          MakeCallback (&OFSwitch13NetDevice::HandleCtrlSucceeded, this),
          MakeCallback (&OFSwitch13NetDevice::HandleCtrlFailed, this));
      return;
  }
  NS_LOG_ERROR ("Controller already set.");
}

// Inherited from NetDevice base class
void
OFSwitch13NetDevice::SetIfIndex (const uint32_t index)
{
  NS_LOG_FUNCTION_NOARGS ();
  m_ifIndex = index;
}

uint32_t
OFSwitch13NetDevice::GetIfIndex (void) const
{
  NS_LOG_FUNCTION_NOARGS ();
  return m_ifIndex;
}

Ptr<Channel>
OFSwitch13NetDevice::GetChannel (void) const
{
  NS_LOG_FUNCTION_NOARGS ();
  return m_channel;
}

void
OFSwitch13NetDevice::SetAddress (Address address)
{
  NS_LOG_FUNCTION_NOARGS ();
  m_address = Mac48Address::ConvertFrom (address);
  NS_LOG_INFO ("Switch addr " << m_address);
}

Address
OFSwitch13NetDevice::GetAddress (void) const
{
  NS_LOG_FUNCTION_NOARGS ();
  return m_address;
}

bool
OFSwitch13NetDevice::SetMtu (const uint16_t mtu)
{
  NS_LOG_FUNCTION_NOARGS ();
  m_mtu = mtu;
  return true;
}

uint16_t
OFSwitch13NetDevice::GetMtu (void) const
{
  NS_LOG_FUNCTION_NOARGS ();
  return m_mtu;
}

bool
OFSwitch13NetDevice::IsLinkUp (void) const
{
  NS_LOG_FUNCTION_NOARGS ();
  return true;
}

void
OFSwitch13NetDevice::AddLinkChangeCallback (Callback<void> callback)
{
}

bool
OFSwitch13NetDevice::IsBroadcast (void) const
{
  NS_LOG_FUNCTION_NOARGS ();
  return true;
}

Address
OFSwitch13NetDevice::GetBroadcast (void) const
{
  NS_LOG_FUNCTION_NOARGS ();
  return Mac48Address ("ff:ff:ff:ff:ff:ff");
}

bool
OFSwitch13NetDevice::IsMulticast (void) const
{
  NS_LOG_FUNCTION_NOARGS ();
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
  NS_LOG_FUNCTION_NOARGS ();
  return false;
}

bool
OFSwitch13NetDevice::IsBridge (void) const
{
  NS_LOG_FUNCTION_NOARGS ();
  return true;
}

bool
OFSwitch13NetDevice::Send (Ptr<Packet> packet, const Address& dest, uint16_t protocolNumber)
{
  NS_LOG_FUNCTION_NOARGS ();
  return SendFrom (packet, m_address, dest, protocolNumber);
}

bool
OFSwitch13NetDevice::SendFrom (Ptr<Packet> packet, const Address& src, const Address& dest, uint16_t protocolNumber)
{
  NS_LOG_FUNCTION_NOARGS ();

  // TODO implementar aqui ???
  return true;
}

Ptr<Node>
OFSwitch13NetDevice::GetNode (void) const
{
  NS_LOG_FUNCTION_NOARGS ();
  return m_node;
}

void
OFSwitch13NetDevice::SetNode (Ptr<Node> node)
{
  NS_LOG_FUNCTION_NOARGS ();
  m_node = node;
}

bool
OFSwitch13NetDevice::NeedsArp (void) const
{
  NS_LOG_FUNCTION_NOARGS ();
  return true;
}

void
OFSwitch13NetDevice::SetReceiveCallback (NetDevice::ReceiveCallback cb)
{
  NS_LOG_FUNCTION_NOARGS ();
  m_rxCallback = cb;
}

void
OFSwitch13NetDevice::SetPromiscReceiveCallback (NetDevice::PromiscReceiveCallback cb)
{
  NS_LOG_FUNCTION_NOARGS ();
  m_promiscRxCallback = cb;
}

bool
OFSwitch13NetDevice::SupportsSendFrom () const
{
  NS_LOG_FUNCTION_NOARGS ();
  return true;
}

/********** Private methods **********/

void
OFSwitch13NetDevice::DoDispose ()
{
  NS_LOG_FUNCTION_NOARGS ();
  
  // No need to notify the controller that this port has been deleted
  for (Ports_t::iterator b = m_ports.begin (), e = m_ports.end (); b != e; b++)
    {
      b->netdev = 0;
      ofl_structs_free_port (b->conf);
      free (b->stats);
    }
  m_ports.clear ();
  
  m_channel = 0;
  m_node = 0;
  m_ctrlSocket = 0;

  // FIXME pipeline_destroy (m_pipeline);

  NetDevice::DoDispose ();
}

ofs::Port*
OFSwitch13NetDevice::PortGetOfsPort (Ptr<NetDevice> dev)
{
  NS_LOG_FUNCTION (dev);
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
  NS_LOG_FUNCTION (no);
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
OFSwitch13NetDevice::PortUpdateStatus (ofs::Port *p)
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

int
OFSwitch13NetDevice::ReceiveFromController (ofpbuf* buffer)
{ 
  NS_ASSERT (buffer);

  uint32_t xid;
  struct ofl_msg_header *msg;
  ofl_err error;
  
  error = ofl_msg_unpack ((uint8_t*)buffer->data, buffer->size, &msg, &xid, NULL/*&ofl_exp*/);
  if (!error)
    {
      LogOflMsg ((ofl_msg_header*)msg, true/*Rx*/);
      /* Dispatches control messages to appropriate handler functions. */
      switch (msg->type)
        {
          case OFPT_HELLO:
            ofl_msg_free (msg, NULL/*dp->exp*/);
            break;
          case OFPT_ERROR:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          case OFPT_ECHO_REQUEST:
            //error = handle_control_echo_request (dp, (struct ofl_msg_echo *)msg, sender);
          case OFPT_ECHO_REPLY:
            //error = handle_control_echo_reply (dp, (struct ofl_msg_echo *)msg, sender);
            break;
          case OFPT_EXPERIMENTER:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
            break;

          /* Switch configuration messages. */
          case OFPT_FEATURES_REQUEST:
            error = HandleMsgFeaturesRequest (msg, xid);
            break;
          case OFPT_FEATURES_REPLY:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          case OFPT_GET_CONFIG_REQUEST:
            error = HandleMsgGetConfigRequest (msg, xid);
            break;
          case OFPT_GET_CONFIG_REPLY:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          case OFPT_SET_CONFIG:
            //error = handle_control_set_config (dp, (struct ofl_msg_set_config *)msg, sender);
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
          case OFPT_SET_ASYNC:
            //error = dp_handle_async_request (dp, (struct ofl_msg_async_config*)msg, sender);
            break;       
          case OFPT_GET_ASYNC_REPLY:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          case OFPT_PACKET_OUT:
            //error = handle_control_packet_out (dp, (struct ofl_msg_packet_out *)msg, sender);
            break;
          case OFPT_FLOW_MOD:
            error = HandleMsgFlowMod ((struct ofl_msg_flow_mod*)msg); 
            break;
          case OFPT_GROUP_MOD:
            //error = roup_table_handle_group_mod (dp->groups, (struct ofl_msg_group_mod *)msg, sender);
            break;
          case OFPT_PORT_MOD:
            //error = dp_ports_handle_port_mod (dp, (struct ofl_msg_port_mod *)msg, sender);
            break;
          case OFPT_TABLE_MOD:
            //error = pipeline_handle_table_mod (dp->pipeline, (struct ofl_msg_table_mod *)msg, sender);
            break;

          /* Statistics messages. */
          case OFPT_MULTIPART_REQUEST:
            error = HandleMsgMultipartRequest ((struct ofl_msg_multipart_request_header*)msg, xid);
            break;
          case OFPT_MULTIPART_REPLY:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;

          /* Barrier messages. */
          case OFPT_BARRIER_REQUEST:
            //error = handle_control_barrier_request (dp, msg, sender);
            break;
          case OFPT_BARRIER_REPLY:
            ofl_msg_free (msg, NULL/*dp->exp*/);
            break;
          
          /* Role messages. */
          case OFPT_ROLE_REQUEST:
            //error = dp_handle_role_request (dp, (struct ofl_msg_role_request*)msg, sender);
            break;
          case OFPT_ROLE_REPLY:
            ofl_msg_free (msg, NULL/*dp->exp*/);
            break;

          /* Queue Configuration messages. */
          case OFPT_QUEUE_GET_CONFIG_REQUEST:
            //error = dp_ports_handle_queue_get_config_request (dp, (struct ofl_msg_queue_get_config_request *)msg, sender);
            break;
          case OFPT_QUEUE_GET_CONFIG_REPLY:
            error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
            break;
          case OFPT_METER_MOD:
            //error = meter_table_handle_meter_mod (dp->meters, (struct ofl_msg_meter_mod *)msg, sender);
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
      // Notify the controller
      struct ofl_msg_error err;
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
  NS_LOG_FUNCTION_NOARGS ();
  NS_ASSERT (m_ctrlSocket);

  return m_ctrlSocket->Send (packet);
}

void
OFSwitch13NetDevice::ReceiveFromSwitchPort (Ptr<NetDevice> netdev, 
    Ptr<const Packet> packet, uint16_t protocol, const Address &src, 
    const Address &dst, PacketType packetType)
{
  NS_LOG_FUNCTION_NOARGS ();
  
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
  struct ofpbuf *buffer = ofs::BufferFromPacket (pktCopy, bodyRoom, headRoom);
  struct packet *pkt = ofs::InternalPacketFromBuffer (inPort->stats->port_no, buffer, false);

  // Update port stats
  inPort->stats->rx_packets++;
  inPort->stats->rx_bytes += buffer->size;

  // Runs the packet through the pipeline
  Simulator::Schedule (m_lookupDelay, &OFSwitch13NetDevice::PipelineProcessPacket, this, pkt);
}

bool
OFSwitch13NetDevice::SendToSwitchPort (struct packet *pkt, ofs::Port *port)
{
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
OFSwitch13NetDevice::PipelineProcessPacket (struct packet* pkt)
{
  NS_LOG_FUNCTION (this << packet_to_string (pkt));
  
  struct flow_entry *entry;
  struct flow_table *table, *next_table;

  // Check ttl
  if (!packet_handle_std_is_ttl_valid (pkt->handle_std)) 
    {
      if ((m_config.flags & OFPC_INVALID_TTL_TO_CONTROLLER) != 0) 
        {
          NS_LOG_WARN ("Packet has invalid TTL, sending to controller.");
          Ptr<Packet> ns3pkt = CreatePacketIn (pkt, 0, OFPR_INVALID_TTL, UINT64_MAX);
          SendToController (ns3pkt);
        } 
      else 
        {
          NS_LOG_WARN ("Packet has invalid TTL, dropping.");
        }
      packet_destroy (pkt);
      return;
    }

  // Look for a match in flow tables
  next_table = m_pipeline->tables[0];
  while (next_table != NULL) 
    {
      NS_LOG_DEBUG ("trying table " << (short)next_table->stats->table_id);

      pkt->table_id = next_table->stats->table_id;
      table = next_table;
      next_table = NULL;

      NS_LOG_DEBUG ("searching table entry for packet match: " <<  
            ofl_structs_match_to_string ((struct ofl_match_header*)&(pkt->handle_std->match), NULL));

      entry = flow_table_lookup (table, pkt);
      if (entry != NULL) 
        {
          NS_LOG_DEBUG ("found matching entry: " << ofl_structs_flow_stats_to_string (entry->stats, NULL));
       
          pkt->handle_std->table_miss = ((entry->stats->priority) == 0 && (entry->match->length <= 4));
          PipelineExecuteEntry (m_pipeline, entry, &next_table, &pkt);
          
          /* Packet could be destroyed by a meter instruction */
          if (!pkt)
            {
              return;
            }

          if (next_table == NULL) 
            {
              // Pipeline end. Execute actions and free packet
              ActionSetExecute (pkt, pkt->action_set, UINT64_MAX);
              packet_destroy (pkt);
              return;
            }
        } 
      else 
        {
          /* OpenFlow 1.3 default behavior on a table miss */
          NS_LOG_DEBUG ("No matching entry found. Dropping packet.");
          packet_destroy (pkt);
          return;
        }
    }
    NS_LOG_ERROR ("Reached outside of pipeline processing cycle.");
}

void
OFSwitch13NetDevice::PipelineExecuteEntry (struct pipeline *pl, struct flow_entry *entry, 
      struct flow_table **next_table, struct packet **pkt)
{
  /** 
   * Instructions, when present, will be executed in the following order:
   * Meter, Apply-Actions, Clear-Actions, Write-Actions, Write-Metadata, and
   * Goto-Table.
   **/
  size_t i;
  struct ofl_instruction_header *inst;

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
              struct ofl_instruction_goto_table *gi = (struct ofl_instruction_goto_table *)inst;
              *next_table = pl->tables[gi->table_id];
              break;
            }
          case OFPIT_WRITE_METADATA: 
            {
              struct ofl_instruction_write_metadata *wi = (struct ofl_instruction_write_metadata *)inst;
              struct ofl_match_tlv *f;

              /* NOTE: Hackish solution. If packet had multiple handles, metadata should be updated in all. */
              packet_handle_std_validate ((*pkt)->handle_std);
              
              /* Search field on the description of the packet. */
              HMAP_FOR_EACH_WITH_HASH (f, struct ofl_match_tlv, hmap_node, HashInt (OXM_OF_METADATA, 0), 
                                       &(*pkt)->handle_std->match.match_fields)
                {
                  uint64_t *metadata = (uint64_t*) f->value;
                  *metadata = (*metadata & ~wi->metadata_mask) | (wi->metadata & wi->metadata_mask);
                  NS_LOG_DEBUG ("Executing write metadata: " << *metadata);
                }
              break;
            }
          case OFPIT_WRITE_ACTIONS: 
            {
              struct ofl_instruction_actions *wa = (struct ofl_instruction_actions *)inst;
              action_set_write_actions ((*pkt)->action_set, wa->actions_num, wa->actions);
              break;
            }
          case OFPIT_APPLY_ACTIONS: 
            {
              struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)inst;
              ActionListExecute ((*pkt), ia->actions_num, ia->actions, entry->stats->cookie);
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
              // struct ofl_instruction_meter *im = (struct ofl_instruction_meter *)inst;
              // meter_table_apply(pl->dp->meters, pkt , im->meter_id);
              break;
            }
          case OFPIT_EXPERIMENTER: 
            {
              // dp_exp_inst((*pkt), (struct ofl_instruction_experimenter *)inst);
              break;
            }
        }
    }
}

void
OFSwitch13NetDevice::PipelineTimeout ()
{
  // FIXME No meter support by now
  // meter_table_add_tokens(dp->meters);
      
  /**FIXME Disabled due to time incompatibility from simulator and ofsoftswitch13 
  
  // Check for flow entry timeout
  struct flow_table *table;
  struct flow_entry *entry, *next;
  
  uint64_t nowMsec = (uint64_t)Simulator::Now ().GetMilliSeconds ();
  for (int i = 0; i < PIPELINE_TABLES; i++) 
    {
      table = m_pipeline->tables[i];
      
      // NOTE: hard timeout entries are ordered by the time they should be
      // removed at, so if one is not removed, the rest will not be either. 
      LIST_FOR_EACH_SAFE (entry, next, struct flow_entry, hard_node, &table->hard_entries) 
        {
          if ((entry->remove_at != 0) && 
              (nowMsec > entry->remove_at))
            {
              FlowEntryRemove (entry, OFPRR_HARD_TIMEOUT);
            }
          else break;
        }

      LIST_FOR_EACH_SAFE (entry, next, struct flow_entry, idle_node, &table->idle_entries) 
        {
          if ((entry->stats->idle_timeout != 0) &&
              (nowMsec > entry->last_used + entry->stats->idle_timeout * 1000))
            {
              FlowEntryRemove (entry, OFPRR_IDLE_TIMEOUT);
            }
        }
    }
  **/

  // Check for changes in port status
  for (size_t i = 0; i < m_ports.size (); i++)
    {
      ofs::Port *p = &m_ports[i];
      if (PortUpdateStatus (p))
        {
          NS_LOG_DEBUG ("Port configuration has changed. Notifying the controller...");
          struct ofl_msg_port_status msg;
          msg.header.type = OFPT_PORT_STATUS;
          msg.reason = OFPPR_MODIFY;
          msg.desc = p->conf;

          Ptr<Packet> packet = ofs::PacketFromMsg ((ofl_msg_header*)&msg, ++m_xid);
          LogOflMsg ((ofl_msg_header*)&msg);
          SendToController (packet);
        }
    }

  Simulator::Schedule (m_timeout , &OFSwitch13NetDevice::PipelineTimeout, this);
  m_lastTimeout = Simulator::Now ();
}

void
OFSwitch13NetDevice::ActionListExecute (struct packet *pkt, size_t actions_num,
    struct ofl_action_header **actions, uint64_t cookie) 
{
  NS_LOG_FUNCTION_NOARGS ();
  
  size_t i;
  for (i=0; i < actions_num; i++) 
    {
      ActionExecute (pkt, actions[i]);
      if (pkt->out_group != OFPG_ANY) 
        {
          uint32_t group = pkt->out_group;
          pkt->out_group = OFPG_ANY;
          NS_LOG_DEBUG ("Group action; executing group " << group);
          // FIXME No group support by now
          // group_table_execute(pkt->dp->groups, pkt, group); 
          // ActionOutputGroup (?);
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
OFSwitch13NetDevice::ActionSetExecute (struct packet *pkt, 
    struct action_set *set, uint64_t cookie)
{
  struct action_set_entry *entry, *next;

  LIST_FOR_EACH_SAFE (entry, next, struct action_set_entry, node, &set->actions) 
    {
      ActionExecute (pkt, entry->action);
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
OFSwitch13NetDevice::ActionExecute (struct packet *pkt, 
    struct ofl_action_header *action)
{
  char *a = ofl_action_to_string (action, NULL/*pkt->dp->exp*/);
  NS_LOG_DEBUG ("executing action " << a);
  free(a);

  switch (action->type) 
    {
      case (OFPAT_SET_FIELD): 
        set_field (pkt,(struct ofl_action_set_field*) action);
        break;
      case (OFPAT_OUTPUT): 
        output (pkt, (struct ofl_action_output *)action);
        break;
      case (OFPAT_COPY_TTL_OUT): 
        copy_ttl_out (pkt, action);
        break;
      case (OFPAT_COPY_TTL_IN):
        copy_ttl_in (pkt, action);
        break;
      case (OFPAT_SET_MPLS_TTL):
        set_mpls_ttl (pkt, (struct ofl_action_mpls_ttl *)action);
        break;
      case (OFPAT_DEC_MPLS_TTL): 
        dec_mpls_ttl (pkt, action);
        break;
      case (OFPAT_PUSH_VLAN): 
        push_vlan (pkt, (struct ofl_action_push *)action);
        break;
      case (OFPAT_POP_VLAN): 
        pop_vlan (pkt, action);
        break;
      case (OFPAT_PUSH_MPLS): 
        push_mpls (pkt, (struct ofl_action_push *)action);
        break;
      case (OFPAT_POP_MPLS): 
        pop_mpls (pkt, (struct ofl_action_pop_mpls *)action);
        break;
      case (OFPAT_SET_QUEUE): 
        set_queue (pkt, (struct ofl_action_set_queue *)action);
        break;
      case (OFPAT_GROUP): 
        group (pkt, (struct ofl_action_group *)action);
        break;
      case (OFPAT_SET_NW_TTL): 
        set_nw_ttl (pkt, (struct ofl_action_set_nw_ttl *)action);
        break;
      case (OFPAT_DEC_NW_TTL): 
        dec_nw_ttl (pkt, action);
        break;
      case (OFPAT_PUSH_PBB):
        push_pbb (pkt, (struct ofl_action_push*)action);
        break;
      case (OFPAT_POP_PBB):
        pop_pbb (pkt, action);
        break;
      case (OFPAT_EXPERIMENTER): 
        dp_exp_action (pkt, (struct ofl_action_experimenter *)action);
        break;
      default: 
        NS_LOG_WARN ("Trying to execute unknown action type " << action->type);
    }
 
  char *p = packet_to_string (pkt);
  NS_LOG_DEBUG ("Action result: "<< p);
  free (p);
}

void
OFSwitch13NetDevice::ActionOutputPort (struct packet *pkt, uint32_t out_port,
    uint32_t out_queue, uint16_t max_len, uint64_t cookie) 
{
  switch (out_port) 
    {
      case (OFPP_TABLE): 
        if (pkt->packet_out) 
          {
            // NOTE: hackish; makes sure packet cannot be resubmit to pipeline again.
            pkt->packet_out = false;
            PipelineProcessPacket (pkt);
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
          Ptr<Packet> ns3pkt = CreatePacketIn (pkt, pkt->table_id, 
              (pkt->handle_std->table_miss ? OFPR_NO_MATCH : OFPR_ACTION), cookie);
          SendToController (ns3pkt);
          break;
        }
      case (OFPP_FLOOD):
      case (OFPP_ALL): 
        {
          ofs::Port *p;
          // Send to all ports except input
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
OFSwitch13NetDevice::ActionValidate (size_t num, struct ofl_action_header **actions)
{
  for (size_t i = 0; i < num; i++) 
    {
      if (actions[i]->type == OFPAT_OUTPUT) 
        {
          struct ofl_action_output *ao = (struct ofl_action_output *)actions[i];

          if (ao->port <= OFPP_MAX && !(PortGetOfsPort (ao->port) != NULL)) 
            {
              NS_LOG_WARN ("Output action for invalid port " << ao->port);
              return ofl_error (OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT);
            }
        }
      
      /** FIXME No group support by now
      if (actions[i]->type == OFPAT_GROUP) 
        {
          struct ofl_action_group *ag = (struct ofl_action_group *)actions[i];

          if (ag->group_id <= OFPG_MAX && group_table_find(dp->groups, ag->group_id) == NULL) 
            {
              VLOG_WARN_RL(LOG_MODULE, &rl, "Group action for invalid group (%u).", ag->group_id);
              return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_GROUP);
            }
        }
      **/
    }
  return 0;
}

struct flow_table*
OFSwitch13NetDevice::FlowTableCreate (uint8_t table_id)
{
  struct flow_table *table;
  struct ds string = DS_EMPTY_INITIALIZER;

  ds_put_format (&string, "table_%u", table_id);

  table = (struct flow_table*)xmalloc (sizeof (struct flow_table));
  memset (table, 0x00, sizeof (struct flow_table));

  //table->dp = dp;
  table->disabled = 0;
  
  /*Init table stats */
  table->stats = (struct ofl_table_stats*)xmalloc (sizeof (struct ofl_table_stats));
  memset (table->stats, 0x00, sizeof (struct ofl_table_stats));
  table->stats->table_id      = table_id;
  table->stats->active_count  = 0;
  table->stats->lookup_count  = 0;
  table->stats->matched_count = 0;

  /* Init Table features */
  table->features = (struct ofl_table_features*)xmalloc (sizeof (struct ofl_table_features));
  memset (table->features, 0x00, sizeof (struct ofl_table_features));
  table->features->table_id       = table_id;
  table->features->name           = ds_cstr(&string);
  table->features->metadata_match = 0xffffffffffffffff; 
  table->features->metadata_write = 0xffffffffffffffff;
  table->features->config         = OFPTC_TABLE_MISS_CONTROLLER;
  table->features->max_entries    = FLOW_TABLE_MAX_ENTRIES;
  table->features->properties_num = flow_table_features (table->features);

  list_init (&table->match_entries);
  list_init (&table->hard_entries);
  list_init (&table->idle_entries);

  return table;
}

ofl_err
OFSwitch13NetDevice::FlowTableAdd (struct flow_table *table, struct ofl_msg_flow_mod *mod, 
    bool check_overlap, bool *match_kept, bool *insts_kept) 
{
  // Note: new entries will be placed behind those with equal priority
  struct flow_entry *entry, *new_entry;

  LIST_FOR_EACH (entry, struct flow_entry, match_node, &table->match_entries) 
    {
      if (check_overlap && flow_entry_overlaps (entry, mod)) 
        {
          return ofl_error (OFPET_FLOW_MOD_FAILED, OFPFMFC_OVERLAP);
        }

      /* if the entry equals, replace the old one */
      if (flow_entry_matches (entry, mod, true/*strict*/, false/*check_cookie*/)) 
        {
          new_entry = flow_entry_create (NULL/*table->dp*/, table, mod);
          *match_kept = true;
          *insts_kept = true;

          /* NOTE: no flow removed message should be generated according to spec. */
          list_replace (&new_entry->match_node, &entry->match_node);
          list_remove (&entry->hard_node);
          list_remove (&entry->idle_node);
          FlowEntryDestroy (entry);
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

  new_entry = flow_entry_create (NULL/*table->dp*/, table, mod);
  *match_kept = true;
  *insts_kept = true;

  list_insert (&entry->match_node, &new_entry->match_node);
  add_to_timeout_lists (table, new_entry);

  return 0;
}

ofl_err 
OFSwitch13NetDevice::FlowTableDelete (struct flow_table *table, 
    struct ofl_msg_flow_mod *mod, bool strict)
{
  struct flow_entry *entry, *next;

  LIST_FOR_EACH_SAFE (entry, next, struct flow_entry, match_node, &table->match_entries) 
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
OFSwitch13NetDevice::FlowTableModify (struct flow_table *table, 
    struct ofl_msg_flow_mod *mod, bool strict, bool *insts_kept)
{
  struct flow_entry *entry;

  LIST_FOR_EACH (entry, struct flow_entry, match_node, &table->match_entries) 
    {
      if (flow_entry_matches (entry, mod, strict, true/*check_cookie*/)) 
        {
          /* Code from flow_entry_replace_instructions (entry, mod->instructions_num, mod->instructions); */
          {
            size_t instructions_num = mod->instructions_num;
            struct ofl_instruction_header **instructions = mod->instructions;
            // FIXME No group support by now
            // del_group_refs(entry);
            OFL_UTILS_FREE_ARR_FUN2 (entry->stats->instructions, entry->stats->instructions_num, 
                ofl_structs_free_instruction, NULL/*entry->dp->exp*/);
            entry->stats->instructions_num = instructions_num;
            entry->stats->instructions = instructions;
            // init_group_refs(entry);
          }
          flow_entry_modify_stats (entry, mod);
          *insts_kept = true;
        }
    }

  return 0;
}

void
OFSwitch13NetDevice::FlowEntryRemove (struct flow_entry *entry, uint8_t reason)
{
  NS_LOG_FUNCTION_NOARGS ();

  if (entry->send_removed)
    {
      flow_entry_update (entry);
        {
          NS_LOG_DEBUG ("Flow entry expired. Notifying the controller...");
          struct ofl_msg_flow_removed msg;
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
  
  // del_group_refs (entry);
  // del_meter_refs (entry);
  ofl_structs_free_flow_stats (entry->stats, NULL/*entry->dp->exp*/);
  free (entry);
}

void 
OFSwitch13NetDevice::FlowEntryDestroy (struct flow_entry *entry)
{
  // FIXME No meter/group support by now
  // del_group_refs (entry);
  // del_meter_refs (entry);
  ofl_structs_free_flow_stats (entry->stats, NULL/*entry->dp->exp*/);
  free (entry);
}

void
OFSwitch13NetDevice::AddEthernetHeader (Ptr<Packet> p, Mac48Address source, 
    Mac48Address dest, uint16_t protocolNumber)
{
  NS_LOG_FUNCTION (p << source << dest << protocolNumber);

  EthernetHeader header (false);
  header.SetSource (source);
  header.SetDestination (dest);

  EthernetTrailer trailer;
  if (p->GetSize () < 46)
    {
      uint8_t buffer[46];
      memset (buffer, 0, 46);
      Ptr<Packet> padd = Create<Packet> (buffer, 46 - p->GetSize ());
      p->AddAtEnd (padd);
    }

  header.SetLengthType (protocolNumber);
  p->AddHeader (header);

  if (Node::ChecksumEnabled ())
    {
      trailer.EnableFcs (true);
    }
  trailer.CalcFcs (p);
  p->AddTrailer (trailer);
}

Ptr<Packet> 
OFSwitch13NetDevice::CreatePacketIn (struct packet *pkt, uint8_t tableId,
    ofp_packet_in_reason reason, uint64_t cookie)
{
  NS_LOG_FUNCTION_NOARGS (); 
  struct ofl_msg_packet_in msg;
  msg.header.type = OFPT_PACKET_IN;
  msg.total_len = pkt->buffer->size;
  msg.reason = reason;
  msg.table_id = tableId;
  msg.data = (uint8_t*)pkt->buffer->data;
  msg.cookie = cookie;

  if (m_config.miss_send_len != OFPCML_NO_BUFFER)
    {
      // FIXME No buffers support by now
      // dp_buffers_save(pkt->dp->buffers, pkt);
      // msg.buffer_id = pkt->buffer_id;
      // msg.data_length = MIN(max_len, pkt->buffer->size);
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
  msg.match = (struct ofl_match_header*)&pkt->handle_std->match;
 
  LogOflMsg ((ofl_msg_header*)&msg);
  return ofs::PacketFromMsg ((ofl_msg_header*)&msg, ++m_xid);
}


ofl_err
OFSwitch13NetDevice::HandleMsgFeaturesRequest (struct ofl_msg_header *msg, uint64_t xid)
{
  struct ofl_msg_features_reply reply;
  reply.header.type  = OFPT_FEATURES_REPLY;
  reply.datapath_id  = m_id;
  reply.n_buffers    = 0; // FIXME No buffer support by now
  reply.n_tables     = PIPELINE_TABLES;
  reply.auxiliary_id = 0; // FIXME No auxiliary connection support by now
  reply.capabilities = DP_SUPPORTED_CAPABILITIES;
  reply.reserved     = 0x00000000;

  Ptr<Packet> pkt = ofs::PacketFromMsg ((ofl_msg_header*)&reply, xid);
  LogOflMsg ((ofl_msg_header*)&reply);
  SendToController (pkt);
  
  // All handlers must free the message when everything is ok
  ofl_msg_free (msg, NULL/*dp->exp*/);
  return 0;
}

ofl_err
OFSwitch13NetDevice::HandleMsgGetConfigRequest (struct ofl_msg_header *msg, uint64_t xid)
{
  struct ofl_msg_get_config_reply reply;
  reply.header.type = OFPT_GET_CONFIG_REPLY;
  reply.config      = &m_config;

  Ptr<Packet> pkt = ofs::PacketFromMsg ((ofl_msg_header*)&reply, xid);
  LogOflMsg ((ofl_msg_header*)&reply);
  SendToController (pkt);
  
  // All handlers must free the message when everything is ok
  ofl_msg_free (msg, NULL/*dp->exp*/);
  return 0;
}

ofl_err
OFSwitch13NetDevice::HandleMsgFlowMod (struct ofl_msg_flow_mod *msg)
{
  /**
   * Modifications to a flow table from the controller are do ne with the
   * OFPT_FLOW_MOD message (including add, modify or delete).
   * \see ofsoftswitch13 pipeline_handle_flow_mod () at udatapath/pipeline.c
   * and flow_table_flow_mod () at udatapath/flow_table.c
   */

  // FIXME No table_id = 0xff support by now
  ofl_err error;
  size_t i;
  bool match_kept, insts_kept;
  match_kept = false;
  insts_kept = false;

  /*Sort by execution oder*/
  qsort (msg->instructions, msg->instructions_num, sizeof (struct ofl_instruction_header *), inst_compare);

  // Validate actions in flow_mod
  for (i = 0; i < msg->instructions_num; i++) 
    {
      if (msg->instructions[i]->type == OFPIT_APPLY_ACTIONS || msg->instructions[i]->type == OFPIT_WRITE_ACTIONS) 
        {
          struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)msg->instructions[i];

          error = ActionValidate ((size_t)ia->actions_num, ia->actions);
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
      if ((msg->table_id == (PIPELINE_TABLES - 1)) && (msg->instructions[i]->type == OFPIT_GOTO_TABLE))
        {
          return ofl_error (OFPET_BAD_INSTRUCTION, OFPBIC_UNSUP_INST);
        }
    }

  // Execute flow modification at proper table
  struct flow_table *table = m_pipeline->tables[msg->table_id];
  switch (msg->command) 
    {
      case (OFPFC_ADD): 
        {
          bool overlap = ((msg->flags & OFPFF_CHECK_OVERLAP) != 0);
          error = FlowTableAdd (table, msg, overlap, &match_kept, &insts_kept);
          break;
        }
      case (OFPFC_MODIFY): 
        {
          error =  FlowTableModify (table, msg, false, &insts_kept);
          break;
        }
      case (OFPFC_MODIFY_STRICT): 
        {
          error =  FlowTableModify (table, msg, true, &insts_kept);
          break;
        }
      case (OFPFC_DELETE): 
        {
          error = FlowTableDelete (table, msg, false);
          break;
        }
      case (OFPFC_DELETE_STRICT): 
        {
          error = FlowTableDelete (table, msg, true);
          break;
        }
      default: 
        {
          return ofl_error (OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_COMMAND);
        }
    }
  if (error) 
    {
      return error;
    }
  
  if ((msg->command == OFPFC_ADD || msg->command == OFPFC_MODIFY || msg->command == OFPFC_MODIFY_STRICT) && 
       msg->buffer_id != NO_BUFFER) 
    {
      NS_FATAL_ERROR ("Should not get in here... no buffers!");
      // FIXME No buffers support by now
      // /* run buffered message through pipeline */
      // struct packet *pkt;

      // pkt = dp_buffers_retrieve (m_pipeline->dp->buffers, msg->buffer_id);
      // if (pkt != NULL) 
      //   {
      //     pipeline_process_packet (m_pipeline, pkt);
      //   } 
      // else 
      //   {
      //     NS_LOG_ERROR ("The buffer flow_mod referred to was empty " << msg->buffer_id);
      //   }
    }

  // All handlers must free the message when everything is ok
  ofl_msg_free_flow_mod (msg, !match_kept, !insts_kept, NULL/*m_pipeline->dp->exp*/);
  return 0;
}

ofl_err 
OFSwitch13NetDevice::HandleMsgMultipartRequest (struct ofl_msg_multipart_request_header *msg, uint64_t xid)
{
  switch (msg->type) 
    {
      case (OFPMP_DESC): 
        {
          return MultipartMsgDesc (msg, xid);
        }
      case (OFPMP_FLOW): 
        {
          //return pipeline_handle_stats_request_flow(dp->pipeline, (struct ofl_msg_multipart_request_flow *)msg, sender);
        }
      case (OFPMP_AGGREGATE): 
        {
          //return pipeline_handle_stats_request_aggregate(dp->pipeline, (struct ofl_msg_multipart_request_flow *)msg, sender);
        }
      case (OFPMP_TABLE): 
        {
          //return pipeline_handle_stats_request_table(dp->pipeline, msg, sender);
        }
      case (OFPMP_TABLE_FEATURES):
        {
          //return pipeline_handle_stats_request_table_features_request(dp->pipeline, msg, sender);
        }
      case (OFPMP_PORT_STATS): 
        {
          //return dp_ports_handle_stats_request_port(dp, (struct ofl_msg_multipart_request_port *)msg, sender);
        }
      case (OFPMP_QUEUE): 
        {
          //return dp_ports_handle_stats_request_queue(dp, (struct ofl_msg_multipart_request_queue *)msg, sender);
        }
      case (OFPMP_GROUP): 
        {
          //return group_table_handle_stats_request_group(dp->groups, (struct ofl_msg_multipart_request_group *)msg, sender);
        }
      case (OFPMP_GROUP_DESC): 
        {
          //return group_table_handle_stats_request_group_desc(dp->groups, msg, sender);
        }
      case (OFPMP_GROUP_FEATURES):
        {
          //return group_table_handle_stats_request_group_features(dp->groups, msg, sender);			
      	}		
      case (OFPMP_METER):
        {
      	  //return meter_table_handle_stats_request_meter(dp->meters,(struct ofl_msg_multipart_meter_request*)msg, sender);
        }
      case (OFPMP_METER_CONFIG):
        {
          //return meter_table_handle_stats_request_meter_conf(dp->meters,(struct ofl_msg_multipart_meter_request*)msg, sender);        
        }
      case OFPMP_METER_FEATURES:
        {
          //return meter_table_handle_features_request(dp->meters, msg, sender);
        }
      case OFPMP_PORT_DESC:
        {
          //return dp_ports_handle_port_desc_request(dp, msg, sender);        
        }
      case (OFPMP_EXPERIMENTER): 
        {
          //return dp_exp_stats(dp, (struct ofl_msg_multipart_request_experimenter *)msg, sender);
        }
      default: 
        {
          return ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_MULTIPART);
        }
    }
}


ofl_err
OFSwitch13NetDevice::MultipartMsgDesc (struct ofl_msg_multipart_request_header *msg, uint64_t xid)
{

  char *mfrDesc = (char*)xmalloc (DESC_STR_LEN);
  char *hwDesc  = (char*)xmalloc (DESC_STR_LEN);
  char *swDesc  = (char*)xmalloc (DESC_STR_LEN);
  char *serDesc = (char*)xmalloc (DESC_STR_LEN);
  char *dpDesc  = (char*)xmalloc (DESC_STR_LEN);
  strcpy (mfrDesc, GetManufacturerDescription ());
  strcpy (hwDesc, GetHardwareDescription ());
  strcpy (swDesc, GetSoftwareDescription ());
  strcpy (serDesc, GetSerialNumber ());
  strcpy (dpDesc, GetDatapathDescrtiption ());

  struct ofl_msg_reply_desc reply;
  reply.header.header.type = OFPT_MULTIPART_REPLY;
  reply.header.type  = OFPMP_DESC;
  reply.header.flags = 0x0000;
  reply.mfr_desc    = mfrDesc;
  reply.hw_desc     = hwDesc;
  reply.sw_desc     = swDesc;
  reply.serial_num  = serDesc;
  reply.dp_desc     = dpDesc;

  Ptr<Packet> pkt = ofs::PacketFromMsg ((ofl_msg_header*)&reply, xid);
  LogOflMsg ((ofl_msg_header*)&reply);
  SendToController (pkt);

  free (mfrDesc);
  free (hwDesc);
  free (swDesc);
  free (serDesc);
  free (dpDesc);

  // All handlers must free the message when everything is ok
  ofl_msg_free ((struct ofl_msg_header *)msg, NULL/*dp->exp*/);
  return 0;
}


void 
OFSwitch13NetDevice::HandleCtrlRead (Ptr<Socket> socket)
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

          // Creante an ofpbuffer from packet
          uint32_t pktSize = packet->GetSize ();
          struct ofpbuf *buffer = ofpbuf_new (pktSize);
          packet->CopyData ((uint8_t*)ofpbuf_put_uninit (buffer, pktSize), pktSize);
          
          // Process the openflow buffer
          NS_ASSERT (buffer->size == pktSize);
          ReceiveFromController (buffer);
        }
    }
}

void
OFSwitch13NetDevice::HandleCtrlSucceeded (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_LOGIC ("Controller accepted connection request!");
  socket->SetRecvCallback (MakeCallback (&OFSwitch13NetDevice::HandleCtrlRead, this));

  // Send Hello message
  struct ofl_msg_header msg;
  msg.type = OFPT_HELLO;
  LogOflMsg (&msg);
  Ptr<Packet> pkt = ofs::PacketFromMsg (&msg, ++m_xid);
  SendToController (pkt);
}

void
OFSwitch13NetDevice::HandleCtrlFailed (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_ERROR ("Controller did not accepted connection request!");
}

} // namespace ns3
#endif // NS3_OFSWITCH13
