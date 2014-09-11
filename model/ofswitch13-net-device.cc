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
  ;
  return tid;
}

OFSwitch13NetDevice::OFSwitch13NetDevice ()
  : m_node (0),
    m_ctrlSocket (0),
    m_ctrlApp (0),
    m_ifIndex (0),
    m_mtu (0x0000),
    m_xid (0x00ff0000)
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

int 
OFSwitch13NetDevice::AddSwitchPort (Ptr<NetDevice> switchPort)
{
  NS_LOG_FUNCTION (this << switchPort);
  NS_LOG_DEBUG ("Adding port addr " << switchPort->GetAddress ());
  
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
  NS_LOG_DEBUG ("Port # " << no);
  
  // Notify the controller that this port has been added
  if (m_ctrlSocket)
    {
      struct ofl_msg_port_status msg;
      msg.header.type = OFPT_PORT_STATUS;
      msg.reason = OFPPR_ADD;
      msg.desc = p.conf;

      struct ofpbuf *buffer = ofs::PackFromMsg ((ofl_msg_header*)&msg, ++m_xid);
      Ptr<Packet> packet = ofs::PacketFromBufferAndFree (buffer);
      SendToController (packet);
    }

  NS_LOG_DEBUG ("RegisterProtocolHandler for " << switchPort->GetInstanceTypeId ().GetName ());
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
OFSwitch13NetDevice::SetController (Ptr<OFSwitch13Controller> c, Address addr)
{
  if (m_ctrlAddr.IsInvalid ())
    {
      m_ctrlApp = c;
      m_ctrlAddr = addr;
      // Create a TCP connection to the controller
      if (!m_ctrlSocket)
        {
          m_ctrlSocket = Socket::CreateSocket (GetNode (), TcpSocketFactory::GetTypeId ());
          m_ctrlSocket->Bind ();
          m_ctrlSocket->Connect (InetSocketAddress::ConvertFrom(addr));
        }
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
  NS_LOG_DEBUG ("Switch addr " << m_address);
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
  m_ctrlApp = 0;

  // TODO pipeline_destroy (m_pipeline);

  NetDevice::DoDispose ();
}

ofs::Port*
OFSwitch13NetDevice::GetOfsPort (Ptr<NetDevice> dev)
{
  NS_LOG_FUNCTION (dev);
  for (size_t i = 0; i < m_ports.size (); i++)
    {
      if (m_ports[i].netdev == dev)
        {
          NS_LOG_DEBUG ("Found port no " << m_ports[i].port_no);
          return &m_ports[i];
        }
    }
  return NULL;
}

ofs::Port*
OFSwitch13NetDevice::GetOfsPort (uint32_t no)
{
  NS_LOG_FUNCTION (no);
  NS_ASSERT_MSG (no > 0 && no <= m_ports.size (), "Invalid port number");

  if (m_ports[no-1].port_no == no)
    {
      NS_LOG_DEBUG ("Found port no " << m_ports[no-1].port_no);
      return &m_ports[no-1];
    }
  
  for (size_t i = 0; i < m_ports.size (); i++)
    {
      if (m_ports[i].port_no == no)
        {
          NS_LOG_DEBUG ("Found port no " << m_ports[i].port_no);
          return &m_ports[i];
        }
    }
  return NULL;
}

int
OFSwitch13NetDevice::ReceiveFromController (ofpbuf* buffer)
{ 
  uint32_t xid;
  struct ofl_msg_header *msg;
  ofl_msg_unpack ((uint8_t*)buffer->data, buffer->size, &msg, &xid, NULL/*&ofl_exp*/);
  ofpbuf_delete (buffer);   // TODO validar se esse free não está causando problemas
 
  char *str; 
  str = ofl_msg_to_string ((ofl_msg_header*)msg, NULL/*&ofl_exp*/);
  NS_LOG_INFO ("RECEIVING: " << str);
  free (str);

  // For not defined messages, default error ;)
  ofl_err error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
  switch (msg->type)
    {
      // TODO: implementar todas os outros tipos de Handle*Msg ()
      case OFPT_HELLO:
        break;
      case OFPT_ERROR:
        break;
      case OFPT_ECHO_REQUEST:
      case OFPT_ECHO_REPLY:
        break;
      case OFPT_EXPERIMENTER:
        NS_LOG_WARN ("No support for EXPERIMENTER message.");
        error = ofl_error (OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        break;

      /* Switch configuration messages. */
      case OFPT_FEATURES_REQUEST:
        break;
      case OFPT_FEATURES_REPLY:
        break;
      case OFPT_GET_CONFIG_REQUEST:
        break;
      case OFPT_GET_CONFIG_REPLY:
        break;
      case OFPT_SET_CONFIG:
        break;

      /* Asynchronous messages. */
      case OFPT_PACKET_IN:
        break;
      case OFPT_FLOW_REMOVED:
        break;
      case OFPT_PORT_STATUS:
        break;

      /* Controller command messages. */
      case OFPT_GET_ASYNC_REQUEST:
        break;       
      case OFPT_GET_ASYNC_REPLY:
      case OFPT_SET_ASYNC:
        break;
      case OFPT_PACKET_OUT:
        break;
      case OFPT_FLOW_MOD:
        error = HandleMsgFlowMod ((struct ofl_msg_flow_mod*)msg); 
        break;
      case OFPT_GROUP_MOD:
        break;
      case OFPT_PORT_MOD:
        break;
      case OFPT_TABLE_MOD:
        break;

      /* Statistics messages. */
      case OFPT_MULTIPART_REQUEST:
        break;
      case OFPT_MULTIPART_REPLY:
        break;

      /* Barrier messages. */
      case OFPT_BARRIER_REQUEST:
      case OFPT_BARRIER_REPLY:
        break;
      
      /* Role messages. */
      case OFPT_ROLE_REQUEST:
      case OFPT_ROLE_REPLY:
        break;

      /* Queue Configuration messages. */
      case OFPT_QUEUE_GET_CONFIG_REQUEST:
        break;
      case OFPT_QUEUE_GET_CONFIG_REPLY:
        break;
      case OFPT_METER_MOD:
        break;            
      
      default: 
        error = ofl_error (OFPET_BAD_REQUEST, OFPGMFC_BAD_TYPE);
    }
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
  
  NS_LOG_DEBUG ("Switch id " << this->GetNode()->GetId() << 
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

  /** Starting pipeline process... **/

  // Get the input port and check configuration
  ofs::Port* inPort = GetOfsPort (netdev);
  NS_ASSERT_MSG (inPort != NULL, "This device is not registered as a switch port");
  if (inPort->conf->config & ((OFPPC_NO_RECV | OFPPC_PORT_DOWN) != 0)) 
    {
      NS_LOG_DEBUG ("This port is down or inoperating. Discarding packet");
      return;
    }

  /**
   * Adding the ethernet header back to the packet. It was removed by
   * CsmaNetDevice but we need L2 information for the pipeline.
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
  struct packet *pkt = InternalPacketCreate (inPort->stats->port_no, buffer, false);

  // Update port stats
  inPort->stats->rx_packets++;
  inPort->stats->rx_bytes += buffer->size;

  // Runs the packet through the pipeline
  Simulator::Schedule (m_lookupDelay, &OFSwitch13NetDevice::PipelineProcessPacket, this, 0, pkt, inPort);
  //TODO descobrir onde iremos liberar o buffer e o pacote 
}

int 
SendToSwitchPort (Ptr<Packet> packet, Ptr<NetDevice> netdev)
{
  //TODO: implementar
  return 0;
}

struct packet *
OFSwitch13NetDevice::InternalPacketCreate (uint32_t in_port, struct ofpbuf *buf, 
    bool packet_out) 
{
  struct packet *pkt;

  pkt = (struct packet*)xmalloc (sizeof (struct packet));

  pkt->dp         = NULL;
  pkt->buffer     = buf;
  pkt->in_port    = in_port;
  pkt->action_set = (struct action_set*)xmalloc (sizeof (struct action_set));
  list_init(&pkt->action_set->actions);

  pkt->packet_out       = packet_out;
  pkt->out_group        = OFPG_ANY;
  pkt->out_port         = OFPP_ANY;
  pkt->out_port_max_len = 0;
  pkt->out_queue        = 0;
  pkt->buffer_id        = NO_BUFFER;
  pkt->table_id         = 0;

  pkt->handle_std = packet_handle_std_create (pkt);
  return pkt;
}


void
OFSwitch13NetDevice::PipelineProcessPacket (uint32_t packet_uid, 
    struct packet* pkt, ofs::Port* inPort)
{
  struct flow_table *table, *next_table;
  struct flow_entry *entry;
 
  NS_LOG_DEBUG ("processing packet: " << packet_to_string (pkt));

  // Check ttl
  if (!packet_handle_std_is_ttl_valid (pkt->handle_std)) 
    {
      if ((m_config.flags & OFPC_INVALID_TTL_TO_CONTROLLER) != 0) 
        {
          NS_LOG_DEBUG ("Packet has invalid TTL, sending to controller.");
          // TODO send_packet_to_controller(pl, pkt, 0/*table_id*/, OFPR_INVALID_TTL);
        } 
      else 
        {
          NS_LOG_DEBUG ("Packet has invalid TTL, dropping.");
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
          ExecuteEntry (m_pipeline, entry, &next_table, &pkt); //TODO: implementar a realização das ações...
          
          /* Packet could be destroyed by a meter instruction */
          if (!pkt)
            return;

          if (next_table == NULL) 
            {
              // action_set_execute (pkt->action_set, pkt, 0xffffffffffffffff);
              packet_destroy (pkt);
              return;
            }
        } 
      else 
        {
          /* OpenFlow 1.3 default behavior on a table miss */
          NS_LOG_DEBUG("No matching entry found. Dropping packet.");
          packet_destroy (pkt);
          return;
        }
    }
    NS_LOG_ERROR ("Reached outside of pipeline processing cycle.");
}


void
OFSwitch13NetDevice::ExecuteEntry (struct pipeline *pl, struct flow_entry *entry, 
      struct flow_table **next_table, struct packet **pkt)
{
  /** NOTE: instructions, when present, will be executed in
   *       the following order:
   *       Meter
   *       Apply-Actions
   *       Clear-Actions
   *       Write-Actions
   *       Write-Metadata
   *       Goto-Table
   **/
  size_t i;
  struct ofl_instruction_header *inst;

  for (i=0; i < entry->stats->instructions_num; i++) 
    {
      /*Packet was dropped by some instruction or action*/

      if(!(*pkt))
        {
          return;
        }
      
      inst = entry->stats->instructions[i];
      switch (inst->type) 
        { // TODO: implementar outros tipos de acoes
          case OFPIT_GOTO_TABLE: 
            {
              struct ofl_instruction_goto_table *gi = (struct ofl_instruction_goto_table *)inst;
              *next_table = pl->tables[gi->table_id];
              break;
            }
          case OFPIT_WRITE_METADATA: 
            {
//              struct ofl_instruction_write_metadata *wi = (struct ofl_instruction_write_metadata *)inst;
//              struct  ofl_match_tlv *f;
//
//              /* NOTE: Hackish solution. If packet had multiple handles, metadata
//               *       should be updated in all. */
//              packet_handle_std_validate((*pkt)->handle_std);
//              /* Search field on the description of the packet. */
//              HMAP_FOR_EACH_WITH_HASH(f, struct ofl_match_tlv,
//                  hmap_node, hash_int(OXM_OF_METADATA,0), &(*pkt)->handle_std->match.match_fields){
//                  uint64_t *metadata = (uint64_t*) f->value;
//                  *metadata = (*metadata & ~wi->metadata_mask) | (wi->metadata & wi->metadata_mask);
//                  VLOG_DBG_RL(LOG_MODULE, &rl, "Executing write metadata: %"PRIu64"", *metadata);
//              }
              break;
            }
          case OFPIT_WRITE_ACTIONS: 
            {
//              struct ofl_instruction_actions *wa = (struct ofl_instruction_actions *)inst;
//              action_set_write_actions((*pkt)->action_set, wa->actions_num, wa->actions);
              break;
            }
          case OFPIT_APPLY_ACTIONS: 
            {
              struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)inst;
              ExecuteActionList ((*pkt), ia->actions_num, ia->actions, entry->stats->cookie);
              break;
            }
          case OFPIT_CLEAR_ACTIONS: 
            {
//              action_set_clear_actions((*pkt)->action_set);
//              break;
            }
          case OFPIT_METER: 
            {
//              struct ofl_instruction_meter *im = (struct ofl_instruction_meter *)inst;
//              meter_table_apply(pl->dp->meters, pkt , im->meter_id);
              break;
            }
          case OFPIT_EXPERIMENTER: 
            {
//              dp_exp_inst((*pkt), (struct ofl_instruction_experimenter *)inst);
              break;
            }
        }
    }
}


void
OFSwitch13NetDevice::ExecuteActionList (struct packet *pkt, size_t actions_num,
    struct ofl_action_header **actions, uint64_t cookie) 
{
  NS_LOG_DEBUG ("Executing action list.");
  
  size_t i;
  for (i=0; i < actions_num; i++) 
    {
      struct ofl_action_header *action = actions[i];
      char *a = ofl_action_to_string(action, NULL/*pkt->dp->exp*/);
      NS_LOG_DEBUG ("executing action " << a);
      free(a);

      switch (action->type) 
        { // TODO: implementar outros tipos de acoes
          case (OFPAT_SET_FIELD): 
            {
//              set_field(pkt,(struct ofl_action_set_field*) action);
              break;
            }
           case (OFPAT_OUTPUT): 
            {
              output (pkt, (struct ofl_action_output *)action);
              break;
            }
          case (OFPAT_COPY_TTL_OUT): 
            {
//              copy_ttl_out(pkt, action);
              break;
            }
          case (OFPAT_COPY_TTL_IN):
            {
//              copy_ttl_in(pkt, action);
              break;
            }
          case (OFPAT_SET_MPLS_TTL):
            {
//              set_mpls_ttl(pkt, (struct ofl_action_mpls_ttl *)action);
              break;
            }
          case (OFPAT_DEC_MPLS_TTL): 
            {
//              dec_mpls_ttl(pkt, action);
              break;
            }
          case (OFPAT_PUSH_VLAN): 
            {
//              push_vlan(pkt, (struct ofl_action_push *)action);
              break;
            }
          case (OFPAT_POP_VLAN): 
            {
//              pop_vlan(pkt, action);
              break;
            }
          case (OFPAT_PUSH_MPLS): 
            {
//              push_mpls(pkt, (struct ofl_action_push *)action);
              break;
            }
          case (OFPAT_POP_MPLS): 
            {
//              pop_mpls(pkt, (struct ofl_action_pop_mpls *)action);
              break;
            }
          case (OFPAT_SET_QUEUE): 
            {
//              set_queue(pkt, (struct ofl_action_set_queue *)action);
              break;
            }
          case (OFPAT_GROUP): 
            {
//              group(pkt, (struct ofl_action_group *)action);
              break;
            }
          case (OFPAT_SET_NW_TTL): 
            {
//              set_nw_ttl(pkt, (struct ofl_action_set_nw_ttl *)action);
              break;
            }
          case (OFPAT_DEC_NW_TTL): 
            {
//              dec_nw_ttl(pkt, action);
              break;
            }
          case (OFPAT_PUSH_PBB):{
//              push_pbb(pkt, (struct ofl_action_push*)action);
              break;
            }
          case (OFPAT_POP_PBB):{
//              pop_pbb(pkt, action);
              break;
            }
          case (OFPAT_EXPERIMENTER): 
            {
//          	dp_exp_action(pkt, (struct ofl_action_experimenter *)action);
              break;
            }

          default: 
            {
              NS_LOG_WARN ("Trying to execute unknown action type " << action->type);
            }
        }
     
      char *p = packet_to_string(pkt);
      NS_LOG_DEBUG ("Action result: "<< p);
      free(p);
      
      if (pkt->out_group != OFPG_ANY) 
        {
          uint32_t group = pkt->out_group;
          pkt->out_group = OFPG_ANY;
          NS_LOG_DEBUG ("Group action; executing group " << group);
//          group_table_execute(pkt->dp->groups, pkt, group);
        } 
      else if (pkt->out_port != OFPP_ANY) 
        {
          uint32_t port = pkt->out_port;
          uint32_t queue = pkt->out_queue;
          uint16_t max_len = pkt->out_port_max_len;
          pkt->out_port = OFPP_ANY;
          pkt->out_port_max_len = 0;
          pkt->out_queue = 0;
          NS_LOG_DEBUG ("Port action; sending to port " << port);
          ActionsOutputPort (pkt, port, queue, max_len, cookie);
        }
    }
}


void
OFSwitch13NetDevice::ActionsOutputPort (struct packet *pkt, uint32_t out_port,
    uint32_t out_queue, uint16_t max_len, uint64_t cookie) 
{
    switch (out_port) 
      {
        case (OFPP_TABLE): 
          {
            if (pkt->packet_out) 
              {
                // NOTE: hackish; makes sure packet cannot be resubmit to pipeline again.
                pkt->packet_out = false;
                NS_FATAL_ERROR ("Should not get in here... check this!"); // FIXME gambiarra
                // pipeline_process_packet (pkt->dp->pipeline, pkt);
              } 
            else 
              {
                NS_LOG_WARN ("Trying to resubmit packet to pipeline.");
              }
            break;
          }
        case (OFPP_IN_PORT): 
          {
//            dp_ports_output (pkt->dp, pkt->buffer, pkt->in_port, 0);
            break;
          }
        case (OFPP_CONTROLLER): 
          {
//            struct ofl_msg_packet_in msg;
//            msg.header.type = OFPT_PACKET_IN;
//            msg.total_len   = pkt->buffer->size;
//            msg.reason = pkt->handle_std->table_miss? OFPR_NO_MATCH:OFPR_ACTION;
//            msg.table_id = pkt->table_id;
//            msg.data        = pkt->buffer->data;
//            msg.cookie = cookie;
//
//            if (pkt->dp->config.miss_send_len != OFPCML_NO_BUFFER){
//                dp_buffers_save(pkt->dp->buffers, pkt);
//                msg.buffer_id = pkt->buffer_id;
//                msg.data_length = MIN(max_len, pkt->buffer->size);
//            }
//            else {
//                msg.buffer_id = OFP_NO_BUFFER;
//                msg.data_length =  pkt->buffer->size;
//            }
//
//            if (!pkt->handle_std->valid){
//                packet_handle_std_validate(pkt->handle_std);
//            }
//            /* In this implementation the fields in_port and in_phy_port
//                always will be the same, because we are not considering logical
//                ports*/
//            msg.match = (struct ofl_match_header*) &pkt->handle_std->match;
//            dp_send_message(pkt->dp, (struct ofl_msg_header *)&msg, NULL);
            break;
          }
        case (OFPP_FLOOD):
        case (OFPP_ALL): 
          {
//            dp_ports_output_all(pkt->dp, pkt->buffer, pkt->in_port, out_port == OFPP_FLOOD);
            break;
          }
        case (OFPP_NORMAL):
            // TODO Zoltan: Implement
        case (OFPP_LOCAL):
        default: 
          {
            if (pkt->in_port == out_port) 
              {
                NS_LOG_WARN ("can't directly forward to input port.");
              } 
            else 
              {
                NS_LOG_DEBUG ("Outputting packet on port " << out_port);
                PortOutput (pkt, out_port);
              }
          }
      }
}


void
OFSwitch13NetDevice::PortOutput (struct packet *pkt, int out_port)
{
  if (out_port >= 0 && out_port < DP_MAX_PORTS)
    {
      ofs::Port *p = GetOfsPort (out_port);
      if (p->netdev != 0 && p->conf->config & ((OFPPC_NO_RECV | OFPPC_PORT_DOWN) != 0)) 
        {
         // ofi::SwitchPacketMetadata data = m_packetData.find (packet_uid)->second;
         // size_t bufsize = data.buffer->size;
         // NS_LOG_INFO ("Sending packet " << data.packet->GetUid () << " over port " << out_port);
         // if (p->netdev->SendFrom (data.packet->Copy (), data.src, data.dst, data.protocolNumber))
         //   {
         //     p->tx_packets++;
         //     p->tx_bytes += bufsize;
         //   }
         // else
         //   {
         //     p->tx_dropped++;
         //   }
         // return;
        }
    }

  NS_LOG_DEBUG ("can't forward to bad port " << out_port);
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

  new_entry = flow_entry_create (NULL/*table->dp*/, table, mod);
  *match_kept = true;
  *insts_kept = true;

  list_insert (&entry->match_node, &new_entry->match_node);
  add_to_timeout_lists (table, new_entry);

  return 0;
}

ofl_err 
OFSwitch13NetDevice::ActionsValidate (size_t num, struct ofl_action_header **actions)
{
  for (size_t i = 0; i < num; i++) 
    {
      if (actions[i]->type == OFPAT_OUTPUT) 
        {
          struct ofl_action_output *ao = (struct ofl_action_output *)actions[i];

          if (ao->port <= OFPP_MAX && !(GetOfsPort (ao->port) != NULL)) 
            {
              NS_LOG_WARN ("Output action for invalid port " << ao->port);
              return ofl_error (OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT);
            }
        }
      
      /** FIXME No support for groups by now
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

void
OFSwitch13NetDevice::PipelineTimeout ()
{
  // meter_table_add_tokens(dp->meters);
      
  /** // FIXME Disabled due to time incompatibility from simulator and ofsoftswitch13 
  
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
      if (UpdatePortStatus (p))
        {
          NS_LOG_DEBUG ("Port configuration has changed. Notifying the controller...");
          struct ofl_msg_port_status msg;
          msg.header.type = OFPT_PORT_STATUS;
          msg.reason = OFPPR_MODIFY;
          msg.desc = p->conf;

          struct ofpbuf *buffer = ofs::PackFromMsg ((ofl_msg_header*)&msg, ++m_xid);
          Ptr<Packet> packet = ofs::PacketFromBufferAndFree (buffer);
          SendToController (packet);
        }
    }

  Simulator::Schedule (m_timeout , &OFSwitch13NetDevice::PipelineTimeout, this);
  m_lastTimeout = Simulator::Now ();
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

          struct ofpbuf *buffer = ofs::PackFromMsg ((ofl_msg_header*)&msg, ++m_xid);
          Ptr<Packet> packet = ofs::PacketFromBufferAndFree (buffer);
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

int
OFSwitch13NetDevice::UpdatePortStatus (ofs::Port *p)
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


/**
 * Modifications to a flow table from the controller are do ne with the
 * OFPT_FLOW_MOD message (including add, modify or delete).
 * \see ofsoftswitch13 pipeline_handle_flow_mod () at udatapath/pipeline.c
 * and flow_table_flow_mod () at udatapath/flow_table.c
 */
ofl_err
OFSwitch13NetDevice::HandleMsgFlowMod (struct ofl_msg_flow_mod *msg)
{
  // No support for table_id = 0xff by now
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

          error = ActionsValidate ((size_t)ia->actions_num, ia->actions);
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
          FlowTableAdd (table, msg, overlap, &match_kept, &insts_kept);
          break;
        }
      case (OFPFC_MODIFY): 
        {
      //    error =  flow_table_modify (table, msg, false, &insts_kept);
           break;
        }
      case (OFPFC_MODIFY_STRICT): 
        {
      //    error =  flow_table_modify (table, msg, true, &insts_kept);
            break;
        }
      case (OFPFC_DELETE): 
        {
      //    error =  flow_table_delete (table, msg, false);
          break;
        }
      case (OFPFC_DELETE_STRICT): 
        {
      //    error =  flow_table_delete (table, msg, true);
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
  ofl_msg_free_flow_mod (msg, !match_kept, !insts_kept, NULL/*m_pipeline->dp->exp*/);
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
          NS_LOG_DEBUG ("At time " << Simulator::Now ().GetSeconds ()
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
  NS_LOG_DEBUG ("Controller accepted connection request!");
  //Ipv4Address temp = socket->GetNode()->GetObject<Ipv4>()->GetAddress(1,0).GetLocal();
  //m_clientAddress = temp;
  socket->SetRecvCallback (MakeCallback (&OFSwitch13NetDevice::HandleCtrlRead, this));
  //SendRequest(socket, "main/object");
}

void
OFSwitch13NetDevice::HandleCtrlFailed (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_ERROR ("Controller did not accepted connection request!");
}


} // namespace ns3

#endif // NS3_OFSWITCH13
