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

NS_LOG_COMPONENT_DEFINE ("OFSwitch13NetDevice");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (OFSwitch13NetDevice)
  ;

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
                   "The identification of the OFSwitch13NetDevice/Datapath, needed for OpenFlow compatibility.",
                   UintegerValue (GenerateId ()),
                   MakeUintegerAccessor (&OFSwitch13NetDevice::m_id),
                   MakeUintegerChecker<uint64_t> ())
  ;
  return tid;
}

OFSwitch13NetDevice::OFSwitch13NetDevice ()
  : m_node (0),
    m_ifIndex (0),
    m_mtu (0xffff)
{
  NS_LOG_FUNCTION_NOARGS ();

  m_channel = CreateObject<BridgeChannel> ();
  SetAddress (Mac48Address::Allocate ()); 
  
  m_ports.reserve (DP_MAX_PORTS);

  // Initializing the datapath, as in dp_net at udatapath/datapath.c
  NS_LOG_INFO ("OpenFlow version " << OFP_VERSION);
  NS_LOG_DEBUG ("Switch addr " << m_address);
  
  // Create the pipeline
  time_init ();
  m_pipeline = (struct pipeline*)xmalloc (sizeof (struct pipeline));
  for (int i=0; i<PIPELINE_TABLES; i++) 
    {
      m_pipeline->tables[i] = FlowTableCreate (i);
    }
 
  // Switch configuration
  m_config.flags = OFPC_FRAG_NORMAL;
  m_config.miss_send_len = OFP_DEFAULT_MISS_SEND_LEN;

  nblink_initialize(); // FIXME Vou mesmo usar o nblink?
  ns3::Packet::EnablePrinting (); // FIXME: 
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
  
  Ptr<CsmaNetDevice> csmaSwitchPort = switchPort->GetObject<CsmaNetDevice> ();
  if (!csmaSwitchPort)
    {
      NS_FATAL_ERROR ("NetDevice must be of CsmaNetDevice type.");
    }
  if (csmaSwitchPort->GetEncapsulationMode () != CsmaNetDevice::DIX)
    {
      NS_FATAL_ERROR ("CsmaNetDevice must use DIX encapsulation.");
    }

  if (m_ports.size () >= DP_MAX_PORTS)
    {
      return EXFULL;
    }

  int no = m_ports.size () + 1;
  NS_LOG_DEBUG ("Port # " << no);

  ofs::Port p (switchPort, no);
  m_ports.push_back (p);
  
  // TODO: Notify the controller that this port has been added
  // {
  // struct ofl_msg_port_status msg =
  //       {{.type = OFPT_PORT_STATUS},
  //         .reason = OFPPR_ADD, .desc = p.conf};
  // SendPortStatus (p, OFPPR_ADD);
  // dp_send_message(dp, (struct ofl_msg_header *)&msg, NULL/*sender*/);
  // }

  NS_LOG_DEBUG ("RegisterProtocolHandler for " << switchPort->GetInstanceTypeId ().GetName ());
  m_node->RegisterProtocolHandler (MakeCallback (&OFSwitch13NetDevice::ReceiveFromDevice, this), 0, switchPort, true);
  m_channel->AddChannel (switchPort->GetChannel ());
  return 0;
}

uint32_t
OFSwitch13NetDevice::GetNSwitchPorts (void) const
{
  return m_ports.size ();
}

void
OFSwitch13NetDevice::SetController (Ptr<OFSwitch13Controller> c)
{
  if (m_controller != 0)
    {
      NS_LOG_ERROR ("Controller already set.");
      return;
    }
  m_controller = c;
  m_controller->AddSwitch (this);
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

  // TODO implementar aqui o envio do buffer openflow pela porta adequada....
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


/********** Protected methods **********/


void
OFSwitch13NetDevice::DoDispose ()
{
  NS_LOG_FUNCTION_NOARGS ();

  for (Ports_t::iterator b = m_ports.begin (), e = m_ports.end (); b != e; b++)
    {
      // TODO: Notify the controller that this port has been deleted
      // SendPortStatus (*b, OFPPR_DELETE);
      b->netdev = 0;
      ofl_structs_free_port (b->conf);
      free (b->stats);
    }
  
  m_ports.clear ();
  m_channel = 0;
  m_node = 0;
 
  //pipeline_destroy (m_pipeline);

  NetDevice::DoDispose ();
}

ofs::Port*
OFSwitch13NetDevice::GetPortFromNetDevice (Ptr<NetDevice> dev)
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
OFSwitch13NetDevice::GetPortFromNumber (uint32_t no)
{
  NS_LOG_FUNCTION ("Port number " << no);
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


void
OFSwitch13NetDevice::ReceiveFromDevice (Ptr<NetDevice> netdev, 
    Ptr<const Packet> packet, uint16_t protocol, const Address& src, 
    const Address& dst, PacketType packetType)
{
  NS_LOG_FUNCTION_NOARGS ();
  //Ptr<CsmaNetDevice> csmaNetDev = netdev->GetObject<CsmaNetDevice> ();
  
  Mac48Address src48 = Mac48Address::ConvertFrom (src);
  Mac48Address dst48 = Mac48Address::ConvertFrom (dst);
  
  NS_LOG_DEBUG ("Switch " << this->GetNode()->GetId() << 
                " -- Pkt UID: " << packet->GetUid ());
  NS_LOG_DEBUG ("Received packet type " << packetType << 
                " from " << src48 << " looking for " << dst48);

  if (!m_promiscRxCallback.IsNull ())
    {
      m_promiscRxCallback (this, packet, protocol, src, dst, packetType);
    }
 
  ofs::Port* inPort = GetPortFromNetDevice (netdev);
  NS_ASSERT_MSG (inPort != NULL, "This device is not registered as a switch port");

  if (packetType == PACKET_HOST && dst48 == m_address)
    {
      m_rxCallback (this, packet, protocol, src);
    }
  else if (packetType == PACKET_BROADCAST || packetType == PACKET_MULTICAST || packetType == PACKET_OTHERHOST)
    {
      if (packetType == PACKET_OTHERHOST && dst48 == m_address)
        {
          m_rxCallback (this, packet, protocol, src);
        }
      else
        {
          if (packetType != PACKET_OTHERHOST)
            {
              m_rxCallback (this, packet, protocol, src);
            }

          ofs::SwitchPacketMetadata data;
          data.packet = packet->Copy ();
          
          ofpbuf *buffer = Of13BufferCreate (data.packet, src48, dst48, netdev->GetMtu (), protocol);
          data.buffer = buffer;
          
          inPort->stats->rx_packets++;
          inPort->stats->rx_bytes += buffer->size;

          data.protocolNumber = protocol;
          data.src = Address (src);
          data.dst = Address (dst);
          // m_packetData.insert (std::make_pair (packet_uid, data));

          // TODO descobrir onde iremos liberar o buffer e o pacote 
          PipelineProcessBuffer (0, buffer, inPort);

        }
    }

/*
  // Run periodic execution.
  Time now = Simulator::Now ();
  if (now >= Seconds (m_lastExecute.GetSeconds () + 1)) // If a second or more has passed from the simulation time, execute.
    {
      // If port status is modified in any way, notify the controller.
      for (size_t i = 0; i < m_ports.size (); i++)
        {
          if (UpdatePortStatus (m_ports[i]))
            {
              SendPortStatus (m_ports[i], OFPPR_MODIFY);
            }
        }

      // If any flows have expired, delete them and notify the controller.
      List deleted = LIST_INITIALIZER (&deleted);
      sw_flow *f, *n;
      chain_timeout (m_chain, &deleted);
      LIST_FOR_EACH_SAFE (f, n, sw_flow, node, &deleted)
      {
        std::ostringstream str;
        str << "Flow [";
        for (int i = 0; i < 6; i++)
          str << (i!=0 ? ":" : "") << std::hex << f->key.flow.dl_src[i]/16 << f->key.flow.dl_src[i]%16;
        str << " -> ";
        for (int i = 0; i < 6; i++)
          str << (i!=0 ? ":" : "") << std::hex << f->key.flow.dl_dst[i]/16 << f->key.flow.dl_dst[i]%16;
        str <<  "] expired.";
        
        NS_LOG_INFO (str.str ());
        SendFlowExpired (f, (ofp_flow_expired_reason)f->reason);
        list_remove (&f->node);
        flow_free (f);
      }

      m_lastExecute = now;
    }
*/
}


ofpbuf *
OFSwitch13NetDevice::Of13BufferCreate (Ptr<Packet> packet, Mac48Address src, 
    Mac48Address dst, int mtu, uint16_t protocol)
{
  NS_LOG_INFO ("Creating Openflow buffer from packet.");

  /*
   * Allocate buffer with some headroom to add headers in forwarding
   * to the controller or adding a vlan tag, plus an extra 2 bytes to
   * allow IP headers to be aligned on a 4-byte boundary.
   */
  const int headroom = 128 + 2;
  const int hard_header = VLAN_ETH_HEADER_LEN;
  ofpbuf *buffer = ofpbuf_new_with_headroom (hard_header + mtu, headroom);

  // Adding the ethernet header
  Ptr<Packet> pktCopy = packet->Copy ();
  AddEthernetHeader (pktCopy, src, dst, protocol);

  ofpbuf_put_uninit (buffer, pktCopy->GetSize ());
  pktCopy->CopyData ((uint8_t*)buffer->data, pktCopy->GetSize ());

  return buffer;
}

struct packet *
OFSwitch13NetDevice::Of13PacketCreate (uint32_t in_port, struct ofpbuf *buf, 
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
OFSwitch13NetDevice::PipelineProcessBuffer (uint32_t packet_uid, 
    struct ofpbuf* buffer, ofs::Port* inPort)
{
  struct packet *pkt;
  struct flow_table *table, *next_table;
  struct flow_entry *entry;
 
  /* Runs a datapath packet through the pipeline, if the port is not set to down. */
  if (inPort->conf->config & ((OFPPC_NO_RECV | OFPPC_PORT_DOWN) != 0)) 
    {
      NS_LOG_DEBUG ("This port is down or inoperating. Discarding packet");
      ofpbuf_delete (buffer);
      // TODO: Aqui significa que a porta esta desligada. Então é preciso nao
      // só deletar o buffer mas liberar tb o ofs::SwitchPacketMetadata 
      return;
    }
  
  // packet takes ownership of ofpbuf buffer
  pkt = Of13PacketCreate (inPort->stats->port_no, buffer, false);
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
          // ExecuteEntry (pl, entry, &next_table, &pkt); //TODO: implementar a realização das ações...
          
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


ofl_err
OFSwitch13NetDevice::HandleFlowMod (struct ofl_msg_flow_mod *msg)
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
      NS_FATAL_ERROR ("Should not get in here... check this!");
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
  ofl_msg_free_flow_mod (msg, !match_kept, !insts_kept, NULL);
  return 0;
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
          new_entry = flow_entry_create (table->dp, table, mod);
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

  new_entry = flow_entry_create (table->dp, table, mod);
  *match_kept = true;
  *insts_kept = true;

  list_insert (&entry->match_node, &new_entry->match_node);
  add_to_timeout_lists (table, new_entry);

  return 0;
}

struct flow_table *
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
  table->features->properties_num = flow_table_features (table_id, table->features);

  list_init (&table->match_entries);
  list_init (&table->hard_entries);
  list_init (&table->idle_entries);

  return table;
}

ofl_err 
OFSwitch13NetDevice::ActionsValidate (size_t num, struct ofl_action_header **actions)
{
  size_t i;

  for (i=0; i < num; i++) 
    {
      if (actions[i]->type == OFPAT_OUTPUT) 
        {
          struct ofl_action_output *ao = (struct ofl_action_output *)actions[i];

          if (ao->port <= OFPP_MAX && !(GetPortFromNumber (ao->port) != NULL)) 
            {
              NS_LOG_WARN ("Output action for invalid port " << ao->port);
              return ofl_error (OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT);
            }
        }
      // TODO No support for groups by now
      // if (actions[i]->type == OFPAT_GROUP) 
      //   {
      //     struct ofl_action_group *ag = (struct ofl_action_group *)actions[i];

      //     if (ag->group_id <= OFPG_MAX && group_table_find(dp->groups, ag->group_id) == NULL) 
      //       {
      //         VLOG_WARN_RL(LOG_MODULE, &rl, "Group action for invalid group (%u).", ag->group_id);
      //         return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_GROUP);
      //       }
      //   }
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



} // namespace ns3

#endif // NS3_OFSWITCH13
