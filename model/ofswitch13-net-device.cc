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
  m_ports.reserve (DP_MAX_PORTS);
  SetAddress (Mac48Address::Allocate ()); 

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
 
  pipeline_destroy (m_pipeline);

  NetDevice::DoDispose ();
}

ofs::Port*
OFSwitch13NetDevice::GetPortFromNetDevice (Ptr<CsmaNetDevice> dev)
{
  for (size_t i = 0; i < m_ports.size (); i++)
    {
      if (m_ports[i].netdev == dev)
        {
          return &m_ports[i];
        }
    }
  return NULL;
}


void
OFSwitch13NetDevice::ReceiveFromDevice (Ptr<NetDevice> netdev, Ptr<const Packet> packet, 
    uint16_t protocol, const Address& src, const Address& dst, PacketType packetType)
{
  NS_LOG_FUNCTION_NOARGS ();
  Ptr<CsmaNetDevice> csmaNetDev = netdev->GetObject<CsmaNetDevice> ();
  
  Mac48Address src48 = Mac48Address::ConvertFrom (src);
  Mac48Address dst48 = Mac48Address::ConvertFrom (dst);
  
  NS_LOG_DEBUG ("Switch " << this->GetNode()->GetId() << " -- Pkt UID: " << packet->GetUid ());
  NS_LOG_DEBUG ("Received packet type " << packetType << " from " << src48 << " looking for " << dst48);

  if (!m_promiscRxCallback.IsNull ())
    {
      m_promiscRxCallback (this, packet, protocol, src, dst, packetType);
    }
 
  ofs::Port* inPort = GetPortFromNetDevice (csmaNetDev);
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

          // ofi::SwitchPacketMetadata data;
          // data.packet = packet->Copy ();
          //
          // //                  m_ports[i].rx_packets++;
          // m_ports[i].rx_bytes += buffer->size;
          // data.buffer = buffer;
          // uint32_t packet_uid = save_buffer (buffer);
          //
          // data.protocolNumber = protocol;
          // data.src = Address (src);
          // data.dst = Address (dst);
          // m_packetData.insert (std::make_pair (packet_uid, data));
          //
          // RunThroughFlowTable (packet_uid, i);

          
          
          
          
          ofs::SwitchPacketMetadata data;
          data.packet = packet->Copy ();
          
          ofpbuf *buffer = BufferFromPacket (data.packet, src48, dst48, netdev->GetMtu (), protocol);
          // data.buffer = buffer;
          // uint32_t packet_uid = dp_buffers_save (); // FIXME Precisa resolver essa parada de salvar o buffer
          
          inPort->stats->rx_packets++;
          inPort->stats->rx_bytes += buffer->size;

          // data.protocolNumber = protocol;
          // data.src = Address (src);
          // data.dst = Address (dst);
          // m_packetData.insert (std::make_pair (packet_uid, data));

          // ProcessBuffer....

       
          // TODO processar o buffer pelo pipeline.... e liberar depois.... 
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
OFSwitch13NetDevice::BufferFromPacket (Ptr<Packet> packet, Mac48Address src, Mac48Address dst, int mtu, uint16_t protocol)
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

  /**
   * When the packet gets here, the Ethernet header has already been removed by
   * CsmaNetDevice::Receive () method. So, we are going to include it again to
   * properly buffer the packet. We will remove this header at TODO
   */
  AddEthernetHeaderBack (packet, src, dst, protocol);

//  uint32_t psize = packet->GetSize ();
//  uint8_t bu[psize];
//  packet->CopyData (bu, psize); 
//  for (uint32_t i = 0; i < psize; i++)
//  {
//    printf ("%02x ",bu[i]);
//  }
//  printf ("\n");

//  packet->Print (std::cout);
//  PacketMetadata::ItemIterator k = packet->BeginItem ();
//  while (k.HasNext ())
//  {
//    struct PacketMetadata::Item item = k.Next ();
//    if (item.type == PacketMetadata::Item::HEADER)
//    {
//      //Callback<ObjectBase *> constructor = item.tid.GetConstructor ();
//      //HistoryHeaderBase *header = dynamic_cast<HistoryHeaderBase *> (constructor ());
//      std::cout << item.tid << "\n";
//      if (item.tid == ns3::EthernetHeader::GetTypeId ())
//          NS_LOG_UNCOND ("Eth");
//      else
//          NS_LOG_UNCOND ("NAo achou");
//      }
//    }
//
  ofpbuf_put_uninit (buffer, packet->GetSize ());
  packet->CopyData ((uint8_t*)buffer->data, packet->GetSize ());

  uint32_t psize = packet->GetSize ();
  uint8_t bu[psize];
  packet->CopyData (bu, psize); 
  for (uint32_t i = 0; i < psize; i++)
  {
    printf ("%02x ",bu[i]);
  }
  printf ("\n");



//  TODO: Ainda estou na dúvida sobre este código aqui. Abaixo temos um parser
//  básico para pacotes, onde os cabecalhos sao criados e depois inseridos no
//  comeco do buffer... acredito que eu nao preciso disso agora.

/*  buffer->data = (char*)buffer->data + headroom + hard_header;

  int l2_length = 0, l3_length = 0, l4_length = 0;

  ArpHeader ah;
  packet->PeekHeader (ah);
  NS_LOG_DEBUG (ah);

  // Load Packet header into buffer
  // L2 header
  EthernetHeader ethHeader;
  if (packet->PeekHeader (ethHeader))
    {
      NS_LOG_DEBUG (ethHeader);
      NS_LOG_DEBUG (ethHeader.GetSource ());
      buffer->l2 = new eth_header;
      eth_header* eth_h = (eth_header*)buffer->l2;
      dst.CopyTo (eth_h->eth_dst);              // Destination Mac Address
      src.CopyTo (eth_h->eth_src);              // Source Mac Address
      eth_h->eth_type = htons (ethHeader.GetLengthType ());    // Ether Type
      NS_LOG_INFO ("Parsed EthernetHeader");
      l2_length = ETH_HEADER_LEN;
    }

  // L3 header
  if (protocol == Ipv4L3Protocol::PROT_NUMBER)
    {
      Ipv4Header ip_hd;
      if (packet->PeekHeader (ip_hd))
        {
          buffer->l3 = new ip_header;
          ip_header* ip_h = (ip_header*)buffer->l3;
          ip_h->ip_ihl_ver  = IP_IHL_VER (5, IP_VERSION);             // Version
          ip_h->ip_tos      = ip_hd.GetTos ();                        // Type of Service/Differentiated Services
          ip_h->ip_tot_len  = packet->GetSize ();                     // Total Length
          ip_h->ip_id       = ip_hd.GetIdentification ();             // Identification
          ip_h->ip_frag_off = ip_hd.GetFragmentOffset ();             // Fragment Offset
          ip_h->ip_ttl      = ip_hd.GetTtl ();                        // Time to Live
          ip_h->ip_proto    = ip_hd.GetProtocol ();                   // Protocol
          ip_h->ip_src      = htonl (ip_hd.GetSource ().Get ());      // Source Address
          ip_h->ip_dst      = htonl (ip_hd.GetDestination ().Get ()); // Destination Address
          ip_h->ip_csum     = csum (&ip_h, sizeof ip_h);              // Header Checksum
          NS_LOG_INFO ("Parsed Ipv4Header");
          l3_length = IP_HEADER_LEN;
        }
    }
  else if (protocol == ArpL3Protocol::PROT_NUMBER)
    {
      // ARP Packet; the underlying OpenFlow header isn't used to match, so this is probably superfluous.
      ArpHeader arp_hd;
      if (packet->PeekHeader (arp_hd))
        {
          buffer->l3 = new arp_eth_header;
          arp_eth_header* arp_h = (arp_eth_header*)buffer->l3;
          arp_h->ar_hrd = ARP_HRD_ETHERNET;                               // Hardware type.
          arp_h->ar_pro = ARP_PRO_IP;                                     // Protocol type.
          arp_h->ar_op = arp_hd.m_type;                                   // Opcode.
          arp_hd.GetDestinationHardwareAddress ().CopyTo (arp_h->ar_tha); // Target hardware address.
          arp_hd.GetSourceHardwareAddress ().CopyTo (arp_h->ar_sha);      // Sender hardware address.
          arp_h->ar_tpa = arp_hd.GetDestinationIpv4Address ().Get ();     // Target protocol address.
          arp_h->ar_spa = arp_hd.GetSourceIpv4Address ().Get ();          // Sender protocol address.
          arp_h->ar_hln = sizeof arp_h->ar_tha;                           // Hardware address length.
          arp_h->ar_pln = sizeof arp_h->ar_tpa;                           // Protocol address length.
          NS_LOG_INFO ("Parsed ArpHeader");
          l3_length = ARP_ETH_HEADER_LEN;
        }

    }
  else
    {
      NS_ASSERT_MSG (false, "Unknown L3 Protocol... openflow will abort!");
    }

  // L4 header
  TcpHeader tcp_hd;
  if (packet->PeekHeader (tcp_hd))
    {
      buffer->l4 = new tcp_header;
      tcp_header* tcp_h = (tcp_header*)buffer->l4;
      tcp_h->tcp_src = htons (tcp_hd.GetSourcePort ());         // Source Port
      tcp_h->tcp_dst = htons (tcp_hd.GetDestinationPort ());    // Destination Port
      tcp_h->tcp_seq = tcp_hd.GetSequenceNumber ().GetValue (); // Sequence Number
      tcp_h->tcp_ack = tcp_hd.GetAckNumber ().GetValue ();      // ACK Number
      tcp_h->tcp_ctl = TCP_FLAGS (tcp_hd.GetFlags ());          // Data Offset + Reserved + Flags
      tcp_h->tcp_winsz = tcp_hd.GetWindowSize ();               // Window Size
      tcp_h->tcp_urg = tcp_hd.GetUrgentPointer ();              // Urgent Pointer
      tcp_h->tcp_csum = csum (&tcp_h, sizeof tcp_h);            // Header Checksum
      NS_LOG_INFO ("Parsed TcpHeader");
      l4_length = TCP_HEADER_LEN;
    }
  else
    {
      UdpHeader udp_hd;
      if (packet->PeekHeader (udp_hd))
        {
          buffer->l4 = new udp_header;
          udp_header* udp_h = (udp_header*)buffer->l4;
          udp_h->udp_src = htons (udp_hd.GetSourcePort ());       // Source Port
          udp_h->udp_dst = htons (udp_hd.GetDestinationPort ());  // Destination Port
          udp_h->udp_len = htons (UDP_HEADER_LEN + packet->GetSize ());

          if (protocol == Ipv4L3Protocol::PROT_NUMBER)
            {
              ip_header* ip_h = (ip_header*)buffer->l3;
              uint32_t udp_csum = csum_add32 (0, ip_h->ip_src);
              udp_csum = csum_add32 (udp_csum, ip_h->ip_dst);
              udp_csum = csum_add16 (udp_csum, IP_TYPE_UDP << 8);
              udp_csum = csum_add16 (udp_csum, udp_h->udp_len);
              udp_csum = csum_continue (udp_csum, udp_h, sizeof udp_h);
              udp_h->udp_csum = csum_finish (csum_continue (udp_csum, buffer->data, buffer->size)); // Header Checksum
            }
          else // protocol == ArpL3Protocol::PROT_NUMBER
            {
              udp_h->udp_csum = htons (0);
            }
          NS_LOG_INFO ("Parsed UdpHeader");
          l4_length = UDP_HEADER_LEN;
        }
    }

  // Load Packet data into buffer data
  packet->CopyData ((uint8_t*)buffer->data, packet->GetSize ());

  if (buffer->l4)
    {
      ofpbuf_push (buffer, buffer->l4, l4_length);
      delete (tcp_header*)buffer->l4;
    }
  if (buffer->l3)
    {
      ofpbuf_push (buffer, buffer->l3, l3_length);
      delete (ip_header*)buffer->l3;
    }
  if (buffer->l2)
    {
      ofpbuf_push (buffer, buffer->l2, l2_length);
      delete (eth_header*)buffer->l2;
    }
*/  
  return buffer;
}

void
OFSwitch13NetDevice::PipelineProcessBuffer (uint32_t packet_uid, struct ofpbuf* buffer, ofs::Port* inPort)
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
  pkt = PacketCreate (inPort->stats->port_no, buffer, false);
  NS_LOG_DEBUG ("processing packet: " << packet_to_string (pkt));

  // o codigo abaixo é do pipeline_process_packet (m_dp->pipeline, pkt);

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
          NS_LOG_DEBUG ("found matching entry: " << ofl_structs_flow_stats_to_string (entry->stats, pkt->dp->exp));
       
          pkt->handle_std->table_miss = ((entry->stats->priority) == 0 && (entry->match->length <= 4));
         // executarssaporra (pl, entry, &next_table, &pkt);
          
          /* Packet could be destroyed by a meter instruction */
          if (!pkt)
            return;

          if (next_table == NULL) 
            {
              action_set_execute (pkt->action_set, pkt, 0xffffffffffffffff);
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


//ofl_err
//OFSwitch13NetDevice::HandleFlowMod (struct ofl_msg_flow_mod *msg)
//{
//   struct sender *sender = (struct sender*)xmalloc (sizeof (struct sender));
//   sender->remote = (struct remote*)xmalloc (sizeof (struct remote));
//   sender->remote->role = OFPCR_ROLE_MASTER;
// 
// 
// 
// //struct ofl_msg_flow_mod mensagem =
// //            {{.type = OFPT_FLOW_MOD},
// //             .cookie = 0x0000000000000000ULL,
// //             .cookie_mask = 0x0000000000000000ULL,
// //             .table_id = 0x00,
// //             .command = OFPFC_ADD,
// //             .idle_timeout = OFP_FLOW_PERMANENT,
// //             .hard_timeout = OFP_FLOW_PERMANENT,
// //             .priority = OFP_DEFAULT_PRIORITY,
// //             .buffer_id = 0xffffffff,
// //             .out_port = OFPP_ANY,
// //             .out_group = OFPG_ANY,
// //             .flags = 0x0000,
// //             .match = NULL,
// //             .instructions_num = 0,
// //             .instructions = NULL};
// //
// ////HandleFlowMod (&mensagem);
// 
// 
// 
// 
//  
// 
//   ofl_err ret = pipeline_handle_flow_mod (m_dp->pipeline, msg, sender);
// 
//   free (sender);
//   return ret;
//  ofl_err ret;
//  return ret;
//}




void 
OFSwitch13NetDevice::executarssaporra (struct pipeline *pl, struct flow_entry *entry, struct flow_table **next_table, struct packet **pkt)
{


// size_t i;
//     struct ofl_instruction_header *inst;
// 
//     for (i=0; i < entry->stats->instructions_num; i++) {
//         /*Packet was dropped by some instruction or action*/
// 
//         if(!(*pkt)){
//             return;
//         }
// 
//         inst = entry->stats->instructions[i];
//         switch (inst->type) {
//             case OFPIT_GOTO_TABLE: {
//                 struct ofl_instruction_goto_table *gi = (struct ofl_instruction_goto_table *)inst;
// 
//                 *next_table = pl->tables[gi->table_id];
//                 break;
//             }
//             case OFPIT_WRITE_METADATA: {
//                 struct ofl_instruction_write_metadata *wi = (struct ofl_instruction_write_metadata *)inst;
//                 struct  ofl_match_tlv *f;
// 
//                 /* NOTE: Hackish solution. If packet had multiple handles, metadata
//                  *       should be updated in all. */
//                 packet_handle_std_validate((*pkt)->handle_std);
//                 /* Search field on the description of the packet. */
//                 HMAP_FOR_EACH_WITH_HASH(f, struct ofl_match_tlv,
//                     hmap_node, hash_int(OXM_OF_METADATA,0), &(*pkt)->handle_std->match.match_fields){
//                     uint64_t *metadata = (uint64_t*) f->value;
//                     *metadata = (*metadata & ~wi->metadata_mask) | (wi->metadata & wi->metadata_mask);
//             //        VLOG_DBG_RL(LOG_MODULE, &rl, "Executing write metadata: %"PRIu64"", *metadata);
//                 }
//                 break;
//             }
//             case OFPIT_WRITE_ACTIONS: {
//                 struct ofl_instruction_actions *wa = (struct ofl_instruction_actions *)inst;
//                 action_set_write_actions((*pkt)->action_set, wa->actions_num, wa->actions);
//                 break;
//             }
//             case OFPIT_APPLY_ACTIONS: {
//                 struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)inst;
//                 dp_execute_action_list((*pkt), ia->actions_num, ia->actions, entry->stats->cookie);
//                 break;
//             }
//             case OFPIT_CLEAR_ACTIONS: {
//                 action_set_clear_actions((*pkt)->action_set);
//                 break;
//             }
//             case OFPIT_METER: {
//             	struct ofl_instruction_meter *im = (struct ofl_instruction_meter *)inst;
//                 meter_table_apply(pl->dp->meters, pkt , im->meter_id);
//                 break;
//             }
//             case OFPIT_EXPERIMENTER: {
//                 dp_exp_inst((*pkt), (struct ofl_instruction_experimenter *)inst);
//                 break;
//             }
//         }
//     }

}





struct flow_table *
OFSwitch13NetDevice::FlowTableCreate (uint8_t table_id)
{
  struct flow_table *table;
  struct ds string = DS_EMPTY_INITIALIZER;

  ds_put_format (&string, "table_%u", table_id);

  table = (struct flow_table*)xmalloc (sizeof (struct flow_table));
  //table->dp = dp;
  table->disabled = 0;
  
  /*Init table stats */
  table->stats = (struct ofl_table_stats*)xmalloc (sizeof (struct ofl_table_stats));
  table->stats->table_id      = table_id;
  table->stats->active_count  = 0;
  table->stats->lookup_count  = 0;
  table->stats->matched_count = 0;

  /* Init Table features */
  table->features = (struct ofl_table_features*)xmalloc (sizeof (struct ofl_table_features));
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

struct packet *
OFSwitch13NetDevice::PacketCreate (uint32_t in_port, struct ofpbuf *buf, bool packet_out) 
{
  struct packet *pkt;

  pkt = (struct packet*)xmalloc (sizeof (struct packet));

  pkt->dp         = NULL;
  pkt->buffer     = buf;
  pkt->in_port    = in_port;
  pkt->action_set = (struct action_set*) xmalloc (sizeof (struct action_set));
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
OFSwitch13NetDevice::AddEthernetHeaderBack (Ptr<Packet> p, Mac48Address source, 
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
