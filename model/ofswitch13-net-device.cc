/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2015 University of Campinas (Unicamp)
 *
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

#define NS_LOG_APPEND_CONTEXT \
  if (m_dpId) { std::clog << "[dp " << m_dpId << "] "; }

#include "ofswitch13-net-device.h"
#include "ofswitch13-interface.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13NetDevice");
NS_OBJECT_ENSURE_REGISTERED (OFSwitch13NetDevice);

// Initializing OFSwitch13NetDevice static members
uint64_t OFSwitch13NetDevice::m_globalDpId = 0;
uint64_t OFSwitch13NetDevice::m_globalPktId = 0;
OFSwitch13NetDevice::DpIdDevMap_t OFSwitch13NetDevice::m_globalSwitchMap;

/********** Public methods **********/
TypeId
OFSwitch13NetDevice::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OFSwitch13NetDevice")
    .SetParent<NetDevice> ()
    .SetGroupName ("OFSwitch13")
    .AddConstructor<OFSwitch13NetDevice> ()
    .AddAttribute ("DatapathId",
                   "The identification of the OFSwitch13NetDevice/Datapath.",
                   TypeId::ATTR_GET,
                   UintegerValue (0),
                   MakeUintegerAccessor (&OFSwitch13NetDevice::m_dpId),
                   MakeUintegerChecker<uint64_t> ())
    .AddAttribute ("TCAMDelay",
                   "Average time to perform a TCAM operation "
                   "(Default: standard TCAM on a NetFPGA).",
                   TimeValue (NanoSeconds (30)),
                   MakeTimeAccessor (&OFSwitch13NetDevice::m_tcamDelay),
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

    // Meter band packet drop trace source
    .AddTraceSource ("MeterDrop",
                     "Trace source indicating a packet dropped by meter band",
                     MakeTraceSourceAccessor (&OFSwitch13NetDevice::m_meterDropTrace),
                     "ns3::Packet::TracedCallback")
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
  OFSwitch13NetDevice::RegisterDatapath (m_dpId, Ptr<OFSwitch13NetDevice> (this));
  Simulator::Schedule (m_timeout, &OFSwitch13NetDevice::DatapathTimeout,
                       this, m_datapath);
}

OFSwitch13NetDevice::~OFSwitch13NetDevice ()
{
  NS_LOG_FUNCTION (this);
}

Ptr<OFSwitch13Port>
OFSwitch13NetDevice::AddSwitchPort (Ptr<NetDevice> portDevice)
{
  NS_LOG_FUNCTION (this << portDevice);
  NS_LOG_INFO ("Adding port addr " << portDevice->GetAddress ());

  if (GetNSwitchPorts () >= DP_MAX_PORTS)
    {
      NS_LOG_ERROR ("No more ports allowed.");
      return 0;
    }

  Ptr<CsmaNetDevice> csmaPortDevice = portDevice->GetObject<CsmaNetDevice> ();
  if (!csmaPortDevice)
    {
      NS_FATAL_ERROR ("NetDevice must be of CsmaNetDevice type.");
    }

  // Create the OpenFlow port for this device
  Ptr<OFSwitch13Port> ofPort;
  ofPort = CreateObject<OFSwitch13Port> (m_datapath, csmaPortDevice, this);

  // Save pointer for further use
  std::pair<uint32_t, Ptr<OFSwitch13Port> > entry (ofPort->GetPortNo (), ofPort);
  m_portsByNo.insert (entry);

  return ofPort;
}

void
OFSwitch13NetDevice::ReceiveFromSwitchPort (Ptr<Packet> packet, uint32_t portNo)
{
  NS_LOG_FUNCTION (this << packet);

  Simulator::Schedule (m_pipeDelay, &OFSwitch13NetDevice::SendToPipeline,
                       this, packet, portNo);
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
OFSwitch13NetDevice::GetNumberFlowEntries (void) const
{
  NS_LOG_FUNCTION (this);
  NS_ASSERT_MSG (m_datapath, "No datapath defined yet.");

  uint32_t entries = 0;
  for (size_t i = 0; i < PIPELINE_TABLES; i++)
    {
      entries += GetNumberFlowEntries (i);
    }
  return entries;
}

uint32_t
OFSwitch13NetDevice::GetNumberFlowEntries (size_t tid) const
{
  NS_ASSERT_MSG (m_datapath, "No datapath defined yet.");

  uint32_t entries = 0;
  struct flow_table *table = m_datapath->pipeline->tables[tid];
  if (!(table->disabled))
    {
      entries = table->stats->active_count;
    }
  return entries;
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

Ptr<OFSwitch13Queue>
OFSwitch13NetDevice::GetOutputQueue (uint32_t portNo)
{
  NS_LOG_FUNCTION (this << portNo);
  return GetOFSwitch13Port (portNo)->GetOutputQueue ();
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

// This is a OpenFlow device, so we really don't need any kind of address
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

// This is a OpenFlow device, so we don't send packets from here. Instead, we
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

// This is a OpenFlow device, so we don't expect packets addressed to this
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

// ofsoftswitch13 overriding and callback functions.
int
OFSwitch13NetDevice::SendOpenflowBufferToRemote (ofpbuf *buffer, remote *ctrl)
{
  Ptr<OFSwitch13NetDevice> dev =
    OFSwitch13NetDevice::GetDatapathDevice (ctrl->dp->id);

  // FIXME No support for multiple controllers nor auxiliary connections by now.
  // So, just ignoring remote information and sending to our single socket.
  Ptr<Packet> packet = ofs::PacketFromBuffer (buffer);
  return dev->SendToController (packet);
}

void
OFSwitch13NetDevice::DpActionsOutputPort (struct packet *pkt, uint32_t outPort,
                                          uint32_t outQueue, uint16_t maxLen,
                                          uint64_t cookie)
{
  Ptr<OFSwitch13NetDevice> dev =
    OFSwitch13NetDevice::GetDatapathDevice (pkt->dp->id);

  switch (outPort)
    {
    case (OFPP_TABLE):
      {
        if (pkt->packet_out)
          {
            // Makes sure packet cannot be resubmit to pipeline again setting
            // packet_out to false. Also, pipeline_process_packet takes
            // ownership of the packet, we need a copy.
            struct packet *pkt_copy = packet_clone (pkt);
            pkt_copy->packet_out = false;
            pipeline_process_packet (pkt_copy->dp->pipeline, pkt_copy);
          }
        break;
      }
    case (OFPP_IN_PORT):
      {
        dev->SendToSwitchPort (pkt, pkt->in_port, 0);
        break;
      }
    case (OFPP_CONTROLLER):
      {
        ofl_msg_packet_in msg;
        msg.header.type = OFPT_PACKET_IN;
        msg.total_len = pkt->buffer->size;
        msg.reason = pkt->handle_std->table_miss ? OFPR_NO_MATCH : OFPR_ACTION;
        msg.table_id = pkt->table_id;
        msg.data = (uint8_t*)pkt->buffer->data;
        msg.cookie = cookie;

        // Even with miss_send_len == OFPCML_NO_BUFFER, save the packet into
        // buffer to avoid loosing ns-3 packet id. This is not full compliant
        // with OpenFlow specification, but works very well here ;)
        dp_buffers_save (pkt->dp->buffers, pkt);
        msg.buffer_id = pkt->buffer_id;
        msg.data_length = MIN (maxLen, pkt->buffer->size);

        if (!pkt->handle_std->valid)
          {
            packet_handle_std_validate (pkt->handle_std);
          }
        msg.match = (ofl_match_header*) &pkt->handle_std->match;
        dp_send_message (pkt->dp, (ofl_msg_header *)&msg, 0);
        break;
      }
    case (OFPP_FLOOD):
    case (OFPP_ALL):
      {
        sw_port *p;
        LIST_FOR_EACH (p, struct sw_port, node, &pkt->dp->port_list)
        {
          if ((p->stats->port_no == pkt->in_port)
              || (outPort == OFPP_FLOOD && p->conf->config & OFPPC_NO_FWD))
            {
              continue;
            }
          dev->SendToSwitchPort (pkt, p->stats->port_no, 0);
        }
        break;
      }
    case (OFPP_NORMAL):
    case (OFPP_LOCAL):
    default:
      {
        if (pkt->in_port != outPort)
          {
            // Outputting packet on port outPort
            dev->SendToSwitchPort (pkt, outPort, outQueue);
          }
      }
    }
}

void
OFSwitch13NetDevice::MeterDropCallback (struct packet *pkt)
{
  Ptr<OFSwitch13NetDevice> dev =
    OFSwitch13NetDevice::GetDatapathDevice (pkt->dp->id);
  dev->NotifyPacketDropped (pkt);
}

void
OFSwitch13NetDevice::PacketCloneCallback (struct packet *pkt,
                                          struct packet *clone)
{
  Ptr<OFSwitch13NetDevice> dev =
    OFSwitch13NetDevice::GetDatapathDevice (pkt->dp->id);
  dev->NotifyPacketCloned (pkt, clone);
}

void
OFSwitch13NetDevice::PacketDestroyCallback (struct packet *pkt)
{
  Ptr<OFSwitch13NetDevice> dev =
    OFSwitch13NetDevice::GetDatapathDevice (pkt->dp->id);
  dev->NotifyPacketDestroyed (pkt);
}

void
OFSwitch13NetDevice::BufferSaveCallback (struct packet *pkt, time_t timeout)
{
  Ptr<OFSwitch13NetDevice> dev =
    OFSwitch13NetDevice::GetDatapathDevice (pkt->dp->id);
  dev->BufferPacketSave (pkt->ns3_uid, timeout);
}

void
OFSwitch13NetDevice::BufferRetrieveCallback (struct packet *pkt)
{
  Ptr<OFSwitch13NetDevice> dev =
    OFSwitch13NetDevice::GetDatapathDevice (pkt->dp->id);
  dev->BufferPacketRetrieve (pkt->ns3_uid);
}


/********** Private methods **********/
void
OFSwitch13NetDevice::DoDispose ()
{
  NS_LOG_FUNCTION (this);

  OFSwitch13NetDevice::UnregisterDatapath (m_dpId);

  m_node = 0;
  m_ctrlSocket = 0;
  m_portsByNo.clear ();

  pipeline_destroy (m_datapath->pipeline);
  group_table_destroy (m_datapath->groups);
  meter_table_destroy (m_datapath->meters);
  free (m_datapath);

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
  dp->max_queues = OFSwitch13Queue::GetMaxQueues ();
  dp->exp = 0;

  dp->config.flags = OFPC_FRAG_NORMAL; // IP fragments with no special handling
  dp->config.miss_send_len = OFP_DEFAULT_MISS_SEND_LEN; // 128 bytes

  // ofsoftswitch13 callbacks
  dp->pkt_clone_cb = &OFSwitch13NetDevice::PacketCloneCallback;
  dp->pkt_destroy_cb = &OFSwitch13NetDevice::PacketDestroyCallback;
  dp->buff_save_cb = &OFSwitch13NetDevice::BufferSaveCallback;
  dp->buff_retrieve_cb = &OFSwitch13NetDevice::BufferRetrieveCallback;
  dp->meter_drop_cb = &OFSwitch13NetDevice::MeterDropCallback;

  return dp;
}

void
OFSwitch13NetDevice::DatapathTimeout (datapath* dp)
{
  NS_LOG_FUNCTION (this);

  meter_table_add_tokens (dp->meters);
  pipeline_timeout (dp->pipeline);

  // Check for changes in links (port) status
  PortNoMap_t::iterator it;
  for (it = m_portsByNo.begin (); it != m_portsByNo.end (); it++)
    {
      it->second->PortUpdateState ();
    }

  //
  // To provide a more realistic OpenFlow switch model, specially with respect
  // to flow table search time, we are considering that in real OpenFlow
  // implementations, packet classification can use sophisticated search
  // algorithms, as the HyperSplit (DOI 10.1109/FPT.2010.5681492). As most of
  // theses algorithms classifies the packet based on binary search trees, we
  // are estimating the pipeline average time to a K * log (n), where k is the
  // m_tcamDelay set to the time for a TCAM operation in a NetFPGA hardware,
  // and n is the current number of entries in flow tables. 
  //
  m_pipeDelay = m_tcamDelay * (int64_t)ceil (log2 (GetNumberFlowEntries ()));

  dp->last_timeout = time_now ();
  Simulator::Schedule (m_timeout, &OFSwitch13NetDevice::DatapathTimeout, this, dp);
}

Ptr<OFSwitch13Port>
OFSwitch13NetDevice::GetOFSwitch13Port (uint32_t no)
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

bool
OFSwitch13NetDevice::SendToSwitchPort (struct packet *pkt, uint32_t portNo,
                                       uint32_t queueNo)
{
  NS_LOG_FUNCTION (this << pkt->ns3_uid << portNo);

  Ptr<OFSwitch13Port> port = GetOFSwitch13Port (portNo);
  if (!port)
    {
      NS_LOG_ERROR ("can't forward to invalid port.");
      return false;
    }

  // When a packet is sent to OpenFlow pipeline, we keep track of its original
  // ns3::Packet using the PipelinePacket structure. When the packet is
  // processed by the pipeline with no internal changes, we forward the
  // original ns3::Packet to the specified output port.  When internal changes
  // are necessary, we need to create a new packet with the modified content
  // and copy all packet tags to this new one. This approach is more expensive
  // than the previous one, but is far more simple than identifying which
  // changes were performed in the packet to modify the original ns3::Packet.
  Ptr<Packet> packet;
  if (m_pktPipe.IsValid ())
    {
      NS_ASSERT_MSG (m_pktPipe.HasId (pkt->ns3_uid), "Invalid packet ID.");
      if (pkt->changes)
        {
          // The original ns-3 packet was modified by OpenFlow switch.
          // Create a new packet with modified data and copy tags from the
          // original packet.
          NS_LOG_DEBUG ("Packet modified by OpenFlow switch.");
          packet = ofs::PacketFromBuffer (pkt->buffer);
          OFSwitch13NetDevice::CopyTags (m_pktPipe.GetPacket (), packet);
        }
      else
        {
          // Using the original ns-3 packet.
          packet = m_pktPipe.GetPacket ();
        }
    }
  else
    {
      // This is a new packet (probably created by the controller).
      NS_LOG_DEBUG ("Creating new ns-3 packet from openflow buffer.");
      packet = ofs::PacketFromBuffer (pkt->buffer);
    }

  // Send the packet to switch port.
  return port->Send (packet, queueNo);
}

void
OFSwitch13NetDevice::SendToPipeline (Ptr<Packet> packet, uint32_t portNo)
{
  NS_LOG_FUNCTION (this << packet);
  NS_ASSERT_MSG (!m_pktPipe.IsValid (), "Another packet in pipeline.");

  // Creating the internal OpenFlow packet structure from ns-3 packet
  // Allocate buffer with some extra space for OpenFlow packet modifications.
  uint32_t headRoom = 128 + 2;
  uint32_t bodyRoom = packet->GetSize () + VLAN_ETH_HEADER_LEN;
  ofpbuf *buffer = ofs::BufferFromPacket (packet, bodyRoom, headRoom);
  struct packet *pkt = packet_create (m_datapath, portNo, buffer, false);

  // Save the ns-3 packet
  pkt->ns3_uid = OFSwitch13NetDevice::GetNewPacketId ();
  m_pktPipe.SetPacket (pkt->ns3_uid, packet);

  // Send packet to ofsoftswitch13 pipeline
  pipeline_process_packet (m_datapath->pipeline, pkt);
}

int
OFSwitch13NetDevice::SendToController (Ptr<Packet> packet)
{
  if (!m_ctrlSocket)
    {
      NS_LOG_WARN ("No controller connection. Discarding message... ");
      return -1;
    }

  // Check for available space in TCP buffer before sending the packet
  if (m_ctrlSocket->GetTxAvailable () < packet->GetSize ())
    {
      NS_LOG_ERROR ("Unavailable space to send OpenFlow message now.");
      Simulator::Schedule (m_timeout, &OFSwitch13NetDevice::SendToController,
                           this, packet);
    }

  uint32_t bytes = m_ctrlSocket->Send (packet);
  if (bytes != packet->GetSize ())
    {
      NS_LOG_WARN ("There was an error sending the message!");
    }
  return (int)!bytes;
}

void
OFSwitch13NetDevice::ReceiveFromController (Ptr<Socket> socket)
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
          uint16_t port = InetSocketAddress::ConvertFrom (from).GetPort ();
          NS_LOG_LOGIC ("At time " << Simulator::Now ().GetSeconds () <<
                        "s the OpenFlow switch " << GetDatapathId () <<
                        " received " << pendingPacket->GetSize () <<
                        " bytes from controller " << ipv4 <<
                        " socket " << socket <<
                        " port " << port);

          ofl_msg_header *msg;
          ofl_err error;

          // FIXME No support for multiple controllers by now.
          // Gets the remote structure for this controller connection.
          // As we currently support a single controller, it must be the first.
          struct sender ctrl;
          ctrl.remote = CONTAINER_OF (list_front (&m_datapath->remotes),
                                      remote, node);
          ctrl.conn_id = 0; // FIXME No support for auxiliary connections.

          // Get the OpenFlow buffer, unpack the message and send to handler
          ofpbuf *buffer = ofs::BufferFromPacket (pendingPacket,
                                                  pendingPacket->GetSize ());
          error = ofl_msg_unpack ((uint8_t*)buffer->data, buffer->size, &msg,
                                  &ctrl.xid, m_datapath->exp);
          if (!error)
            {
              char *msg_str = ofl_msg_to_string (msg, m_datapath->exp);
              NS_LOG_DEBUG ("Rx from ctrl: " << msg_str);
              free (msg_str);

              error = handle_control_msg (m_datapath, msg, &ctrl);
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
              dp_send_message (m_datapath, (ofl_msg_header*)&err, &ctrl);
            }
          ofpbuf_delete (buffer);
        }
      pendingPacket = 0;
      pendingBytes = 0;

      // Repeat until socket buffer gets empty
    }
  while (socket->GetRxAvailable ());
}

void
OFSwitch13NetDevice::SocketCtrlSucceeded (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);

  NS_LOG_LOGIC ("Controller accepted connection request!");
  socket->SetRecvCallback (
    MakeCallback (&OFSwitch13NetDevice::ReceiveFromController, this));

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
OFSwitch13NetDevice::NotifyPacketCloned (struct packet *pkt,
                                         struct packet *cloned)
{
  NS_LOG_FUNCTION (this << pkt->ns3_uid);


  // Assigning a new unique ID for this cloned packet.
  cloned->ns3_uid = OFSwitch13NetDevice::GetNewPacketId ();
  m_pktPipe.NewCopy (cloned->ns3_uid);
}

void
OFSwitch13NetDevice::NotifyPacketDestroyed (struct packet *pkt)
{
  NS_LOG_FUNCTION (this << pkt->ns3_uid);

  if (m_pktPipe.IsValid () && m_pktPipe.HasId (pkt->ns3_uid))
    {
      // This is the packet current under pipeline
      bool valid = m_pktPipe.DelCopy (pkt->ns3_uid);
      if (!valid)
        {
          NS_LOG_DEBUG ("Packet " << pkt->ns3_uid <<
                        " done at switch " << GetDatapathId ());
        }
    }
  else
    {
      // This dropped packet is not the one current under pipeline. It must be
      // an old packet that was previously saved into buffer and will be
      // deleted now, freeing up space for a new packet at same buffer index
      // (that's how the ofsoftswitch13 handles the buffer). So, we are going
      // to remove this packet from our buffer list, if it still exists there.
      BufferPacketDelete (pkt->ns3_uid);
    }
}

void
OFSwitch13NetDevice::NotifyPacketDropped (struct packet *pkt)
{
  NS_LOG_FUNCTION (this << pkt->ns3_uid);

  NS_ASSERT_MSG (m_pktPipe.HasId (pkt->ns3_uid), "Invalid packet ID.");
  NS_LOG_DEBUG ("OpenFlow meter band dropped packet " << pkt->ns3_uid);

  // Fire drop trace source
  m_meterDropTrace (m_pktPipe.GetPacket ());
}

void
OFSwitch13NetDevice::BufferPacketSave (uint64_t packetId, time_t timeout)
{
  NS_LOG_FUNCTION (this << packetId);

  NS_ASSERT_MSG (m_pktPipe.HasId (packetId), "Invalid packet ID.");

  // Remove from pipeline and save into buffer map
  std::pair <uint64_t, Ptr<Packet> > entry (packetId, m_pktPipe.GetPacket ());
  std::pair <IdPacketMap_t::iterator, bool> ret;
  ret = m_pktsBuffer.insert (entry);
  if (ret.second == false)
    {
      NS_LOG_WARN ("Packet " << packetId << " already in switch "
                             << GetDatapathId () << " buffer.");
    }
  m_pktPipe.DelCopy (packetId);

  // Scheduling the buffer remove for expired packet. Since packet timeout
  // resolution is expressed in seconds, let's double it to avoid rounding
  // conflicts.
  Simulator::Schedule (Time::FromInteger (2 * timeout, Time::S),
                       &OFSwitch13NetDevice::BufferPacketDelete,
                       this, packetId);
}

void
OFSwitch13NetDevice::BufferPacketRetrieve (uint64_t packetId)
{
  NS_LOG_FUNCTION (this << packetId);

  NS_ASSERT_MSG (!m_pktPipe.IsValid (), "Another packet in pipeline.");

  // Remove from buffer map and save back into pipeline
  IdPacketMap_t::iterator it = m_pktsBuffer.find (packetId);
  NS_ASSERT_MSG (it != m_pktsBuffer.end (), "Packet not found in buffer.");
  m_pktPipe.SetPacket (it->first, it->second);
  m_pktsBuffer.erase (it);
}

void
OFSwitch13NetDevice::BufferPacketDelete (uint64_t packetId)
{
  NS_LOG_FUNCTION (this << packetId);

  // Delete from buffer map
  IdPacketMap_t::iterator it = m_pktsBuffer.find (packetId);
  if (it != m_pktsBuffer.end ())
    {
      m_pktsBuffer.erase (it);
    }
}

uint64_t
OFSwitch13NetDevice::GetNewPacketId ()
{
  return ++m_globalPktId;
}

bool
OFSwitch13NetDevice::CopyTags (Ptr<const Packet> srcPkt,
                               Ptr<const Packet> dstPkt)
{
  // Copy packet tags
  PacketTagIterator pktIt = srcPkt->GetPacketTagIterator ();
  while (pktIt.HasNext ())
    {
      PacketTagIterator::Item item = pktIt.Next ();
      Callback<ObjectBase *> constructor = item.GetTypeId ().GetConstructor ();
      Tag *tag = dynamic_cast <Tag *> (constructor ());
      item.GetTag (*tag);
      dstPkt->AddPacketTag (*tag);
      delete tag;
    }

  // Copy byte tags
  ByteTagIterator bytIt = srcPkt->GetByteTagIterator ();
  while (bytIt.HasNext ())
    {
      ByteTagIterator::Item item = bytIt.Next ();
      Callback<ObjectBase *> constructor = item.GetTypeId ().GetConstructor ();
      Tag *tag = dynamic_cast<Tag *> (constructor ());
      item.GetTag (*tag);
      dstPkt->AddByteTag (*tag);
      delete tag;
    }

  return true;
}

void
OFSwitch13NetDevice::RegisterDatapath (uint64_t id, Ptr<OFSwitch13NetDevice> dev)
{
  std::pair<uint64_t, Ptr<OFSwitch13NetDevice> > entry (id, dev);
  std::pair<DpIdDevMap_t::iterator, bool> ret;
  ret = OFSwitch13NetDevice::m_globalSwitchMap.insert (entry);
  if (ret.second == false)
    {
      NS_FATAL_ERROR ("Error inserting datapath device into global map.");
    }
}

void
OFSwitch13NetDevice::UnregisterDatapath (uint64_t id)
{
  DpIdDevMap_t::iterator it;
  it = OFSwitch13NetDevice::m_globalSwitchMap.find (id);
  if (it != OFSwitch13NetDevice::m_globalSwitchMap.end ())
    {
      OFSwitch13NetDevice::m_globalSwitchMap.erase (it);
    }
  else
    {
      NS_FATAL_ERROR ("Error removing datapath device from global map.");
    }
}

Ptr<OFSwitch13NetDevice>
OFSwitch13NetDevice::GetDatapathDevice (uint64_t id)
{
  DpIdDevMap_t::iterator it;
  it = OFSwitch13NetDevice::m_globalSwitchMap.find (id);
  if (it != OFSwitch13NetDevice::m_globalSwitchMap.end ())
    {
      return it->second;
    }
  else
    {
      NS_FATAL_ERROR ("Error retrieving datapath device from global map.");
      return 0;
    }
}

OFSwitch13NetDevice::PipelinePacket::PipelinePacket ()
  : m_valid (false),
    m_packet (0)
{
}

void
OFSwitch13NetDevice::PipelinePacket::SetPacket (uint64_t id,
                                                Ptr<Packet> packet)
{
  NS_ASSERT_MSG (id && packet, "Invalid packet metadata values.");
  m_valid = true;
  m_packet = packet;
  m_ids.push_back (id);
}

Ptr<Packet>
OFSwitch13NetDevice::PipelinePacket::GetPacket (void) const
{
  NS_ASSERT_MSG (IsValid (), "Invalid packet metadata.");
  return m_packet;
}

void
OFSwitch13NetDevice::PipelinePacket::Invalidate (void)
{
  m_valid = false;
  m_packet = 0;
  m_ids.clear ();
}

bool
OFSwitch13NetDevice::PipelinePacket::IsValid (void) const
{
  return m_valid;
}

void
OFSwitch13NetDevice::PipelinePacket::NewCopy (uint64_t id)
{
  NS_ASSERT_MSG (m_valid, "Invalid packet metadata.");
  m_ids.push_back (id);
}

bool
OFSwitch13NetDevice::PipelinePacket::DelCopy (uint64_t id)
{
  NS_ASSERT_MSG (m_valid, "Invalid packet metadata.");

  std::vector<uint64_t>::iterator it;
  for (it = m_ids.begin (); it != m_ids.end (); it++)
    {
      if (*it == id)
        {
          m_ids.erase (it);
          break;
        }
    }
  if (m_ids.size () == 0)
    {
      Invalidate ();
    }
  return m_valid;
}

bool
OFSwitch13NetDevice::PipelinePacket::HasId (uint64_t id)
{
  NS_ASSERT_MSG (m_valid, "Invalid packet metadata.");

  std::vector<uint64_t>::iterator it;
  for (it = m_ids.begin (); it != m_ids.end (); it++)
    {
      if (*it == id)
        {
          return true;
        }
    }
  return false;
}

} // namespace ns3
