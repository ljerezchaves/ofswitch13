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

#include <ns3/object-vector.h>
#include "ofswitch13-device.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Device");
NS_OBJECT_ENSURE_REGISTERED (OFSwitch13Device);

// Initializing OFSwitch13Device static members.
uint64_t OFSwitch13Device::m_globalDpId = 0;
uint64_t OFSwitch13Device::m_globalPktId = 0;
OFSwitch13Device::DpIdDevMap_t OFSwitch13Device::m_globalSwitchMap;

/********** Public methods **********/
TypeId
OFSwitch13Device::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OFSwitch13Device")
    .SetParent<Object> ()
    .SetGroupName ("OFSwitch13")
    .AddConstructor<OFSwitch13Device> ()
    .AddAttribute ("DatapathId",
                   "The unique identification of this OpenFlow switch.",
                   TypeId::ATTR_GET,
                   UintegerValue (0),
                   MakeUintegerAccessor (&OFSwitch13Device::m_dpId),
                   MakeUintegerChecker<uint64_t> ())
    .AddAttribute ("FlowTableSize",
                   "The maximum number of entries allowed on each flow table.",
                   UintegerValue (FLOW_TABLE_MAX_ENTRIES),
                   MakeUintegerAccessor (&OFSwitch13Device::SetFlowTableSize,
                                         &OFSwitch13Device::GetFlowTableSize),
                   MakeUintegerChecker<uint32_t> (0, FLOW_TABLE_MAX_ENTRIES))
    .AddAttribute ("GroupTableSize",
                   "The maximum number of entries allowed on group table.",
                   UintegerValue (GROUP_TABLE_MAX_ENTRIES),
                   MakeUintegerAccessor (&OFSwitch13Device::SetGroupTableSize,
                                         &OFSwitch13Device::GetGroupTableSize),
                   MakeUintegerChecker<uint32_t> (0, GROUP_TABLE_MAX_ENTRIES))
    .AddAttribute ("MeterTableSize",
                   "The maximum number of entries allowed on meter table.",
                   UintegerValue (METER_TABLE_MAX_ENTRIES),
                   MakeUintegerAccessor (&OFSwitch13Device::SetMeterTableSize,
                                         &OFSwitch13Device::GetMeterTableSize),
                   MakeUintegerChecker<uint32_t> (0, METER_TABLE_MAX_ENTRIES))
    .AddAttribute ("PipelineCapacity",
                   "Pipeline processing capacity in terms of throughput.",
                   DataRateValue (DataRate ("100Gb/s")),
                   MakeDataRateAccessor (&OFSwitch13Device::m_pipeCapacity),
                   MakeDataRateChecker ())
    .AddAttribute ("PortList",
                   "The list of ports associated to this switch.",
                   ObjectVectorValue (),
                   MakeObjectVectorAccessor (&OFSwitch13Device::m_ports),
                   MakeObjectVectorChecker<OFSwitch13Port> ())
    .AddAttribute ("TcamDelay",
                   "Average time to perform a TCAM operation in pipeline.",
                   TimeValue (MicroSeconds (20)),
                   MakeTimeAccessor (&OFSwitch13Device::m_tcamDelay),
                   MakeTimeChecker ())
    .AddAttribute ("TimeoutInterval",
                   "The interval between timeout operations on datapath.",
                   TimeValue (MilliSeconds (100)),
                   MakeTimeAccessor (&OFSwitch13Device::m_timeout),
                   MakeTimeChecker ())

    .AddTraceSource ("BufferExpire",
                     "Trace source indicating an expired packet in buffer.",
                     MakeTraceSourceAccessor (
                       &OFSwitch13Device::m_bufferExpireTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("BufferRetrieve",
                     "Trace source indicating a packet retrieved from buffer.",
                     MakeTraceSourceAccessor (
                       &OFSwitch13Device::m_bufferRetrieveTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("BufferSave",
                     "Trace source indicating a packet saved into buffer.",
                     MakeTraceSourceAccessor (
                       &OFSwitch13Device::m_bufferSaveTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("LoadDrop",
                     "Trace source indicating a packet dropped by pipe load.",
                     MakeTraceSourceAccessor (
                       &OFSwitch13Device::m_loadDropTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("MeterDrop",
                     "Trace source indicating a packet dropped by meter band.",
                     MakeTraceSourceAccessor (
                       &OFSwitch13Device::m_meterDropTrace),
                     "ns3::OFSwitch13Device::MeterDropTracedCallback")
    .AddTraceSource ("PipelinePacket",
                     "Trace source indicating a packet sent to pipeline.",
                     MakeTraceSourceAccessor (
                       &OFSwitch13Device::m_pipePacketTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("DatapathTimeout",
                     "Trace source indicating a datapath timeout operation.",
                     MakeTraceSourceAccessor (
                       &OFSwitch13Device::m_datapathTimeoutTrace),
                     "ns3::OFSwitch13Device::DeviceTracedCallback")

    .AddTraceSource ("BufferUsage",
                     "Traced value indicating the buffer space usage "
                     "(periodically updated on datapath timeout operation).",
                     MakeTraceSourceAccessor (
                       &OFSwitch13Device::m_bufferUsage),
                     "ns3::TracedValueCallback::Double")
    .AddTraceSource ("FlowEntries",
                     "Traced value indicating the total number of flow entries"
                     " (periodically updated on datapath timeout operation).",
                     MakeTraceSourceAccessor (
                       &OFSwitch13Device::m_flowEntries),
                     "ns3::TracedValueCallback::Uint32")
    .AddTraceSource ("GroupEntries",
                     "Traced value indicating the number of group entries "
                     "(periodically updated on datapath timeout operation).",
                     MakeTraceSourceAccessor (
                       &OFSwitch13Device::m_groupEntries),
                     "ns3::TracedValueCallback::Uint32")
    .AddTraceSource ("MeterEntries",
                     "Traced value indicating the number of meter entries "
                     "(periodically updated on datapath timeout operation).",
                     MakeTraceSourceAccessor (
                       &OFSwitch13Device::m_meterEntries),
                     "ns3::TracedValueCallback::Uint32")
    .AddTraceSource ("PipelineDelay",
                     "Traced value indicating the avg pipeline lookup delay "
                     "(periodically updated on datapath timeout operation).",
                     MakeTraceSourceAccessor (
                       &OFSwitch13Device::m_pipeDelay),
                     "ns3::TracedValueCallback::Time")
    .AddTraceSource ("PipelineLoad",
                     "Traced value indicating the avg pipeline load "
                     "(periodically updated on datapath timeout operation).",
                     MakeTraceSourceAccessor (
                       &OFSwitch13Device::m_pipeLoad),
                     "ns3::TracedValueCallback::DataRate")
  ;
  return tid;
}

OFSwitch13Device::OFSwitch13Device ()
  : m_pipeConsumed (0),
    m_cFlowMod (0),
    m_cGroupMod (0),
    m_cMeterMod (0),
    m_cPacketIn (0),
    m_cPacketOut (0)
{
  NS_LOG_FUNCTION (this);

  NS_LOG_INFO ("OpenFlow version " << OFP_VERSION);
  m_dpId = ++m_globalDpId;
  m_datapath = DatapathNew ();
  OFSwitch13Device::RegisterDatapath (m_dpId, Ptr<OFSwitch13Device> (this));
}

OFSwitch13Device::~OFSwitch13Device ()
{
  NS_LOG_FUNCTION (this);
}

double
OFSwitch13Device::GetBufferUsage (void) const
{
  return m_bufferUsage;
}

uint64_t
OFSwitch13Device::GetDatapathId (void) const
{
  return m_dpId;
}

uint32_t
OFSwitch13Device::GetFlowEntries (void) const
{
  return m_flowEntries;
}

uint32_t
OFSwitch13Device::GetFlowEntries (size_t tableId) const
{
  NS_ASSERT_MSG (m_datapath, "No datapath defined yet.");
  uint32_t entries = 0;
  struct flow_table *table = m_datapath->pipeline->tables [tableId];
  if (!(table->disabled))
    {
      entries = table->stats->active_count;
    }
  return entries;
}

uint64_t
OFSwitch13Device::GetFlowModCounter (void) const
{
  return m_cFlowMod;
}

uint32_t
OFSwitch13Device::GetFlowTableSize (void) const
{
  return m_flowTabSize;
}

uint32_t
OFSwitch13Device::GetGroupEntries (void) const
{
  return m_groupEntries;
}

uint64_t
OFSwitch13Device::GetGroupModCounter (void) const
{
  return m_cGroupMod;
}

uint32_t
OFSwitch13Device::GetGroupTableSize (void) const
{
  return m_groupTabSize;
}

uint32_t
OFSwitch13Device::GetMeterEntries (void) const
{
  return m_meterEntries;
}

uint64_t
OFSwitch13Device::GetMeterModCounter (void) const
{
  return m_cMeterMod;
}

uint32_t
OFSwitch13Device::GetMeterTableSize (void) const
{
  return m_meterTabSize;
}

uint32_t
OFSwitch13Device::GetNSwitchPorts (void) const
{
  return m_datapath->ports_num;
}

uint64_t
OFSwitch13Device::GetPacketInCounter (void) const
{
  return m_cPacketIn;
}

uint64_t
OFSwitch13Device::GetPacketOutCounter (void) const
{
  return m_cPacketOut;
}

DataRate
OFSwitch13Device::GetPipelineCapacity (void) const
{
  return m_pipeCapacity;
}

Time
OFSwitch13Device::GetPipelineDelay (void) const
{
  return m_pipeDelay;
}

DataRate
OFSwitch13Device::GetPipelineLoad (void) const
{
  return m_pipeLoad;
}

Ptr<OFSwitch13Port>
OFSwitch13Device::AddSwitchPort (Ptr<NetDevice> portDevice)
{
  NS_LOG_FUNCTION (this << portDevice);

  NS_LOG_INFO ("Adding port addr " << portDevice->GetAddress ());
  if (GetNSwitchPorts () >= DP_MAX_PORTS)
    {
      NS_FATAL_ERROR ("No more ports allowed.");
    }

  // Create the OpenFlow port for this device.
  Ptr<OFSwitch13Port> ofPort;
  ofPort = CreateObject<OFSwitch13Port> (m_datapath, portDevice, this);

  // Save port in port list (assert port no and vector index).
  m_ports.push_back (ofPort);
  NS_ASSERT (m_ports.size () == ofPort->GetPortNo ());

  return ofPort;
}

void
OFSwitch13Device::ReceiveFromSwitchPort (Ptr<Packet> packet, uint32_t portNo,
                                         uint64_t tunnelId)
{
  NS_LOG_FUNCTION (this << packet << portNo << tunnelId);

  // Check the packet for conformance to the pipeline capacity.
  uint32_t pktSizeBits = packet->GetSize () * 8;
  if (m_pipeTokens < pktSizeBits)
    {
      // Packet will be dropped. Increase counter and fire drop trace source.
      NS_LOG_DEBUG ("Drop packet due to pipeline max processing capacity.");
      m_loadDropTrace (packet);
      return;
    }

  // Consume tokens, fire trace source and schedule the packet to the pipeline.
  m_pipeTokens -= pktSizeBits;
  m_pipeConsumed += pktSizeBits;
  m_pipePacketTrace (packet);
  Simulator::Schedule (m_pipeDelay, &OFSwitch13Device::SendToPipeline,
                       this, packet, portNo, tunnelId);
}

void
OFSwitch13Device::StartControllerConnection (Address ctrlAddr)
{
  NS_LOG_FUNCTION (this << ctrlAddr);

  NS_ASSERT (!ctrlAddr.IsInvalid ());
  NS_ASSERT_MSG (InetSocketAddress::IsMatchingType (ctrlAddr),
                 "Invalid address type (only IPv4 supported by now).");
  NS_ASSERT_MSG (!GetRemoteController (ctrlAddr),
                 "Controller address already in use.");

  // Start a TCP connection to this target controller.
  int error = 0;
  TypeId tcpFact = TypeId::LookupByName ("ns3::TcpSocketFactory");
  Ptr<Socket> ctrlSocket = Socket::CreateSocket (GetObject<Node> (), tcpFact);
  ctrlSocket->SetAttribute ("SegmentSize", UintegerValue (8900));

  error = ctrlSocket->Bind ();
  if (error)
    {
      NS_LOG_ERROR ("Error binding socket " << error);
      return;
    }

  error = ctrlSocket->Connect (InetSocketAddress::ConvertFrom (ctrlAddr));
  if (error)
    {
      NS_LOG_ERROR ("Error connecting socket " << error);
      return;
    }

  ctrlSocket->SetConnectCallback (
    MakeCallback (&OFSwitch13Device::SocketCtrlSucceeded, this),
    MakeCallback (&OFSwitch13Device::SocketCtrlFailed, this));

  // Create a RemoteController object for this controller and save it.
  Ptr<RemoteController> remoteCtrl = Create<RemoteController> ();
  remoteCtrl->m_address = ctrlAddr;
  remoteCtrl->m_socket = ctrlSocket;
  m_controllers.push_back (remoteCtrl);
}

// ofsoftswitch13 overriding and callback functions.
void
OFSwitch13Device::SendPacketToController (struct pipeline *pl,
                                          struct packet *pkt, uint8_t tableId,
                                          uint8_t reason)
{
  Ptr<OFSwitch13Device> dev = OFSwitch13Device::GetDevice (pl->dp->id);
  dev->SendPacketInMessage (pkt, tableId, reason,
                            dev->m_datapath->config.miss_send_len);
}

int
OFSwitch13Device::SendOpenflowBufferToRemote (struct ofpbuf *buffer,
                                              struct remote *remote)
{
  Ptr<OFSwitch13Device> dev = OFSwitch13Device::GetDevice (remote->dp->id);
  Ptr<Packet> packet = ofs::PacketFromBuffer (buffer);
  Ptr<RemoteController> remoteCtrl = dev->GetRemoteController (remote);
  return dev->SendToController (packet, remoteCtrl);
}

void
OFSwitch13Device::DpActionsOutputPort (struct packet *pkt, uint32_t outPort,
                                       uint32_t outQueue, uint16_t maxLength,
                                       uint64_t cookie)
{
  Ptr<OFSwitch13Device> dev = OFSwitch13Device::GetDevice (pkt->dp->id);
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
        dev->SendToSwitchPort (pkt, pkt->in_port, outQueue);
        break;
      }
    case (OFPP_CONTROLLER):
      {
        dev->SendPacketInMessage (pkt, pkt->table_id,
                                  pkt->handle_std->table_miss ? OFPR_NO_MATCH :
                                  OFPR_ACTION, maxLength, cookie);
        break;
      }
    case (OFPP_FLOOD):
    case (OFPP_ALL):
      {
        struct sw_port *p;
        LIST_FOR_EACH (p, struct sw_port, node, &pkt->dp->port_list)
        {
          if ((p->stats->port_no == pkt->in_port)
              || (outPort == OFPP_FLOOD && p->conf->config & OFPPC_NO_FWD))
            {
              continue;
            }
          dev->SendToSwitchPort (pkt, p->stats->port_no);
        }
        break;
      }
    case (OFPP_NORMAL):
    case (OFPP_LOCAL):
    default:
      {
        if (pkt->in_port != outPort)
          {
            dev->SendToSwitchPort (pkt, outPort, outQueue);
          }
      }
    }
}

void
OFSwitch13Device::MeterCreatedCallback (struct meter_entry *entry)
{
  Ptr<OFSwitch13Device> dev = OFSwitch13Device::GetDevice (entry->dp->id);
  dev->NotifyMeterEntryCreated (entry);
}

void
OFSwitch13Device::MeterDropCallback (struct packet *pkt,
                                     struct meter_entry *entry)
{
  Ptr<OFSwitch13Device> dev = OFSwitch13Device::GetDevice (pkt->dp->id);
  dev->NotifyPacketDroppedByMeter (pkt, entry);
}

void
OFSwitch13Device::PacketCloneCallback (struct packet *pkt,
                                       struct packet *clone)
{
  Ptr<OFSwitch13Device> dev = OFSwitch13Device::GetDevice (pkt->dp->id);
  dev->NotifyPacketCloned (pkt, clone);
}

void
OFSwitch13Device::PacketDestroyCallback (struct packet *pkt)
{
  Ptr<OFSwitch13Device> dev = OFSwitch13Device::GetDevice (pkt->dp->id);
  dev->NotifyPacketDestroyed (pkt);
}

void
OFSwitch13Device::BufferSaveCallback (struct packet *pkt, time_t timeout)
{
  Ptr<OFSwitch13Device> dev = OFSwitch13Device::GetDevice (pkt->dp->id);
  dev->BufferPacketSave (pkt->ns3_uid, timeout);
}

void
OFSwitch13Device::BufferRetrieveCallback (struct packet *pkt)
{
  Ptr<OFSwitch13Device> dev = OFSwitch13Device::GetDevice (pkt->dp->id);
  dev->BufferPacketRetrieve (pkt->ns3_uid);
}

Ptr<OFSwitch13Device>
OFSwitch13Device::GetDevice (uint64_t id)
{
  DpIdDevMap_t::iterator it;
  it = OFSwitch13Device::m_globalSwitchMap.find (id);
  if (it != OFSwitch13Device::m_globalSwitchMap.end ())
    {
      return it->second;
    }
  else
    {
      NS_FATAL_ERROR ("Error retrieving datapath device from global map.");
      return 0;
    }
}

/********** Protected methods **********/
void
OFSwitch13Device::DoDispose ()
{
  NS_LOG_FUNCTION (this);

  OFSwitch13Device::UnregisterDatapath (m_dpId);

  PortList_t::iterator it;
  for (it = m_ports.begin (); it != m_ports.end (); it++)
    {
      Ptr<OFSwitch13Port> port = *it;
      port->Dispose ();
      *it = 0;
    }
  m_ports.clear ();
  m_bufferPkts.clear ();
  m_controllers.clear ();

  pipeline_destroy (m_datapath->pipeline);
  group_table_destroy (m_datapath->groups);
  meter_table_destroy (m_datapath->meters);
  free (m_datapath);

  Object::DoDispose ();
}

void
OFSwitch13Device::NotifyConstructionCompleted ()
{
  NS_LOG_FUNCTION (this);

  // Execute the first datapath timeout.
  DatapathTimeout (m_datapath);

  // Chain up.
  Object::NotifyConstructionCompleted ();
}

/********** Private methods **********/
struct datapath*
OFSwitch13Device::DatapathNew ()
{
  NS_LOG_FUNCTION (this);

  struct datapath *dp = (struct datapath*)xmalloc (sizeof (struct datapath));

  dp->mfr_desc = (char*)xmalloc (DESC_STR_LEN);
  dp->hw_desc = (char*)xmalloc (DESC_STR_LEN);
  dp->sw_desc = (char*)xmalloc (DESC_STR_LEN);
  dp->dp_desc = (char*)xmalloc (DESC_STR_LEN);
  dp->serial_num = (char*)xmalloc (DESC_STR_LEN);
  strncpy (dp->mfr_desc, "The ns-3 team", DESC_STR_LEN);
  strncpy (dp->hw_desc, "N/A", DESC_STR_LEN);
  strncpy (dp->sw_desc, "The ns-3 OFSwitch13 module", DESC_STR_LEN);
  strncpy (dp->dp_desc, "Using ofsoftswitch13 (from CPqD)", DESC_STR_LEN);
  strncpy (dp->serial_num, "3.1.0", DESC_STR_LEN);

  dp->id = m_dpId;
  dp->last_timeout = time_now ();
  m_lastTimeout = Simulator::Now ();
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

  m_bufferSize = dp_buffers_size (dp->buffers);

  list_init (&dp->port_list);
  dp->ports_num = 0;
  dp->max_queues = NETDEV_MAX_QUEUES;
  dp->exp = 0;

  dp->config.flags = OFPC_FRAG_NORMAL; // IP fragments with no special handling
  dp->config.miss_send_len = OFP_DEFAULT_MISS_SEND_LEN; // 128 bytes

  // ofsoftswitch13 callbacks
  dp->pkt_clone_cb = &OFSwitch13Device::PacketCloneCallback;
  dp->pkt_destroy_cb = &OFSwitch13Device::PacketDestroyCallback;
  dp->buff_save_cb = &OFSwitch13Device::BufferSaveCallback;
  dp->buff_retrieve_cb = &OFSwitch13Device::BufferRetrieveCallback;
  dp->meter_drop_cb = &OFSwitch13Device::MeterDropCallback;
  dp->meter_created_cb = &OFSwitch13Device::MeterCreatedCallback;

  return dp;
}

void
OFSwitch13Device::SetFlowTableSize (uint32_t value)
{
  NS_LOG_FUNCTION (this << value);

  NS_ASSERT_MSG (m_datapath, "No datapath created yet.");
  struct flow_table *table;
  for (size_t i = 0; i < PIPELINE_TABLES; i++)
    {
      table = m_datapath->pipeline->tables [i];
      NS_ABORT_MSG_IF (table->stats->active_count >= value,
                       "Can't reduce table size to this value.");
      table->features->max_entries = value;
    }
  m_flowTabSize = value;
}

void
OFSwitch13Device::SetGroupTableSize (uint32_t value)
{
  NS_LOG_FUNCTION (this << value);

  NS_ASSERT_MSG (m_datapath, "No datapath created yet.");
  NS_ABORT_MSG_IF (m_datapath->groups->entries_num >= value,
                   "Can't reduce table size to this value.");
  for (size_t i = 0; i < 4; i++)
    {
      m_datapath->groups->features->max_groups [i] = value;
    }
  m_groupTabSize = value;
}

void
OFSwitch13Device::SetMeterTableSize (uint32_t value)
{
  NS_LOG_FUNCTION (this << value);

  NS_ASSERT_MSG (m_datapath, "No datapath created yet.");
  NS_ABORT_MSG_IF (m_datapath->meters->entries_num >= value,
                   "Can't reduce table size to this value.");
  m_datapath->meters->features->max_meter = value;
  m_meterTabSize = value;
}

void
OFSwitch13Device::DatapathTimeout (struct datapath *dp)
{
  meter_table_add_tokens (dp->meters);
  pipeline_timeout (dp->pipeline);

  // Check for changes in links (port) status.
  PortList_t::iterator it;
  for (it = m_ports.begin (); it != m_ports.end (); it++)
    {
      Ptr<OFSwitch13Port> port = *it;
      port->PortUpdateState ();
    }

  // Update traced values.
  m_bufferUsage = (double)m_bufferPkts.size () / m_bufferSize;
  m_groupEntries =  m_datapath->groups->entries_num;
  m_meterEntries = m_datapath->meters->entries_num;
  uint32_t flowEntries = 0;
  for (size_t i = 0; i < PIPELINE_TABLES; i++)
    {
      flowEntries += GetFlowEntries (i);
    }
  m_flowEntries = flowEntries;

  // The pipeline delay is estimated as k * log (n), where 'k' is the
  // m_tcamDelay set to the time for a single TCAM operation, and 'n' is the
  // current number of entries on all flow tables.
  m_pipeDelay = m_flowEntries < 2U ? m_tcamDelay :
    m_tcamDelay * (int64_t)ceil (log2 (m_flowEntries));

  // The pipeline load is estimated based on the tokens removed from pipeline
  // bucket since last timeout operation.
  m_pipeLoad = DataRate (m_pipeConsumed / m_timeout.GetSeconds ());
  m_pipeConsumed = 0;

  // Refill the pipeline bucket with tokens based on elapsed time
  // (bucket capacity is set to the number of tokens for an entire second).
  Time elapTime = Simulator::Now () - m_lastTimeout;
  uint64_t addTokens = m_pipeCapacity.GetBitRate () * elapTime.GetSeconds ();
  uint64_t maxTokens = m_pipeCapacity.GetBitRate ();
  m_pipeTokens = std::min (m_pipeTokens + addTokens, maxTokens);

  dp->last_timeout = time_now ();
  m_lastTimeout = Simulator::Now ();
  m_datapathTimeoutTrace (this);
  Simulator::Schedule (m_timeout, &OFSwitch13Device::DatapathTimeout,
                       this, m_datapath);
}

Ptr<OFSwitch13Port>
OFSwitch13Device::GetOFSwitch13Port (uint32_t no)
{
  NS_LOG_FUNCTION (this << no);

  // Assert port no (starts at 1).
  NS_ASSERT_MSG (no > 0 && no <= m_ports.size (), "Port is out of range.");
  return m_ports.at (no - 1);
}

int
OFSwitch13Device::SendPacketInMessage (struct packet *pkt, uint8_t tableId,
                                       uint8_t reason, uint16_t maxLength,
                                       uint64_t cookie)
{
  NS_LOG_FUNCTION (this << pkt->ns3_uid << tableId << reason);

  // Create the packet_in message.
  struct ofl_msg_packet_in msg;
  msg.header.type = OFPT_PACKET_IN;
  msg.total_len = pkt->buffer->size;
  msg.reason = (enum ofp_packet_in_reason)reason;
  msg.table_id = tableId;
  msg.cookie = cookie;
  msg.data = (uint8_t*)pkt->buffer->data;

  // A maxLength of OFPCML_NO_BUFFER means that the complete packet should be
  // sent, and it should not be buffered. However, in this implementation we
  // always save the packet into buffer to avoid losing ns-3 packet id
  // reference. This is not full compliant with OpenFlow specification, but
  // works very well here.
  dp_buffers_save (pkt->dp->buffers, pkt);
  msg.buffer_id = pkt->buffer_id;
  msg.data_length = MIN (maxLength, pkt->buffer->size);

  if (!pkt->handle_std->valid)
    {
      packet_handle_std_validate (pkt->handle_std);
    }
  msg.match = (struct ofl_match_header*) &pkt->handle_std->match;

  // Increase packet-in counter and send the message.
  m_cPacketIn++;
  return dp_send_message (pkt->dp, (struct ofl_msg_header *)&msg, 0);
}

bool
OFSwitch13Device::SendToSwitchPort (struct packet *pkt, uint32_t portNo,
                                    uint32_t queueNo)
{
  NS_LOG_FUNCTION (this << pkt->ns3_uid << portNo);

  Ptr<OFSwitch13Port> port = GetOFSwitch13Port (portNo);
  if (!port)
    {
      NS_LOG_ERROR ("Can't forward packet to invalid port.");
      return false;
    }

  // When a packet is sent to OpenFlow pipeline, we keep track of its original
  // ns3::Packet using the PipelinePacket structure. When the packet is
  // processed by the pipeline with no internal changes, we forward the
  // original ns3::Packet to the specified output port. When internal changes
  // are necessary, we need to create a new packet with the modified content
  // and copy all packet tags to this new one. This approach is more expensive
  // than the previous one, but is far more simple than identifying which
  // changes were performed in the packet to modify the original ns3::Packet.
  Ptr<Packet> packet;
  if (m_pipePkt.IsValid ())
    {
      NS_ASSERT_MSG (m_pipePkt.HasId (pkt->ns3_uid), "Invalid packet ID.");
      if (pkt->changes)
        {
          // The original ns-3 packet was modified by OpenFlow switch.
          // Create a new packet with modified data and copy tags from the
          // original packet.
          NS_LOG_DEBUG ("Packet " << pkt->ns3_uid << " modified by switch.");
          packet = ofs::PacketFromBuffer (pkt->buffer);
          OFSwitch13Device::CopyTags (m_pipePkt.GetPacket (), packet);
        }
      else
        {
          // Using the original ns-3 packet.
          packet = m_pipePkt.GetPacket ();
        }
    }
  else
    {
      // This is a new packet, probably created by the controller and sent to
      // the switch within an OpenFlow packet-out message.
      NS_ASSERT_MSG (pkt->ns3_uid == 0, "Invalid packet ID.");
      NS_LOG_DEBUG ("Creating new ns-3 packet from OpenFlow buffer.");
      packet = ofs::PacketFromBuffer (pkt->buffer);
    }

  // Send the packet to switch port.
  return port->Send (packet, queueNo, pkt->tunnel_id);
}

void
OFSwitch13Device::SendToPipeline (Ptr<Packet> packet, uint32_t portNo,
                                  uint64_t tunnelId)
{
  NS_LOG_FUNCTION (this << packet << portNo << tunnelId);

  NS_ASSERT_MSG (!m_pipePkt.IsValid (), "Another packet in pipeline.");

  // Creating the internal OpenFlow packet structure from ns-3 packet
  // Allocate buffer with some extra space for OpenFlow packet modifications.
  uint32_t headRoom = 128 + 2;
  uint32_t bodyRoom = packet->GetSize () + VLAN_ETH_HEADER_LEN;
  struct ofpbuf *buffer = ofs::BufferFromPacket (packet, bodyRoom, headRoom);
  struct packet *pkt = packet_create (m_datapath, portNo, buffer,
                                      tunnelId, false);

  // Save the ns-3 packet into pipeline structure. Note that we are using a
  // private packet uid to avoid conflicts with ns3::Packet uid.
  pkt->ns3_uid = OFSwitch13Device::GetNewPacketId ();
  m_pipePkt.SetPacket (pkt->ns3_uid, packet);

  // Send the packet to pipeline.
  pipeline_process_packet (m_datapath->pipeline, pkt);
}

int
OFSwitch13Device::SendToController (Ptr<Packet> packet,
                                    Ptr<RemoteController> remoteCtrl)
{
  if (!remoteCtrl->m_socket)
    {
      NS_LOG_ERROR ("No controller connection. Discarding message.");
      return -1;
    }

  // TODO: No support for auxiliary connections.
  return remoteCtrl->m_handler->SendMessage (packet);
}

void
OFSwitch13Device::ReceiveFromController (Ptr<Packet> packet, Address from)
{
  NS_LOG_FUNCTION (this << packet << from);

  struct ofl_msg_header *msg;
  ofl_err error;

  Ptr<RemoteController> remoteCtrl = GetRemoteController (from);
  NS_ASSERT_MSG (remoteCtrl, "Error returning controller for this address.");

  struct sender senderCtrl;
  senderCtrl.remote = remoteCtrl->m_remote;
  senderCtrl.conn_id = 0; // TODO No support for auxiliary connections

  // Get the OpenFlow buffer and unpack the message.
  struct ofpbuf *buffer;
  buffer = ofs::BufferFromPacket (packet, packet->GetSize ());
  error = ofl_msg_unpack ((uint8_t*)buffer->data, buffer->size, &msg,
                          &senderCtrl.xid, m_datapath->exp);

  // Check for error while unpacking the message.
  if (error)
    {
      // The ofsoftswitch13 librady only unpacks messages that has the same
      // OFP_VERSION that is supported by the datapath implementation. However,
      // when an OpenFlow connection is first established, each side of the
      // connection must immediately send an OFPT_HELLO message with the
      // version field set to the highest OpenFlow switch protocol version
      // supported by the sender. Upon receipt of this message, the recipient
      // must calculate the OpenFlow switch protocol version to be used, and
      // the negotiated version must be the smaller of the version number that
      // was sent and the one that was received in the version fields. So, for
      // the OFPT_HELLO message, we will check for advertised version to see if
      // it is higher than ours, in which case we can continue.
      struct ofp_header *header = (struct ofp_header*)buffer->data;
      if (header->type != OFPT_HELLO || header->version <= OFP_VERSION)
        {
          // This is not a hello message or the advertised version is lower
          // than OFP_VERSION. Notify the error and return.
          ReplyWithErrorMessage (error, buffer, &senderCtrl);
          ofpbuf_delete (buffer);
          return;
        }
      else
        {
          // The advertised version is equal or higher than OFP_VERSION. Let's
          // change the message version to OFP_VERSION so the message can be
          // successfully unpacked and we can continue.
          header->version = OFP_VERSION;
          error = ofl_msg_unpack ((uint8_t*)buffer->data, buffer->size, &msg,
                                  &senderCtrl.xid, m_datapath->exp);

          // Check for any other error while unpacking the message.
          if (error)
            {
              // Notify the error and return.
              ReplyWithErrorMessage (error, buffer, &senderCtrl);
              ofpbuf_delete (buffer);
              return;
            }
        }
    }

  // Print message content.
  char *msgStr = ofl_msg_to_string (msg, m_datapath->exp);
  Ipv4Address ctrlIp = InetSocketAddress::ConvertFrom (from).GetIpv4 ();
  NS_LOG_DEBUG ("RX from controller " << ctrlIp << ": " << msgStr);
  free (msgStr);

  // Increase internal counters based on message type.
  switch (msg->type)
    {
    case (OFPT_PACKET_OUT):
      {
        m_cPacketOut++;
        break;
      }
    case (OFPT_FLOW_MOD):
      {
        m_cFlowMod++;
        break;
      }
    case (OFPT_METER_MOD):
      {
        m_cMeterMod++;
        break;
      }
    case (OFPT_GROUP_MOD):
      {
        m_cGroupMod++;
        break;
      }
    default:
      {
      }
    }

  // Send the message to handler.
  error = handle_control_msg (m_datapath, msg, &senderCtrl);
  if (error)
    {
      // It is assumed that if a handler returns with error, it did not use any
      // part of the control message, thus it can be freed up. If no error is
      // returned however, the message must be freed inside the handler because
      // the handler might keep parts of the message.
      ofl_msg_free (msg, m_datapath->exp);
      ReplyWithErrorMessage (error, buffer, &senderCtrl);
    }

  // If we got here, let's free the buffer.
  ofpbuf_delete (buffer);
}

int
OFSwitch13Device::ReplyWithErrorMessage (ofl_err error, struct ofpbuf *buffer,
                                         struct sender *senderCtrl)
{
  NS_LOG_FUNCTION (this << error);

  struct ofl_msg_error err;
  err.header.type = OFPT_ERROR;
  err.type = (enum ofp_error_type)ofl_error_type (error);
  err.code = ofl_error_code (error);
  err.data_length = buffer->size;
  err.data = (uint8_t*)buffer->data;

  char *msgStr = ofl_msg_to_string ((struct ofl_msg_header*)&err, 0);
  NS_LOG_ERROR ("Error processing OpenFlow message. Reply with " << msgStr);
  free (msgStr);

  return dp_send_message (m_datapath, (struct ofl_msg_header*)&err,
                          senderCtrl);
}

void
OFSwitch13Device::SocketCtrlSucceeded (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);

  NS_LOG_INFO ("Controller accepted connection request!");
  Ptr<RemoteController> remoteCtrl = GetRemoteController (socket);
  remoteCtrl->m_remote = remote_create (m_datapath, 0, 0);

  // As we have more than one socket that is used for communication between
  // this OpenFlow switch device and controllers, we need to handle the process
  // of sending/receiving OpenFlow messages to/from sockets in an independent
  // way. So, each socket has its own socket handler to this end.
  remoteCtrl->m_handler = CreateObject<OFSwitch13SocketHandler> (socket);
  remoteCtrl->m_handler->SetReceiveCallback (
    MakeCallback (&OFSwitch13Device::ReceiveFromController, this));

  // Send the OpenFlow Hello message.
  struct ofl_msg_header msg;
  msg.type = OFPT_HELLO;

  struct sender senderCtrl;
  senderCtrl.remote = remoteCtrl->m_remote;
  senderCtrl.conn_id = 0; // TODO No support for auxiliary connections.
  dp_send_message (m_datapath, &msg, &senderCtrl);
}

void
OFSwitch13Device::SocketCtrlFailed (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);

  NS_LOG_ERROR ("Controller did not accepted connection request!");

  // Loop over controllers looking for the one associated to this socket and
  // remove it from the collection.
  CtrlList_t::iterator it;
  for (it = m_controllers.begin (); it != m_controllers.end (); it++)
    {
      Ptr<RemoteController> remoteCtrl = *it;
      if (remoteCtrl->m_socket == socket)
        {
          m_controllers.erase (it);
          return;
        }
    }
}

void
OFSwitch13Device::NotifyMeterEntryCreated (struct meter_entry *entry)
{
  NS_LOG_FUNCTION (this << entry->config->meter_id);

  // Update meter entry last_fill field with the time of last datapath timeout,
  // and force a new bucket refill based on this elapsed time.
  for (size_t i = 0; i < entry->config->meter_bands_num; i++)
    {
      entry->stats->band_stats [i]->last_fill =
        static_cast<uint64_t> (m_lastTimeout.GetMilliSeconds ());
    }
  meter_table_add_tokens (m_datapath->meters);
}

void
OFSwitch13Device::NotifyPacketCloned (struct packet *pkt, struct packet *clone)
{
  NS_LOG_FUNCTION (this << pkt->ns3_uid);

  // Assigning a new unique ID for this cloned packet.
  clone->ns3_uid = OFSwitch13Device::GetNewPacketId ();
  m_pipePkt.NewCopy (clone->ns3_uid);
}

void
OFSwitch13Device::NotifyPacketDestroyed (struct packet *pkt)
{
  NS_LOG_FUNCTION (this << pkt->ns3_uid);

  // This is the packet current under pipeline. Let's delete this copy.
  if (m_pipePkt.IsValid () && m_pipePkt.HasId (pkt->ns3_uid))
    {
      bool valid = m_pipePkt.DelCopy (pkt->ns3_uid);
      if (!valid)
        {
          NS_LOG_DEBUG ("Packet " << pkt->ns3_uid << " done at this switch.");
        }
      return;
    }

  // This destroyed packet has no ns-3 ID. This packet was probably created by
  // the OpenFlow controller and sent to the switch within an OpenFlow
  // packet-out message. No action is required here.
  if (pkt->ns3_uid == 0)
    {
      NS_LOG_DEBUG ("Deleting lib packet with no corresponding ns-3 packet.");
      return;
    }

  // If we got here, this packet must not be valid on the pipeline structure.
  NS_ASSERT_MSG ((m_pipePkt.IsValid () && !m_pipePkt.HasId (pkt->ns3_uid))
                 || !m_pipePkt.IsValid (), "Packet still valid in pipeline.");

  // This destroyed packet is probably an old packet that was previously saved
  // into buffer and will be deleted now, freeing up space for a new packet at
  // same buffer index (that's how the library handles the buffer). So, we are
  // going to remove this packet from our buffer, if it still exists there.
  BufferPacketDelete (pkt->ns3_uid);
  NS_LOG_DEBUG ("Packet " << pkt->ns3_uid << " done at this switch.");
}

void
OFSwitch13Device::NotifyPacketDroppedByMeter (struct packet *pkt,
                                              struct meter_entry *entry)
{
  NS_LOG_FUNCTION (this << pkt->ns3_uid << entry->stats->meter_id);

  uint32_t meterId = entry->stats->meter_id;
  NS_ASSERT_MSG (m_pipePkt.HasId (pkt->ns3_uid), "Invalid packet ID.");
  NS_LOG_DEBUG ("OpenFlow meter id " << meterId <<
                " dropped packet " << pkt->ns3_uid);

  // Increase counter and fire drop trace source.
  m_meterDropTrace (m_pipePkt.GetPacket (), meterId);
}

void
OFSwitch13Device::BufferPacketSave (uint64_t packetId, time_t timeout)
{
  NS_LOG_FUNCTION (this << packetId);

  NS_ASSERT_MSG (m_pipePkt.HasId (packetId), "Invalid packet ID.");

  // Remove from pipeline and save into buffer.
  std::pair <uint64_t, Ptr<Packet> > entry (packetId, m_pipePkt.GetPacket ());
  std::pair <IdPacketMap_t::iterator, bool> ret;
  ret = m_bufferPkts.insert (entry);
  if (ret.second == true)
    {
      NS_LOG_DEBUG ("Packet " << packetId << " saved into buffer.");
      m_bufferSaveTrace (m_pipePkt.GetPacket ());
    }
  else
    {
      NS_LOG_WARN ("Packet " << packetId << " already in buffer.");
    }
  m_pipePkt.DelCopy (packetId);
  NS_ASSERT_MSG (!m_pipePkt.IsValid (), "Packet copy still in pipeline.");

  // Scheduling the buffer remove for expired packet. Since packet timeout
  // resolution is expressed in seconds, let's double it to avoid rounding
  // conflicts.
  Simulator::Schedule (Time::FromInteger (2 * timeout, Time::S),
                       &OFSwitch13Device::BufferPacketDelete, this, packetId);
}

void
OFSwitch13Device::BufferPacketRetrieve (uint64_t packetId)
{
  NS_LOG_FUNCTION (this << packetId);

  NS_ASSERT_MSG (!m_pipePkt.IsValid (), "Another packet in pipeline.");

  // Find packet in buffer.
  IdPacketMap_t::iterator it = m_bufferPkts.find (packetId);
  NS_ASSERT_MSG (it != m_bufferPkts.end (), "Packet not found in buffer.");

  // Save packet into pipeline structure.
  m_pipePkt.SetPacket (it->first, it->second);
  m_bufferRetrieveTrace (m_pipePkt.GetPacket ());

  // Delete packet from buffer.
  NS_LOG_DEBUG ("Packet " << packetId << " removed from buffer.");
  m_bufferPkts.erase (it);
}

void
OFSwitch13Device::BufferPacketDelete (uint64_t packetId)
{
  NS_LOG_FUNCTION (this << packetId);

  // Delete from buffer map.
  IdPacketMap_t::iterator it = m_bufferPkts.find (packetId);
  if (it != m_bufferPkts.end ())
    {
      NS_LOG_DEBUG ("Expired packet " << packetId << " deleted from buffer.");
      m_bufferExpireTrace (it->second);
      m_bufferPkts.erase (it);
    }
}

Ptr<OFSwitch13Device::RemoteController>
OFSwitch13Device::GetRemoteController (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);

  CtrlList_t::iterator it;
  for (it = m_controllers.begin (); it != m_controllers.end (); it++)
    {
      if ((*it)->m_socket == socket)
        {
          return *it;
        }
    }
  NS_FATAL_ERROR ("Error returning controller for this socket.");
}

Ptr<OFSwitch13Device::RemoteController>
OFSwitch13Device::GetRemoteController (Address address)
{
  NS_LOG_FUNCTION (this << address);

  CtrlList_t::iterator it;
  for (it = m_controllers.begin (); it != m_controllers.end (); it++)
    {
      if ((*it)->m_address == address)
        {
          return *it;
        }
    }
  return 0;
}

Ptr<OFSwitch13Device::RemoteController>
OFSwitch13Device::GetRemoteController (struct remote *remote)
{
  NS_LOG_FUNCTION (this << remote);

  CtrlList_t::iterator it;
  for (it = m_controllers.begin (); it != m_controllers.end (); it++)
    {
      if ((*it)->m_remote == remote)
        {
          return *it;
        }
    }
  NS_FATAL_ERROR ("Error returning controller for this remote pointer.");
}

uint64_t
OFSwitch13Device::GetNewPacketId ()
{
  return ++m_globalPktId;
}

bool
OFSwitch13Device::CopyTags (Ptr<const Packet> srcPkt, Ptr<const Packet> dstPkt)
{
  // Copy packet tags.
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

  // Copy byte tags.
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
OFSwitch13Device::RegisterDatapath (uint64_t id, Ptr<OFSwitch13Device> dev)
{
  std::pair<uint64_t, Ptr<OFSwitch13Device> > entry (id, dev);
  std::pair<DpIdDevMap_t::iterator, bool> ret;
  ret = OFSwitch13Device::m_globalSwitchMap.insert (entry);
  if (ret.second == false)
    {
      NS_FATAL_ERROR ("Error inserting datapath device into global map.");
    }
}

void
OFSwitch13Device::UnregisterDatapath (uint64_t id)
{
  DpIdDevMap_t::iterator it;
  it = OFSwitch13Device::m_globalSwitchMap.find (id);
  if (it != OFSwitch13Device::m_globalSwitchMap.end ())
    {
      OFSwitch13Device::m_globalSwitchMap.erase (it);
    }
  else
    {
      NS_FATAL_ERROR ("Error removing datapath device from global map.");
    }
}

OFSwitch13Device::RemoteController::RemoteController ()
  : m_socket (0),
    m_handler (0),
    m_remote (0)
{
  m_address = Address ();
}

OFSwitch13Device::PipelinePacket::PipelinePacket ()
  : m_valid (false),
    m_packet (0)
{
}

void
OFSwitch13Device::PipelinePacket::SetPacket (uint64_t id, Ptr<Packet> packet)
{
  NS_ASSERT_MSG (id && packet, "Invalid packet metadata values.");
  m_valid = true;
  m_packet = packet;
  m_ids.push_back (id);
}

Ptr<Packet>
OFSwitch13Device::PipelinePacket::GetPacket (void) const
{
  NS_ASSERT_MSG (IsValid (), "Invalid packet metadata.");
  return m_packet;
}

void
OFSwitch13Device::PipelinePacket::Invalidate (void)
{
  m_valid = false;
  m_packet = 0;
  m_ids.clear ();
}

bool
OFSwitch13Device::PipelinePacket::IsValid (void) const
{
  return m_valid;
}

void
OFSwitch13Device::PipelinePacket::NewCopy (uint64_t id)
{
  NS_ASSERT_MSG (m_valid, "Invalid packet metadata.");
  m_ids.push_back (id);
}

bool
OFSwitch13Device::PipelinePacket::DelCopy (uint64_t id)
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
OFSwitch13Device::PipelinePacket::HasId (uint64_t id)
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
