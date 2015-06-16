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

#include "ns3/log.h"
#include "ns3/enum.h"
#include "ns3/uinteger.h"
#include "ns3/drop-tail-queue.h"
#include "ofswitch13-queue.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Queue");
NS_OBJECT_ENSURE_REGISTERED (OFSwitch13Queue);

// m_maxQueues must be less or equal to ofsoftswitch13 NETDEV_MAX_QUEUES
// constant, which is currently set to 8. To increase this value, update
// dp_ports.h sw_port structure.
const uint16_t OFSwitch13Queue::m_maxQueues = 8;

TypeId OFSwitch13Queue::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OFSwitch13Queue")
    .SetParent<Queue> ()
    .SetGroupName ("OFswitch13")
    .AddConstructor<OFSwitch13Queue> ()
  ;
  return tid;
}

OFSwitch13Queue::OFSwitch13Queue ()
  : Queue (),
    m_swPort (0),
    m_numQueues (0)
{
  NS_LOG_FUNCTION (this);
}

OFSwitch13Queue::OFSwitch13Queue (sw_port* port)
  : Queue (),
    m_swPort (0),
    m_numQueues (0)
{
  NS_LOG_FUNCTION (this << port);

  m_swPort = port;

  // Adding the default drop tail queue with id 0
  AddInternalQueue (0, CreateObject<DropTailQueue> ());
}

OFSwitch13Queue::~OFSwitch13Queue ()
{
  NS_LOG_FUNCTION (this);
  m_queues.clear ();
}

uint16_t
OFSwitch13Queue::GetMaxQueues (void)
{
  return m_maxQueues;
}

bool
OFSwitch13Queue::AddInternalQueue (uint32_t id, Ptr<Queue> queue)
{
  NS_LOG_FUNCTION (this << queue << id);
 
  // Filling ofsoftswitch13 internal structures for this port.
  sw_queue* swQueue = &(m_swPort->queues[id]);
  NS_ASSERT_MSG (!swQueue->port, "Not empty queue position.");

  swQueue->port = m_swPort;
  swQueue->created = time_msec ();
  swQueue->stats = (ofl_queue_stats*)xmalloc (sizeof (ofl_queue_stats));
  swQueue->stats->port_no = m_swPort->conf->port_no;
  swQueue->stats->queue_id = id;
  swQueue->stats->tx_bytes = 0;
  swQueue->stats->tx_packets = 0;
  swQueue->stats->tx_errors = 0;
  swQueue->stats->duration_sec = 0;
  swQueue->stats->duration_nsec = 0;

  swQueue->props = (ofl_packet_queue*)xmalloc (sizeof (struct ofl_packet_queue));
  swQueue->props->queue_id = id;
  swQueue->props->properties_num = 0;
  
  // FIXME ofsoftswitch assumes the packet queue has exactly one property, for min rate
  // swQueue->props->properties = (ofl_queue_prop_header*)xmalloc (
  //   sizeof (struct ofl_queue_prop_header*));
  // swQueue->props->properties [0] = xmalloc (
  //   sizeof(struct ofl_queue_prop_min_rate));
  // ((ofl_queue_prop_min_rate*)(queue->props->properties[0]))->header.type = OFPQT_MIN_RATE;
  // ((ofl_queue_prop_min_rate*)(queue->props->properties[0]))->rate = mr->rate;

  std::pair<uint32_t, Ptr<Queue> > entry (0, queue);
  std::pair<IdQueueMap_t::iterator, bool> ret;
  ret = m_queues.insert (entry);
  NS_ASSERT_MSG (ret.second, "Unable to insert queue " << id);

  m_swPort->num_queues++;
  m_numQueues++;
  
  return true;
}

bool
OFSwitch13Queue::DelInternalQueue (uint32_t id)
{
  NS_LOG_FUNCTION (this << id);

  sw_queue* swQueue = &(m_swPort->queues[id]);
  NS_ASSERT_MSG (swQueue->port, "Invalid queue pointer");

  free (swQueue->stats);
  free (swQueue->props);
  memset (swQueue, 0x00, sizeof (sw_queue));
  m_swPort->num_queues--;
  m_numQueues--;

  IdQueueMap_t::iterator it = m_queues.find (id);
  NS_ASSERT_MSG (it != m_queues.end (), "Invalid queue id.");
  m_queues.erase (it);

  return true;
}

Ptr<Queue>
OFSwitch13Queue::GetQueue (uint32_t id) const
{
  IdQueueMap_t::const_iterator it = m_queues.find (id);
  NS_ASSERT_MSG (it != m_queues.end (), "Invalid queue id.");
  
  return it->second;
}

bool
OFSwitch13Queue::DoEnqueue (Ptr<Packet> p)
{
  NS_LOG_FUNCTION (this << p);

  QueueTag queueNoTag;
  bool found = p->RemovePacketTag (queueNoTag);
  NS_ASSERT_MSG (found, "Packet was supposed to be tagged with queue number.");
  
  uint32_t queueNo = queueNoTag.GetQueueId ();
  NS_LOG_UNCOND ("Packet " << p << " to be enqueued in queue no " << queueNo);

  return GetQueue (queueNo)->Enqueue (p);
}

Ptr<Packet>
OFSwitch13Queue::DoDequeue (void)
{
  NS_LOG_FUNCTION (this);

  return GetQueue (0)->Dequeue ();
}

Ptr<const Packet>
OFSwitch13Queue::DoPeek (void) const
{
  NS_LOG_FUNCTION (this);

  Ptr<const Queue> queue = GetQueue (0);
  return queue->Peek ();
}

} // namespace ns3

