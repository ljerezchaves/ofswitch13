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
  if (m_swPort != 0) { std::clog << "[dp " << m_swPort->dp->id << " port " << m_swPort->conf->port_no << "] "; }

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
// dp_ports.h sw_port.queues structure.
const uint16_t OFSwitch13Queue::m_maxQueues = 8;

TypeId 
OFSwitch13Queue::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OFSwitch13Queue")
    .SetParent<Queue> ()
    .SetGroupName ("OFSwitch13")
    .AddConstructor<OFSwitch13Queue> ()
  ;
  return tid;
}

OFSwitch13Queue::OFSwitch13Queue ()
  : Queue (),
    m_swPort (0)
{
  NS_LOG_FUNCTION (this);
}

OFSwitch13Queue::OFSwitch13Queue (sw_port* port)
  : Queue (),
    m_swPort (port)
{
  NS_LOG_FUNCTION (this << port);

  // Adding the default ns3::DropTailQueue with 
  // id = 0 for best-effort traffic.
  AddInternalQueue (0, CreateObject<DropTailQueue> ());
}

OFSwitch13Queue::~OFSwitch13Queue ()
{
  NS_LOG_FUNCTION (this);
}

void
OFSwitch13Queue::DoDispose ()
{
  NS_LOG_FUNCTION (this);

  // While m_swPort is valid, free internal stats and props 
  // structures for each available queue
  if (m_swPort)
    {
      sw_queue* swQueue;
      IdQueueMap_t::iterator it;
      for (it = m_queues.begin (); it != m_queues.end (); it++)
        {
          swQueue = &(m_swPort->queues[it->first]);
          free (swQueue->stats);
          free (swQueue->props);
        }
      m_swPort = 0;
    }
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
  NS_LOG_FUNCTION (this << id << queue);
  
  NS_ASSERT_MSG (m_swPort, "Invalid OpenFlow port metadata.");
  NS_ASSERT_MSG (id < m_maxQueues, "Invalid queue id.");

  sw_queue* swQueue = &(m_swPort->queues[id]);
  NS_ASSERT_MSG (!swQueue->port, "Queue id already in use.");

  // Filling ofsoftswitch13 internal structures for this queue
  swQueue->port = m_swPort;
  swQueue->created = time_msec ();

  swQueue->stats = (ofl_queue_stats*)xmalloc (sizeof (ofl_queue_stats));
  memset (swQueue->stats, 0x00, sizeof (ofl_queue_stats));
  swQueue->stats->port_no = m_swPort->conf->port_no;
  swQueue->stats->queue_id = id;
  
  swQueue->props = (ofl_packet_queue*)xmalloc (sizeof (struct ofl_packet_queue));
  swQueue->props->queue_id = id;
  swQueue->props->properties_num = 0;
  
  // Inserting the ns3::Queue object into queue map.
  std::pair<uint32_t, Ptr<Queue> > entry (id, queue);
  std::pair<IdQueueMap_t::iterator, bool> ret;
  ret = m_queues.insert (entry);
  if (ret.second == false)
    {
      NS_FATAL_ERROR ("Unable to insert queue id = " << id);
    }

  m_swPort->num_queues++;
  return true;
}

bool
OFSwitch13Queue::DelInternalQueue (uint32_t id)
{
  NS_LOG_FUNCTION (this << id);
  
  sw_queue* swQueue = dp_ports_lookup_queue (m_swPort, id);
  NS_ASSERT_MSG (swQueue, "Invalid queue id.");
  NS_ASSERT_MSG (id != 0, "Can't remove default queue");

  IdQueueMap_t::iterator it = m_queues.find (id);
  if (it == m_queues.end ())
    {
      NS_LOG_ERROR ("Can't remove invalid queue id = " << id);
      return false;
    }
  m_queues.erase (it);

  free (swQueue->stats);
  free (swQueue->props);
  memset (swQueue, 0x00, sizeof (sw_queue));
  m_swPort->num_queues--;
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

  sw_queue* swQueue;
  QueueTag queueNoTag;
  uint32_t queueNo = 0;
  if (p->RemovePacketTag (queueNoTag))
    {
      queueNo = queueNoTag.GetQueueId ();
    }
  NS_LOG_DEBUG ("Packet " << p << " to be enqueued in queue no " << queueNo);

  swQueue = dp_ports_lookup_queue (m_swPort, queueNo);
  NS_ASSERT_MSG (swQueue, "Invalid queue id.");
  if (GetQueue (queueNo)->Enqueue (p))
    {
      swQueue->stats->tx_packets++;
      swQueue->stats->tx_bytes += p->GetSize ();
      return true;
    }
  else
    {
      swQueue->stats->tx_errors++;
      return false;
    }
}

Ptr<Packet>
OFSwitch13Queue::DoDequeue (void)
{
  NS_LOG_FUNCTION (this);

  // TODO From which queue we should get the packet?
  return GetQueue (0)->Dequeue ();
}

Ptr<const Packet>
OFSwitch13Queue::DoPeek (void) const
{
  NS_LOG_FUNCTION (this);

  // TODO From which queue we should get the packet?
  Ptr<const Queue> queue = GetQueue (0);
  return queue->Peek ();
}

} // namespace ns3

