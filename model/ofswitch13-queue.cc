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
#include "ns3/object-vector.h"
#include "ns3/drop-tail-queue.h"
#include "ofswitch13-queue.h"
#include <algorithm>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Queue");
NS_OBJECT_ENSURE_REGISTERED (OFSwitch13Queue);

TypeId
OFSwitch13Queue::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OFSwitch13Queue")
    .SetParent<Queue> ()
    .SetGroupName ("OFSwitch13")
    .AddAttribute ("NumQueues",
                   "The number of internal queues available on this queue.",
                   TypeId::ATTR_GET | TypeId::ATTR_CONSTRUCT,
                   UintegerValue (NETDEV_MAX_QUEUES),
                   MakeUintegerAccessor (&OFSwitch13Queue::m_intQueues),
                   MakeUintegerChecker<uint32_t> (1, NETDEV_MAX_QUEUES))
    .AddAttribute ("QueueList",
                   "The list of internal queues available to the port.",
                   ObjectVectorValue (),
                   MakeObjectVectorAccessor (&OFSwitch13Queue::m_queues),
                   MakeObjectVectorChecker<Queue> ())
  ;
  return tid;
}

OFSwitch13Queue::OFSwitch13Queue (struct sw_port *port)
  : Queue (),
    m_swPort (port)
{
  NS_LOG_FUNCTION (this << port);
}

OFSwitch13Queue::~OFSwitch13Queue ()
{
  NS_LOG_FUNCTION (this);
}

uint32_t
OFSwitch13Queue::GetNQueues (void) const
{
  return m_intQueues;
}

void
OFSwitch13Queue::DoDispose ()
{
  NS_LOG_FUNCTION (this);

  // While m_swPort is valid, free internal stats and props
  // structures for each available queue
  if (m_swPort)
    {
      struct sw_queue *swQueue;
      for (uint32_t i = 0; i < GetNQueues (); i++)
        {
          swQueue = &(m_swPort->queues[i]);
          free (swQueue->stats);
          free (swQueue->props);
        }
      m_swPort = 0;
    }
  m_queues.clear ();
}

void
OFSwitch13Queue::NotifyConstructionCompleted (void)
{
  NS_LOG_FUNCTION (this);

  // We are using a very large queue size for this queue interface. The real
  // check for queue space is performed at DoEnqueue () by the internal queues.
  SetAttribute ("Mode", EnumValue (Queue::QUEUE_MODE_PACKETS));
  SetAttribute ("MaxPackets", UintegerValue (0xffffffff));

  // Setting default internal queue configuration.
  ObjectFactory queueFactory;
  queueFactory.SetTypeId (DropTailQueue::GetTypeId ());
  queueFactory.Set ("Mode", EnumValue (Queue::QUEUE_MODE_PACKETS));
  queueFactory.Set ("MaxPackets", UintegerValue (100));

  // Adding internal queues. It will create the maximum number of queues
  // allowed to this port, even if they are not used.
  for (uint32_t i = 0; i < GetNQueues (); i++)
    {
      AddQueue (queueFactory.Create<Queue> ());
    }

  // Chain up.
  Queue::NotifyConstructionCompleted ();
}

bool
OFSwitch13Queue::DoEnqueue (Ptr<QueueItem> item)
{
  NS_LOG_FUNCTION (this << item);

  struct sw_queue *swQueue;
  QueueTag queueNoTag;
  uint32_t queueNo = 0;
  if (item->GetPacket ()->RemovePacketTag (queueNoTag))
    {
      queueNo = queueNoTag.GetQueueId ();
    }
  NS_LOG_DEBUG ("Item " << item << " to be enqueued in queue id " << queueNo);

  swQueue = dp_ports_lookup_queue (m_swPort, queueNo);
  NS_ASSERT_MSG (swQueue, "Invalid queue id.");

  bool retval = GetQueue (queueNo)->Enqueue (item);
  if (retval)
    {
      swQueue->stats->tx_packets++;
      swQueue->stats->tx_bytes += item->GetPacketSize ();
    }
  else
    {
      NS_LOG_DEBUG ("Packet enqueue dropped by internal queue " << queueNo);
      swQueue->stats->tx_errors++;
      Drop (item);
    }
  return retval;
}

Ptr<QueueItem>
OFSwitch13Queue::DoDequeue (void)
{
  NS_LOG_FUNCTION (this);

  uint32_t qId = GetOutputQueue ();
  NS_LOG_DEBUG ("Packet dequeued from queue id " << qId);
  return GetQueue (qId)->Dequeue ();
}

Ptr<QueueItem>
OFSwitch13Queue::DoRemove (void)
{
  NS_LOG_FUNCTION (this);

  uint32_t qId = GetOutputQueue ();
  NS_LOG_DEBUG ("Packet removed from queue id " << qId);
  return GetQueue (qId)->Remove ();
}

Ptr<const QueueItem>
OFSwitch13Queue::DoPeek (void) const
{
  NS_LOG_FUNCTION (this);

  uint32_t qId = GetOutputQueue (true);
  NS_LOG_DEBUG ("Packet peeked from queue id " << qId);
  return GetQueue (qId)->Peek ();
}

uint32_t
OFSwitch13Queue::AddQueue (Ptr<Queue> queue)
{
  NS_LOG_FUNCTION (this << queue);

  NS_ASSERT_MSG (queue, "Invalid queue pointer.");
  NS_ASSERT_MSG (m_swPort, "Invalid OpenFlow port metadata.");

  uint32_t queueId = (m_swPort->num_queues)++;
  struct sw_queue *swQueue = &(m_swPort->queues[queueId]);
  NS_ASSERT_MSG (!swQueue->port, "Queue id already in use.");

  // Filling ofsoftswitch13 internal structures for this queue
  swQueue->port = m_swPort;
  swQueue->created = time_msec ();

  size_t oflQueueStatsSize = sizeof (struct ofl_queue_stats);
  swQueue->stats = (struct ofl_queue_stats*)xmalloc (oflQueueStatsSize);
  memset (swQueue->stats, 0x00, oflQueueStatsSize);
  swQueue->stats->port_no = m_swPort->conf->port_no;
  swQueue->stats->queue_id = queueId;

  size_t oflPacketQueueSize = sizeof (struct ofl_packet_queue);
  swQueue->props = (struct ofl_packet_queue*)xmalloc (oflPacketQueueSize);
  swQueue->props->queue_id = queueId;
  swQueue->props->properties_num = 0;

  // Inserting the ns3::Queue object into queue list.
  m_queues.push_back (queue);
  NS_LOG_DEBUG ("New queue with id " << queueId);

  return queueId;
}

Ptr<Queue>
OFSwitch13Queue::GetQueue (uint32_t queueId) const
{
  NS_ASSERT_MSG (queueId < GetNQueues (), "Queue is out of range.");
  return m_queues.at (queueId);
}

uint32_t
OFSwitch13Queue::GetOutputQueue (bool peekLock) const
{
  NS_LOG_FUNCTION (this << peekLock);

  static bool isLocked = false;
  static uint32_t queueId = 0;

  // If output queue is locked, we can't change its id.
  if (isLocked)
    {
      // If peekLock is false, unlock it before returning the queue id.
      if (!peekLock)
        {
          isLocked = false;
        }
      return queueId;
    }

  // If output queue is unlocked, let's select the higher-priority nonempty
  // queue. We use queue id as priority indicator (lowest priority id is 0).
  for (int32_t i = GetNQueues () - 1; i >= 0; i--)
    {
      // Check for nonempty queue
      if (GetQueue (i)->IsEmpty () == false)
        {
          queueId = i;
          break;
        }
    }

  // If peekLock is true, lock the output queue before returning it.
  if (peekLock)
    {
      isLocked = true;
    }

  return queueId;
}

} // namespace ns3

