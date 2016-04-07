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
    .AddAttribute ("QueueList",
                   "The list of internal queues associated to this port queue.",
                   ObjectVectorValue (),
                   MakeObjectVectorAccessor (&OFSwitch13Queue::m_queues),
                   MakeObjectVectorChecker<Queue> ())
    .AddAttribute ("Scheduling",
                   "The output queue scheduling algorithm.",
                   EnumValue (OFSwitch13Queue::PRIO),
                   MakeEnumAccessor (&OFSwitch13Queue::m_scheduling),
                   MakeEnumChecker (OFSwitch13Queue::PRIO, "prio"))
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

  // Adding the default ns3::DropTailQueue with id 0 for best-effort traffic.
  uint32_t id = AddQueue (CreateObject<DropTailQueue> ());
  NS_LOG_DEBUG ("New queue " << id << " at port " << m_swPort->conf->port_no);
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

uint16_t
OFSwitch13Queue::GetMaxQueues (void)
{
  return m_maxQueues;
}

uint16_t
OFSwitch13Queue::GetNQueues (void) const
{
  return m_queues.size ();
}

uint32_t
OFSwitch13Queue::AddQueue (Ptr<Queue> queue)
{
  NS_LOG_FUNCTION (this << queue);

  NS_ASSERT_MSG (queue, "Invalid queue pointer.");
  NS_ASSERT_MSG (m_swPort, "Invalid OpenFlow port metadata.");
  NS_ASSERT_MSG (GetNQueues () < GetMaxQueues (), "No more queues available.");

  uint32_t queueId = (m_swPort->num_queues)++;
  sw_queue* swQueue = &(m_swPort->queues[queueId]);
  NS_ASSERT_MSG (!swQueue->port, "Queue id already in use.");

  // Filling ofsoftswitch13 internal structures for this queue
  swQueue->port = m_swPort;
  swQueue->created = time_msec ();

  swQueue->stats = (ofl_queue_stats*)xmalloc (sizeof (ofl_queue_stats));
  memset (swQueue->stats, 0x00, sizeof (ofl_queue_stats));
  swQueue->stats->port_no = m_swPort->conf->port_no;
  swQueue->stats->queue_id = queueId;

  swQueue->props =
    (ofl_packet_queue*)xmalloc (sizeof (struct ofl_packet_queue));
  swQueue->props->queue_id = queueId;
  swQueue->props->properties_num = 0;

  // Inserting the ns3::Queue object into queue list.
  m_queues.push_back (queue);

  return queueId;
}

Ptr<Queue>
OFSwitch13Queue::GetQueue (uint32_t queueId) const
{
  NS_ASSERT_MSG (queueId < GetNQueues (), "Queue is out of range.");
  return m_queues.at (queueId);
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
      Drop (p);
      return false;
    }
}

Ptr<Packet>
OFSwitch13Queue::DoDequeue (void)
{
  NS_LOG_FUNCTION (this);

  uint32_t qId = GetOutputQueue (false);
  NS_LOG_DEBUG ("Packet dequeued from queue no " << qId);
  return GetQueue (qId)->Dequeue ();
}

Ptr<const Packet>
OFSwitch13Queue::DoPeek (void) const
{
  NS_LOG_FUNCTION (this);

  uint32_t qId = GetOutputQueue (true);
  NS_LOG_DEBUG ("Packet peek from queue no " << qId);
  return GetQueue (qId)->Peek ();
}

uint32_t
OFSwitch13Queue::GetOutputQueue (bool peekLock) const
{
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

  // If output queue is unlocked, let's select the queue based on output queue
  // scheduling algorithm.
  if (m_scheduling == OFSwitch13Queue::PRIO)
    {
      // For priority queuing, select the higher-priority nonempty queue.
      // We use the queue id as priority indicator (lowest priority id is 0).
      for (uint32_t i = GetNQueues () - 1; i >= 0; i--)
        {
          // Check for nonempty queue
          if (GetQueue (i)->IsEmpty () == false)
            {
              queueId = i;
              break;
            }
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

