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
#include "ns3/string.h"
#include "ns3/object-vector.h"
#include "ofswitch13-queue.h"
#include "queue-tag.h"

#undef NS_LOG_APPEND_CONTEXT
#define NS_LOG_APPEND_CONTEXT \
  std::clog << "[dp " << m_dpId << " port " << m_portNo << "] ";

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Queue");
NS_OBJECT_ENSURE_REGISTERED (OFSwitch13Queue);

TypeId
OFSwitch13Queue::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OFSwitch13Queue")
    .SetParent<Queue<Packet> > ()
    .SetGroupName ("OFSwitch13")
    .AddAttribute ("QueueList",
                   "The list of internal queues.",
                   ObjectVectorValue (),
                   MakeObjectVectorAccessor (&OFSwitch13Queue::m_queues),
                   MakeObjectVectorChecker<Queue<Packet> > ())
  ;
  return tid;
}

OFSwitch13Queue::OFSwitch13Queue ()
  : Queue<Packet> (),
  m_dpId (0),
  m_portNo (0),
  m_swPort (0),
  NS_LOG_TEMPLATE_DEFINE ("OFSwitch13Queue")
{
  NS_LOG_FUNCTION (this);
}

OFSwitch13Queue::~OFSwitch13Queue ()
{
  NS_LOG_FUNCTION (this);
}

bool
OFSwitch13Queue::Enqueue (Ptr<Packet> packet)
{
  NS_LOG_FUNCTION (this << packet);

  QueueTag queueTag;
  packet->PeekPacketTag (queueTag);
  int queueId = static_cast<int> (queueTag.GetQueueId ());
  NS_ASSERT_MSG (queueId < GetNQueues (), "Queue ID is out of range.");
  NS_LOG_DEBUG ("Packet to be enqueued in queue " << queueId);

  struct sw_queue *swQueue;
  swQueue = dp_ports_lookup_queue (m_swPort, queueId);
  NS_ASSERT_MSG (swQueue, "Invalid queue id.");

  bool retval = GetQueue (queueId)->Enqueue (packet);
  if (retval)
    {
      swQueue->stats->tx_packets++;
      swQueue->stats->tx_bytes += packet->GetSize ();

      // Enqueue the packet in this queue too.
      // This is necessary to ensure consistent statistics. Otherwise, when the
      // NetDevice calls the IsEmpty () method, it will return true.
      DoEnqueue (Tail (), packet);
    }
  else
    {
      NS_LOG_DEBUG ("Packet enqueue dropped by internal queue " << queueId);
      swQueue->stats->tx_errors++;

      // Drop the packet in this queue too.
      // This is necessary to ensure consistent statistics.
      DropBeforeEnqueue (packet);
    }
  return retval;
}

int
OFSwitch13Queue::GetNQueues (void) const
{
  return m_queues.size ();
}

Ptr<Queue<Packet> >
OFSwitch13Queue::GetQueue (int queueId) const
{
  return m_queues.at (queueId);
}

void
OFSwitch13Queue::SetPortStruct (struct sw_port *port)
{
  NS_LOG_FUNCTION (this << port);

  m_swPort = port;
  m_dpId = port->dp->id;
  m_portNo = port->conf->port_no;
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
      for (int queueId = 0; queueId < GetNQueues (); queueId++)
        {
          swQueue = &(m_swPort->queues[queueId]);
          free (swQueue->stats);
          free (swQueue->props);
        }
      m_swPort = 0;
    }
  m_queues.clear ();

  // Chain up.
  Queue<Packet>::DoDispose ();
}

void
OFSwitch13Queue::DoInitialize ()
{
  NS_LOG_FUNCTION (this);

  // Chain up.
  Queue<Packet>::DoInitialize ();
}

void
OFSwitch13Queue::NotifyConstructionCompleted (void)
{
  NS_LOG_FUNCTION (this);

  // We are using a very large queue size for this queue interface. The real
  // check for queue space is performed at DoEnqueue () by the internal queues.
  SetAttribute ("MaxSize", StringValue ("100Mp"));

  // Chain up.
  Queue<Packet>::NotifyConstructionCompleted ();
}

uint32_t
OFSwitch13Queue::AddQueue (Ptr<Queue<Packet> > queue)
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
  NS_LOG_DEBUG ("New queue with ID " << queueId);

  return queueId;
}

void
OFSwitch13Queue::NotifyDequeue (Ptr<Packet> packet)
{
  NS_LOG_FUNCTION (this << packet);

  // Dequeue the packet from this queue too. As we don't know the
  // exactly packet location on this queue, we have to look for it.
  for (auto it = Head (); it != Tail (); it++)
    {
      if ((*it) == packet)
        {
          DoDequeue (it);
          return;
        }
    }
  NS_LOG_WARN ("Packet was not found on this queue.");
}

void
OFSwitch13Queue::NotifyRemove (Ptr<Packet> packet)
{
  NS_LOG_FUNCTION (this << packet);

  // Remove the packet from this queue too. As we don't know the
  // exactly packet location on this queue, we have to look for it.
  for (auto it = Head (); it != Tail (); it++)
    {
      if ((*it) == packet)
        {
          DoRemove (it);
          return;
        }
    }
  NS_LOG_WARN ("Packet was not found on this queue.");
}

} // namespace ns3
