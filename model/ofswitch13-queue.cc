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
#include "ns3/string.h"
#include "ns3/uinteger.h"
#include "ns3/object-vector.h"
#include "ofswitch13-queue.h"
#include <algorithm>

#undef NS_LOG_APPEND_CONTEXT
#define NS_LOG_APPEND_CONTEXT                                   \
  if (m_swPort != 0)                                            \
    {                                                           \
      std::clog << "[dp " << m_swPort->dp->id                   \
                << " port " << m_swPort->conf->port_no << "] "; \
    }

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Queue");
NS_OBJECT_ENSURE_REGISTERED (OFSwitch13Queue);

ObjectFactory
GetDefaultQueueFactory ()
{
  // Setting default internal queue configuration.
  ObjectFactory queueFactory;
  queueFactory.SetTypeId ("ns3::DropTailQueue<Packet>");
  queueFactory.Set ("MaxSize", StringValue ("100p"));
  return queueFactory;
}

TypeId
OFSwitch13Queue::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OFSwitch13Queue")
    .SetParent<Queue<Packet> > ()
    .SetGroupName ("OFSwitch13")
    .AddAttribute ("NumQueues",
                   "The number of internal queues available on this queue.",
                   TypeId::ATTR_GET | TypeId::ATTR_CONSTRUCT,
                   UintegerValue (NETDEV_MAX_QUEUES),
                   MakeUintegerAccessor (&OFSwitch13Queue::m_intQueues),
                   MakeUintegerChecker<uint32_t> (1, NETDEV_MAX_QUEUES))
    .AddAttribute ("QueueFactory",
                   "The object factory for creating internal queues.",
                   TypeId::ATTR_GET | TypeId::ATTR_CONSTRUCT,
                   ObjectFactoryValue (GetDefaultQueueFactory ()),
                   MakeObjectFactoryAccessor (&OFSwitch13Queue::m_qFactory),
                   MakeObjectFactoryChecker ())
    .AddAttribute ("QueueList",
                   "The list of internal queues available to the port.",
                   ObjectVectorValue (),
                   MakeObjectVectorAccessor (&OFSwitch13Queue::m_queues),
                   MakeObjectVectorChecker<Queue<Packet> > ())
  ;
  return tid;
}

OFSwitch13Queue::OFSwitch13Queue (struct sw_port *port)
  : Queue<Packet> (),
  m_swPort (port),
  NS_LOG_TEMPLATE_DEFINE ("OFSwitch13Queue")
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
  SetAttribute ("MaxSize", StringValue ("100Mp"));

  // Creating the internal queues, defined by the NumQueues attribute.
  for (uint32_t i = 0; i < GetNQueues (); i++)
    {
      AddQueue (m_qFactory.Create<Queue<Packet> > ());
    }

  // Chain up.
  Queue<Packet>::NotifyConstructionCompleted ();
}

bool
OFSwitch13Queue::Enqueue (Ptr<Packet> packet)
{
  NS_LOG_FUNCTION (this << packet);

  QueueTag queueNoTag;
  packet->PeekPacketTag (queueNoTag);
  uint32_t queueNo = queueNoTag.GetQueueId ();
  NS_ASSERT_MSG (queueNo < GetNQueues (), "Queue id is out of range.");
  NS_LOG_DEBUG ("Packet " << packet << " to be enqueued in queue id " << queueNo);

  struct sw_queue *swQueue;
  swQueue = dp_ports_lookup_queue (m_swPort, queueNo);
  NS_ASSERT_MSG (swQueue, "Invalid queue id.");

  bool retval = GetQueue (queueNo)->Enqueue (packet);
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
      NS_LOG_DEBUG ("Packet enqueue dropped by internal queue " << queueNo);
      swQueue->stats->tx_errors++;

      // Drop the packet in this queue too.
      // This is necessary to ensure consistent statistics.
      DropBeforeEnqueue (packet);
    }
  return retval;
}

Ptr<Packet>
OFSwitch13Queue::Dequeue (void)
{
  NS_LOG_FUNCTION (this);

  for (uint32_t i = 0; i < GetNQueues (); i++)
    {
      if (GetQueue (i)->IsEmpty () == false)
        {
          NS_LOG_DEBUG ("Packet dequeued from queue id " << i);
          Ptr<Packet> p = GetQueue (i)->Dequeue ();

          // Dequeue the packet from this queue too. As we don't know the
          // exactly packet location on this queue, we have to look for it.
          for (auto it = Head (); it != Tail (); it++)
            {
              if ((*it) == p)
                {
                  DoDequeue (it);
                  return p;
                }
            }

          NS_LOG_WARN ("Packet " << p << " was not found on this queue.");
          return p;
        }
    }

  NS_LOG_DEBUG ("Queue empty");
  return 0;
}

Ptr<Packet>
OFSwitch13Queue::Remove (void)
{
  NS_LOG_FUNCTION (this);

  for (uint32_t i = 0; i < GetNQueues (); i++)
    {
      if (GetQueue (i)->IsEmpty () == false)
        {
          NS_LOG_DEBUG ("Packet removed from queue id " << i);
          Ptr<Packet> p = GetQueue (i)->Remove ();

          // Remove the packet from this queue too. As we don't know the
          // exactly packet location on this queue, we have to look for it.
          for (auto it = Head (); it != Tail (); it++)
            {
              if ((*it) == p)
                {
                  DoDequeue (it);
                  return p;
                }
            }

          NS_LOG_WARN ("Packet " << p << " was not found on this queue.");
          return p;
        }
    }

  NS_LOG_DEBUG ("Queue empty");
  return 0;
}

Ptr<const Packet>
OFSwitch13Queue::Peek (void) const
{
  NS_LOG_FUNCTION (this);

  for (uint32_t i = 0; i < GetNQueues (); i++)
    {
      if (GetQueue (i)->IsEmpty () == false)
        {
          NS_LOG_DEBUG ("Packet peeked from queue id " << i);
          return GetQueue (i)->Peek ();
        }
    }

  NS_LOG_DEBUG ("Queue empty");
  return 0;
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
  NS_LOG_DEBUG ("New queue with id " << queueId);

  return queueId;
}

Ptr<Queue<Packet> >
OFSwitch13Queue::GetQueue (uint32_t queueId) const
{
  return m_queues.at (queueId);
}

} // namespace ns3
