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
 * Author: Vítor M. Eichemberger <vitor.marge@gmail.com>
 */

#ifndef OFSWITCH13_QUEUE_H
#define OFSWITCH13_QUEUE_H

#include <queue.h>
#include <drop-tail-queue.h>
#include "ns3/packet.h"
#include "ns3/queue.h"
#include "ns3/drop-tail-queue.h"

#define QUEUE_TYPE DropTailQueue

namespace ns3 {

/**
 * \ingroup ofswitch13
 *
 * The OpenFlow Queues, a set of queues, each on with its number.
 * This was implemented to solve the OpenFlow queues problem:
 * the OpenFlow requires a set of queues and not only one, but to transmit
 * by the ethernet (CsmaNetDevice class, in NS-3) there is only one queue.
 */
class OFSwitch13Queue : public Object
{
public:
  OFSwitch13Queue ();            //!< Default constructor
  virtual ~OFSwitch13Queue ();   //!< Dummy destructor, see DoDipose
  void DoDispose ();             //!< Destructor implementation

  void OFSwitch13Queue::SetQueueType (std::string queueType);
  
  /**
   * Add an OpenFoow queue.
   * \param queue The pointer to the new queue.
   * \param queueNo The queue number, used to index this queue.
   * \return true if the addition has succeeded, false otherwise.
   */
  bool AddQueue (uint32_t queueNo);
  
  bool OFSwitch13Queue::AddQueue (uint32_t queueNo, Object type);

  /**
   * Remove an OpenFoow queue.
   * \param queueNo The queue number, used to index this queue.
   * \return true if the remotion has succeeded, false otherwise.
   */
  bool RemoveQueue (uint32_t queueNo);
 
private:
  /**
   * Look for the queue with an specific number.
   * \param queueNo The queue number, used to index this queue.
   * \return A pointer to the queue, or NULL if not found.
   */
  Ptr< QUEUE_TYPE > OFSwitch13Queue::GetQueue (uint32_t queueNo)

  /**
   * Retrieves the queue number from the ? packettag.
   * \param ? ?
   * \return The queue number of this packet.
   */
  uint32_t OFSwitch13Queue::GetQueueNumberFromPackTag()

  /**
   * Enqueue a packet, within the queue whose number is inside the packettag
   * \param packet The packet you want to enqueue.
   * \return True if success, false otherwise.
   */
  bool OFSwitch13Queue::DoEnqueue (Ptr<Packet> packet)

  /**
   * Dequeue a packet, from the queue with the given number.
   * \param queueNo The queue number, used to index this queue.
   * \return The packet from the queue.
   */
  Ptr< Packet > OFSwitch13Queue::DoDequeue (uint32_t queueNo)

  /**
   * Peek the front packet in the queue with the given number.
   * \param queueNo The queue number, used to index this queue.
   * \return The packet.
   */
  Ptr< const Packet > OFSwitch13Queue::DoPeek (uint32_t queueNo)

  /** Structure to ave queues, indexed by queue id (queue number) */
  typedef std::map<uint32_t, Ptr<QUEUE_TYPE> > QueueMap_t;
  
  QueueMap_t                m_openflowQueues; //!< OpenFlow queues, indexed by id (queue number)
  ObjectFactory             m_queueFactory;   //!< Factory to generate the queues
};

} // namespace ns3
#endif /* OFSWITCH13_PORT_H */
