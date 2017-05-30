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
#ifndef OFSWITCH13_QUEUE_H
#define OFSWITCH13_QUEUE_H

#include <queue>
#include "ns3/packet.h"
#include "ns3/queue.h"
#include "ofswitch13-interface.h"
#include "queue-tag.h"

namespace ns3 {

/**
 * \ingroup ofswitch13
 *
 * \brief The OpenFlow 1.3 queue interface for simple QoS management. An
 * OpenFlow switch provides limited Quality-of-Service support (QoS) through a
 * simple queuing mechanism. One (or more) queues can attach to a port and be
 * used to map flow entries on it. Flow entries mapped to a specific queue will
 * be treated according to that queue's configuration. Queue configuration
 * takes place outside the OpenFlow protocol. This class implements the queue
 * interface, extending the ns3::Queue class to allow compatibility with the
 * CsmaNetDevice used by OFSwitch13Port. Internally, it holds a collection of N
 * priority queues, indentified by ids ranging from 0 to N in increasing
 * priority. The ns3::QueueTag is used to identify which internal queue will
 * hold the packet, and the priority algorithms decides from which queue get
 * the packets to send over the wire.
 */
class OFSwitch13Queue : public Queue
{
public:
  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);

  /**
   * Complete constructor.
   * \param port The the pointer to the ofsoftswitch13 internal port
   *        structure.
   */
  OFSwitch13Queue (struct sw_port *port);
  virtual ~OFSwitch13Queue ();  //!< Dummy destructor, see DoDispose.

  /**
   * Get the current number of queues.
   * \return The current number of queues.
   */
  uint32_t GetNQueues (void) const;

protected:
  /** Destructor implementation. */
  virtual void DoDispose ();

  // Inherited from ObjectBase.
  virtual void NotifyConstructionCompleted (void);

private:
  // Inherited from Queue.
  virtual bool DoEnqueue (Ptr<QueueItem> item);
  virtual Ptr<QueueItem> DoDequeue (void);
  virtual Ptr<QueueItem> DoRemove (void);
  virtual Ptr<const QueueItem> DoPeek (void) const;

  /**
   * Add a new internal queue to this OpenFlow queue.
   * \param queue The queue pointer.
   * \return The queue id for the new queue.
   */
  uint32_t AddQueue (Ptr<Queue> queue);

  /**
   * Get a pointer to internal queue with specific id.
   * \param queueId The queue id.
   * \return The queue pointer.
   * \internal This function is marked as const to allow its usage inside
   *           DoPeek () member function.
   */
  Ptr<Queue> GetQueue (uint32_t queueId) const;

  /**
   * Return the queue id that will be used by DoPeek, DoDequeue, and DoRemove
   * functions based on priority output algorithm.
   * \internal This function has to keep consistence in its queue decision
   *           despite arbitrary calls from peek and dequeue functions. When a
   *           peek operation is performed, a output queue must be selected and
   *           has to remain the same until the packet is effectively dequeued
   *           or removed from it.
   * \param peekLock Get the output queue and lock it.
   * \return The queue id.
   */
  uint32_t GetOutputQueue (bool peekLock = false) const;

  /** Structure to save the list of internal queues in this port queue. */
  typedef std::vector<Ptr<Queue> > QueueList_t;

  struct sw_port*       m_swPort;     //!< ofsoftswitch13 struct sw_port.
  uint32_t              m_intQueues;  //!< The number of internal queues.
  QueueList_t           m_queues;     //!< Sorted list of available queues.
};

} // namespace ns3
#endif /* OFSWITCH13_QUEUE_H */
