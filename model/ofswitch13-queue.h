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

#include <ns3/packet.h>
#include <ns3/queue.h>
#include "ofswitch13-interface.h"
#include "queue-tag.h"

namespace ns3 {

// The following explicit template instantiation declaration prevents modules
// including this header file from implicitly instantiating Queue<Packet>.
extern template class Queue<Packet>;

/**
 * \ingroup ofswitch13
 *
 * \brief The OpenFlow 1.3 queue interface for simple QoS management. An
 * OpenFlow switch provides limited Quality-of-Service support (QoS) through a
 * simple queuing mechanism. One (or more) queues can attach to a port and be
 * used to map flow entries on it. Flow entries mapped to a specific queue
 * will be treated according to that queue's configuration. Queue configuration
 * takes place outside the OpenFlow protocol. This class implements the queue
 * interface, extending the ns3::Queue class to allow compatibility with the
 * CsmaNetDevice used by OFSwitch13Port. Internally, it can hold a collection
 * of N priority queues, identified by IDs ranging from 0 to N with decreasing
 * priority (queue ID 0 has the highest priority). The ns3::QueueTag is used to
 * identify which internal queue will hold the packet, and the priority
 * algorithms ensures that higher-priority queues are "always" get serviced
 * first.
 */
class OFSwitch13Queue : public Queue<Packet>
{
public:
  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);

  /**
   * Complete constructor.
   * \param port The pointer to the ofsoftswitch13 internal port structure.
   */
  OFSwitch13Queue (struct sw_port *port);
  virtual ~OFSwitch13Queue ();  //!< Dummy destructor, see DoDispose.

  // Inherited from Queue.
  bool Enqueue (Ptr<Packet> packet);
  Ptr<Packet> Dequeue (void);
  Ptr<Packet> Remove (void);
  Ptr<const Packet> Peek (void) const;

  /**
   * Get the number of internal queues.
   * \return The number of internal queues.
   */
  int GetNQueues (void) const;

protected:
  /** Destructor implementation. */
  virtual void DoDispose ();

  // Inherited from ObjectBase.
  virtual void NotifyConstructionCompleted (void);

private:
  /**
   * Add a new internal queue to this OpenFlow queue interface.
   * \param queue The queue pointer.
   * \return The ID for this new internal queue.
   */
  uint32_t AddQueue (Ptr<Queue<Packet> > queue);

  /**
   * Get a pointer to internal queue with specific id.
   * \param queueId The queue id.
   * \return The queue pointer.
   * \internal This function is marked as const to allow its usage inside
   *           DoPeek () member function.
   */
  Ptr<Queue<Packet> > GetQueue (int queueId) const;

  /** Structure to save the list of internal queues in this queue interface. */
  typedef std::vector<Ptr<Queue> > QueueList_t;

  struct sw_port*       m_swPort;     //!< ofsoftswitch13 port structure.
  ObjectFactory         m_qFactory;   //!< Factory for internal queues.
  int                   m_intQueues;  //!< Number of internal queues.
  QueueList_t           m_queues;     //!< List of internal queues.

  NS_LOG_TEMPLATE_DECLARE;            //!< Redefinition of the log component.
};

} // namespace ns3
#endif /* OFSWITCH13_QUEUE_H */
