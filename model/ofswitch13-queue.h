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

namespace ns3 {

// The following explicit template instantiation declaration prevents modules
// including this header file from implicitly instantiating Queue<Packet>.
extern template class Queue<Packet>;

/**
 * \ingroup ofswitch13
 * \brief The OpenFlow 1.3 queue interface.
 *
 * An OpenFlow switch provides limited Quality-of-Service support (QoS) through
 * a simple queuing mechanism. One (or more) queues can attach to a port and be
 * used to map flow entries on it. Flow entries mapped to a specific queue will
 * be treated according to that queue's configuration. Queue configuration
 * takes place outside the OpenFlow protocol.
 *
 * This class implements the queue interface, extending the ns3::Queue<Packet>
 * class to allow compatibility with the CsmaNetDevice used by OFSwitch13Port.
 * Internally, it holds a collection of N (possibly different) queues,
 * identified by IDs ranging from 0 to N-1. The Enqueue () method uses the
 * ns3::QueueTag to identify which internal queue will hold the packet.
 * Subclasses can perform different output scheduling algorithms by
 * implementing the Dequeue (), Remove () and Peek () methods, always calling
 * the NotifyDequeue () and NotifyRemoved () methods from this base class to
 * keep consistency.
 */
class OFSwitch13Queue : public Queue<Packet>
{
public:
  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);

  OFSwitch13Queue ();           //!< Default constructor.
  virtual ~OFSwitch13Queue ();  //!< Dummy destructor, see DoDispose.

  // Inherited from Queue.
  bool Enqueue (Ptr<Packet> packet);

  /**
   * Get the number of internal queues.
   * \return The number of internal queues.
   */
  int GetNQueues (void) const;

  /**
   * Get a pointer to internal queue with specific id.
   * \param queueId The queue id.
   * \return The queue pointer.
   * \internal This function is marked as const to allow its usage inside
   *           DoPeek () member function.
   */
  Ptr<Queue<Packet> > GetQueue (int queueId) const;

  /**
   * Set the pointer to the internal ofsoftswitch13 port structure.
   * \param port The port structure pointer.
   */
  void SetPortStruct (struct sw_port *port);

protected:
  /** Destructor implementation. */
  virtual void DoDispose ();

  // Inherited from Object.
  virtual void DoInitialize (void);

  // Inherited from ObjectBase.
  virtual void NotifyConstructionCompleted (void);

  /**
   * Add a new internal queue to this OpenFlow queue interface.
   * \param queue The queue pointer.
   * \return The ID for this new internal queue.
   */
  uint32_t AddQueue (Ptr<Queue<Packet> > queue);

  /**
   * Notify the parent class of a packet dequeued from any internal queue.
   * \param packet The packet.
   */
  void NotifyDequeue (Ptr<Packet> packet);

  /**
   * Notify the parent class of a packet removed from any internal queue.
   * \param packet The packet.
   */
  void NotifyRemove (Ptr<Packet> packet);

  // Values used for logging context.
  uint64_t              m_dpId;       //!< OpenFlow datapath ID.
  uint32_t              m_portNo;     //!< OpenFlow port number.

private:
  /** Structure to save the list of internal queues in this queue interface. */
  typedef std::vector<Ptr<Queue> > QueueList_t;

  struct sw_port*       m_swPort;     //!< ofsoftswitch13 port structure.
  QueueList_t           m_queues;     //!< List of internal queues.

  NS_LOG_TEMPLATE_DECLARE;            //!< Redefinition of the log component.
};

} // namespace ns3
#endif /* OFSWITCH13_QUEUE_H */
