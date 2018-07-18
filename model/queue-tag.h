/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
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

#ifndef QUEUE_TAG_H
#define QUEUE_TAG_H

#include <ns3/tag.h>

namespace ns3 {

class Tag;

/**
 * \ingroup ofswitch13
 * Tag used to hold the queue id before enqueueing a packet into
 * OFSwitch13Queue.
 */
class QueueTag : public Tag
{
public:
  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);
  virtual TypeId GetInstanceTypeId (void) const;

  QueueTag ();            //!< Default constructor

  /**
   * Complete constructor.
   * \param id The queue id.
   */
  QueueTag (uint32_t id);

  /**
   * Set the internal queue id.
   * \param id The queue id.
   */
  void SetQueueId (uint32_t id);

  /** \return The queue id */
  uint32_t GetQueueId (void) const;

  // Inherited from Tag
  virtual void Serialize (TagBuffer i) const;
  virtual void Deserialize (TagBuffer i);
  virtual uint32_t GetSerializedSize () const;
  virtual void Print (std::ostream &os) const;

private:
  uint32_t m_queueId;   //!< Packet sequence number
};

} // namespace ns3
#endif // QUEUE_TAG_H

