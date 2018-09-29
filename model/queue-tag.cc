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

#include "queue-tag.h"
#include <ns3/log.h>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QueueTag");
NS_OBJECT_ENSURE_REGISTERED (QueueTag);

QueueTag::QueueTag ()
  : m_queueId (0)
{
}

QueueTag::QueueTag (uint32_t id)
  : m_queueId (id)
{
}

TypeId
QueueTag::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QueueTag")
    .SetParent<Tag> ()
    .SetGroupName ("OFSwitch13")
    .AddConstructor<QueueTag> ()
  ;
  return tid;
}

TypeId
QueueTag::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

void
QueueTag::SetQueueId (uint32_t id)
{
  m_queueId = id;
}

uint32_t
QueueTag::GetQueueId (void) const
{
  return m_queueId;
}

uint32_t
QueueTag::GetSerializedSize (void) const
{
  return 4;
}

void
QueueTag::Serialize (TagBuffer i) const
{
  i.WriteU32 (m_queueId);
}

void
QueueTag::Deserialize (TagBuffer i)
{
  m_queueId = i.ReadU32 ();
}

void
QueueTag::Print (std::ostream &os) const
{
  os << " QueueTag id=" << m_queueId;
}

} // namespace ns3
