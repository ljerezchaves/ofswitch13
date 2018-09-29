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

#include "tunnel-id-tag.h"
#include <ns3/log.h>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("TunnelIdTag");
NS_OBJECT_ENSURE_REGISTERED (TunnelIdTag);

TunnelIdTag::TunnelIdTag ()
  : m_tunnelId (0)
{
}

TunnelIdTag::TunnelIdTag (uint64_t id)
  : m_tunnelId (id)
{
}

TypeId
TunnelIdTag::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::TunnelIdTag")
    .SetParent<Tag> ()
    .SetGroupName ("OFSwitch13")
    .AddConstructor<TunnelIdTag> ()
  ;
  return tid;
}

TypeId
TunnelIdTag::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

void
TunnelIdTag::SetTunnelId (uint64_t id)
{
  m_tunnelId = id;
}

uint64_t
TunnelIdTag::GetTunnelId (void) const
{
  return m_tunnelId;
}

uint32_t
TunnelIdTag::GetSerializedSize (void) const
{
  return 8;
}

void
TunnelIdTag::Serialize (TagBuffer i) const
{
  i.WriteU64 (m_tunnelId);
}

void
TunnelIdTag::Deserialize (TagBuffer i)
{
  m_tunnelId = i.ReadU64 ();
}

void
TunnelIdTag::Print (std::ostream &os) const
{
  os << " TunnelIdTag id=" << m_tunnelId;
}

} // namespace ns3
