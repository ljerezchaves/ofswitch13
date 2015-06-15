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
#include "ns3/uinteger.h"
#include "ofswitch13-queue.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Queue");
NS_OBJECT_ENSURE_REGISTERED (OFSwitch13Queue);

TypeId OFSwitch13Queue::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OFSwitch13Queue")
    .SetParent<Queue> ()
    .SetGroupName ("OFswitch13")
    .AddConstructor<OFSwitch13Queue> ()
    .AddAttribute ("Mode",
                   "Whether to use bytes (see MaxBytes) or packets "
                   "(see MaxPackets) as the maximum queue size metric.",
                   EnumValue (QUEUE_MODE_PACKETS),
                   MakeEnumAccessor (&OFSwitch13Queue::SetMode),
                   MakeEnumChecker (QUEUE_MODE_BYTES, "QUEUE_MODE_BYTES",
                                    QUEUE_MODE_PACKETS, "QUEUE_MODE_PACKETS"))
    .AddAttribute ("MaxPackets",
                   "The maximum number of packets accepted by this OFSwitch13Queue.",
                   UintegerValue (100),
                   MakeUintegerAccessor (&OFSwitch13Queue::m_maxPackets),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxBytes",
                   "The maximum number of bytes accepted by this OFSwitch13Queue.",
                   UintegerValue (100 * 65535),
                   MakeUintegerAccessor (&OFSwitch13Queue::m_maxBytes),
                   MakeUintegerChecker<uint32_t> ())
  ;
  return tid;
}

OFSwitch13Queue::OFSwitch13Queue ()
  : Queue (),
    m_packets (),
    m_bytesInQueue (0)
{
  NS_LOG_FUNCTION (this);
}

OFSwitch13Queue::~OFSwitch13Queue ()
{
  NS_LOG_FUNCTION (this);
}

void
OFSwitch13Queue::SetMode (Queue::QueueMode mode)
{
  NS_LOG_FUNCTION (this << mode);
  m_mode = mode;
}

Queue::QueueMode
OFSwitch13Queue::GetMode (void)
{
  NS_LOG_FUNCTION (this);
  return m_mode;
}

bool
OFSwitch13Queue::DoEnqueue (Ptr<Packet> p)
{
  NS_LOG_FUNCTION (this << p);

  if (m_mode == QUEUE_MODE_PACKETS && (m_packets.size () >= m_maxPackets))
    {
      NS_LOG_LOGIC ("Queue full (at max packets) -- droppping pkt");
      Drop (p);
      return false;
    }

  if (m_mode == QUEUE_MODE_BYTES && (m_bytesInQueue + p->GetSize () >= m_maxBytes))
    {
      NS_LOG_LOGIC ("Queue full (packet would exceed max bytes) -- droppping pkt");
      Drop (p);
      return false;
    }

  m_bytesInQueue += p->GetSize ();
  m_packets.push (p);

  NS_LOG_LOGIC ("Number packets " << m_packets.size ());
  NS_LOG_LOGIC ("Number bytes " << m_bytesInQueue);

  return true;
}

Ptr<Packet>
OFSwitch13Queue::DoDequeue (void)
{
  NS_LOG_FUNCTION (this);

  if (m_packets.empty ())
    {
      NS_LOG_LOGIC ("Queue empty");
      return 0;
    }

  Ptr<Packet> p = m_packets.front ();
  m_packets.pop ();
  m_bytesInQueue -= p->GetSize ();

  NS_LOG_LOGIC ("Popped " << p);

  NS_LOG_LOGIC ("Number packets " << m_packets.size ());
  NS_LOG_LOGIC ("Number bytes " << m_bytesInQueue);

  return p;
}

Ptr<const Packet>
OFSwitch13Queue::DoPeek (void) const
{
  NS_LOG_FUNCTION (this);

  if (m_packets.empty ())
    {
      NS_LOG_LOGIC ("Queue empty");
      return 0;
    }

  Ptr<Packet> p = m_packets.front ();

  NS_LOG_LOGIC ("Number packets " << m_packets.size ());
  NS_LOG_LOGIC ("Number bytes " << m_bytesInQueue);

  return p;
}

} // namespace ns3

