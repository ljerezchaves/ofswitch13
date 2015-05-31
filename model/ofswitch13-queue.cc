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

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Queue");
NS_OBJECT_ENSURE_REGISTERED (OFSwitch13Queue);

OFSwitch13Queue::OFSwitch13Queue ()
{
  NS_LOG_FUNCTION (this);
  
  m_queueFactory.SetTypeId ("ns3::DropTailQueue");
  if(!AddQueue (0, DropTailQueue))
  {
     NS_FATAL_ERROR ("Can't create the default OpenFlow queue.");
  }
}

OFSwitch13Queue::~OFSwitch13Queue ()
{
  NS_LOG_FUNCTION (this);
}

void
OFSwitch13Queue::DoDispose ()
{
  for (QueueMap_t::iterator it = m_openflowQueues.begin(); it != m_openflowQueues.end(); ++it)
  {
     free(it->second);
  }
}

void
OFSwitch13Queue::SetQueueType (std::string queueType)
{
	m_queueFactory.SetTypeId (queueType);
}

bool
OFSwitch13Queue::AddQueue (uint32_t queueNo)
{
  Queue queue = m_queueFactory.Create ();
  NS_LOG_DEBUG (this << queueNo << queue);

  std::pair<uint32_t, Ptr< QUEUE_TYPE > > entry (queueNo, queue);
  return m_openflowQueues.insert (entry).second;
}

bool
OFSwitch13Queue::AddQueue (uint32_t queueNo, Object type)
{
  Queue queue = m_queueFactory.Create<type> ();
  NS_LOG_DEBUG (this << queueNo << queue);

  std::pair<uint32_t, Ptr< QUEUE_TYPE > > entry (queueNo, queue);
  return m_openflowQueues.insert (entry).second;
}

bool
OFSwitch13Queue::RemoveQueue (uint32_t queueNo)
{
  NS_LOG_DEBUG (this << queueNo);

  return m_openflowQueues.erase (queueNo);
}

Ptr< QUEUE_TYPE >
OFSwitch13Queue::GetQueue (uint32_t queueNo)
{
  NS_LOG_DEBUG (this << queueNo);
  QueueMap_t::iterator it;
  
  it = m_openflowQueues.find (queueNo);
  if (it == m_openflowQueues.end ())
    {
      //NS_LOG_ERROR ("No available queue with the given number.");
      return NULL;
    }
  
  Ptr< QUEUE_TYPE > queue = it->second;
  return queue;
}

//TODO
uint32_t
OFSwitch13Queue::GetQueueNumberFromPackTag()
{
  // Pegar o numero do pacote pela PacketTag
  return 0;
}

bool
OFSwitch13Queue::DoEnqueue (Ptr<Packet> packet)
{
  uint32_t queueNo = GetQueueNumberFromPackTag();
  Ptr< QUEUE_TYPE > queue = GetQueue (queueNo);
  
  NS_LOG_DEBUG (this << queueNo << queue);
  
  if(!queue)
  {
     return false;
  }
  
  return queue->Enqueue (packet);
}

Ptr< Packet >
OFSwitch13Queue::DoDequeue (uint32_t queueNo)
{
  Ptr< QUEUE_TYPE > queue = GetQueue (queueNo);
  
  NS_LOG_DEBUG (this << queueNo << queue);
  
  if(!queue)
  {
     return NULL;
  }
  
  return queue->Dequeue ();
}

Ptr< const Packet >
OFSwitch13Queue::DoPeek (uint32_t queueNo)
{
  Ptr< QUEUE_TYPE > queue = GetQueue (queueNo);
  
  NS_LOG_DEBUG (this << queueNo << queue);
  
  if(!queue)
  {
     return false;
  }
  
  return queue->Peek ();
}

} // namespace ns3