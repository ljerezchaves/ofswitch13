/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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

#ifdef NS3_OFSWITCH13

#include "ofswitch13-controller.h"
#include "ofswitch13-net-device.h"

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Controller");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (OFSwitch13Controller)
  ;

OFSwitch13Controller::OFSwitch13Controller ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

OFSwitch13Controller::~OFSwitch13Controller ()
{
  NS_LOG_FUNCTION_NOARGS ();
}


void
OFSwitch13Controller::DoDispose ()
{
  m_switches.clear ();
}

TypeId 
OFSwitch13Controller::GetTypeId (void) 
{
  static TypeId tid = TypeId ("ns3::OFSwitch13Controller") 
    .SetParent<Object> ()
    .AddConstructor<OFSwitch13Controller> ()
    ;
  return tid; 
}
void
OFSwitch13Controller::AddSwitch (Ptr<OFSwitch13NetDevice> swtch)
{
  if (m_switches.find (swtch) != m_switches.end ())
    {
      NS_LOG_INFO ("This Controller has already registered this switch!");
    }
  else
    {
      NS_LOG_INFO ("Registering switch " << swtch << " at controller " << this);
      m_switches.insert (swtch);
    }
}


void
OFSwitch13Controller::SendToSwitch (Ptr<OFSwitch13NetDevice> swtch, void * msg, size_t length)
{
  if (m_switches.find (swtch) == m_switches.end ())
    {
      NS_LOG_ERROR ("Can't send to this switch, not registered to the Controller.");
      return;
    }

 // swtch->ForwardControlInput (msg, length);
}


uint8_t
OFSwitch13Controller::GetPacketType (ofpbuf* buffer)
{
  ofp_header* hdr = (ofp_header*)ofpbuf_try_pull (buffer, sizeof (ofp_header));
  uint8_t type = hdr->type;
  ofpbuf_push_uninit (buffer, sizeof (ofp_header));
  return type;
}



} // namespace ns3
#endif // NS3_OFSWITCH13
