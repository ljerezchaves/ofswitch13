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

#include "ofswitch13-device-container.h"
#include <ns3/names.h>

namespace ns3 {

OFSwitch13DeviceContainer::OFSwitch13DeviceContainer ()
{
}

OFSwitch13DeviceContainer::OFSwitch13DeviceContainer (
  Ptr<OFSwitch13Device> dev)
{
  m_devices.push_back (dev);
}

OFSwitch13DeviceContainer::OFSwitch13DeviceContainer (std::string devName)
{
  Ptr<OFSwitch13Device> dev = Names::Find<OFSwitch13Device> (devName);
  m_devices.push_back (dev);
}

OFSwitch13DeviceContainer::OFSwitch13DeviceContainer (
  const OFSwitch13DeviceContainer &a, const OFSwitch13DeviceContainer &b)
{
  *this = a;
  Add (b);
}

OFSwitch13DeviceContainer::Iterator
OFSwitch13DeviceContainer::Begin (void) const
{
  return m_devices.begin ();
}

OFSwitch13DeviceContainer::Iterator
OFSwitch13DeviceContainer::End (void) const
{
  return m_devices.end ();
}

uint32_t
OFSwitch13DeviceContainer::GetN (void) const
{
  return m_devices.size ();
}

Ptr<OFSwitch13Device>
OFSwitch13DeviceContainer::Get (uint32_t i) const
{
  return m_devices [i];
}

void
OFSwitch13DeviceContainer::Add (OFSwitch13DeviceContainer other)
{
  for (Iterator i = other.Begin (); i != other.End (); i++)
    {
      m_devices.push_back (*i);
    }
}

void
OFSwitch13DeviceContainer::Add (Ptr<OFSwitch13Device> device)
{
  m_devices.push_back (device);
}

void
OFSwitch13DeviceContainer::Add (std::string deviceName)
{
  Ptr<OFSwitch13Device> device = Names::Find<OFSwitch13Device> (deviceName);
  m_devices.push_back (device);
}

} // namespace ns3
