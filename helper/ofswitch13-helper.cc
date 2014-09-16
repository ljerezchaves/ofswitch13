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

#include "ofswitch13-helper.h"
#include "ns3/ofswitch13-net-device.h"
#include "ns3/uinteger.h"
#include "ns3/node.h"
#include "ns3/log.h"
#include "ns3/string.h"

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Helper");

namespace ns3 {

class OFSwitch13Controller;

OFSwitch13Helper::OFSwitch13Helper ()
  : m_ctrlNode (0),
    m_ctrlApp (0),
    m_ctrlDev (0),
    m_dpId (0)
{
  NS_LOG_FUNCTION_NOARGS ();
  m_ctrlFactory.SetTypeId ("ns3::OFSwitch13Controller");
  m_ndevFactory.SetTypeId ("ns3::OFSwitch13NetDevice");
  m_chanFactory.SetTypeId ("ns3::CsmaChannel");
    
  m_ipv4helper.SetBase ("10.100.150.0", "255.255.255.0");

  m_chanFactory.Set ("DataRate", DataRateValue (DataRate ("1Gbps")));
  m_chanFactory.Set ("Delay", TimeValue (MilliSeconds (2)));
  m_csmaChannel = m_chanFactory.Create ()->GetObject<CsmaChannel> ();
}

OFSwitch13Helper::~OFSwitch13Helper ()
{
  m_ctrlNode = 0;
  m_ctrlApp = 0;
  m_ctrlDev = 0;
  m_csmaChannel = 0;
}

void
OFSwitch13Helper::SetDeviceAttribute (std::string n1, const AttributeValue &v1)
{
  NS_LOG_FUNCTION_NOARGS ();
  m_ndevFactory.Set (n1, v1);
}

void
OFSwitch13Helper::SetControllerAttribute (std::string n1, const AttributeValue &v1)
{
  NS_LOG_FUNCTION_NOARGS ();
  m_ctrlFactory.Set (n1, v1);
}

NetDeviceContainer
OFSwitch13Helper::InstallSwitch (Ptr<Node> swNode, NetDeviceContainer ports)
{
  NS_LOG_DEBUG ("Installing OpenFlow switch device on node " << swNode->GetId ());
  
  SetDeviceAttribute ("ID", UintegerValue (++m_dpId));
  Ptr<OFSwitch13NetDevice> openFlowDev = m_ndevFactory.Create<OFSwitch13NetDevice> ();
  swNode->AddDevice (openFlowDev);
  
  for (NetDeviceContainer::Iterator i = ports.Begin (); i != ports.End (); ++i)
    {
      NS_LOG_INFO (" Adding switch port " << *i);
      openFlowDev->AddSwitchPort (*i);
    }

  // Connecting the switch to csma network
  m_internet.Install (swNode);
  NetDeviceContainer swDev = m_csmaHelper.Install (swNode, m_csmaChannel);
  Ipv4InterfaceContainer swIface = m_ipv4helper.Assign (swDev);

  // Updating containers
  m_switches.Add (swNode);
  m_devices.Add (openFlowDev);
  m_address.Add (swIface);

  // If controller address already set, start switch <--> controller connection
  if (!m_ctrlAddr.IsInvalid ())
    {
      openFlowDev->SetAttribute ("ControllerAddr", AddressValue (m_ctrlAddr));
      openFlowDev->StartControllerConnection ();
    }
  return NetDeviceContainer (openFlowDev);
}

Ptr<OFSwitch13Controller> 
OFSwitch13Helper::InstallControllerApp (Ptr<Node> cNode)
{
  NS_LOG_DEBUG ("Installing OpenFlow controller on node " << cNode->GetId ());

  if (m_ctrlApp == 0)
    {
      // Install the controller App in the controller node
      m_ctrlApp = m_ctrlFactory.Create<OFSwitch13Controller> ();
      cNode->AddApplication (m_ctrlApp);
      m_ctrlApp->SetOFSwitch13Helper (this);
      m_ctrlApp->SetStartTime (Seconds (0));
    }
  
  InstallExternalController (cNode);

  return m_ctrlApp;
}

void
OFSwitch13Helper::InstallExternalController (Ptr<Node> cNode)
{
  if (m_ctrlNode == 0)
    {
      m_ctrlNode = cNode;
      m_internet.Install (m_ctrlNode);
      NetDeviceContainer controlDev = m_csmaHelper.Install (m_ctrlNode, m_csmaChannel);
      Ipv4InterfaceContainer ctrlIface = m_ipv4helper.Assign (controlDev);
      m_ctrlDev = controlDev.Get (0);
      
      uint16_t port = 6633;
      if (m_ctrlApp)
        {
          UintegerValue portValue;
          m_ctrlApp->GetAttribute ("Port", portValue);
          port = portValue.Get ();
        } 
      m_ctrlAddr = InetSocketAddress (ctrlIface.GetAddress (0), port);

      // Start switch <--> controller connection
      for (size_t i = 0; i < m_devices.GetN (); i++)
        {
          Ptr<OFSwitch13NetDevice> openFlowDev = DynamicCast<OFSwitch13NetDevice> (m_devices.Get (i));
          openFlowDev->SetAttribute ("ControllerAddr", AddressValue (m_ctrlAddr));
          openFlowDev->StartControllerConnection ();
        }
    }
}

void
OFSwitch13Helper::EnableOpenFlowPcap ()
{
  m_csmaHelper.EnablePcap ("openflow-channel", m_ctrlDev, true);
}

Ipv4Address 
OFSwitch13Helper::GetSwitchAddress (uint32_t idx)
{
  return m_address.GetAddress (idx);
}

Ptr<OFSwitch13NetDevice> 
OFSwitch13Helper::GetSwitchDevice (uint32_t idx)
{
  return DynamicCast<OFSwitch13NetDevice> (m_devices.Get (idx));
}

Ptr<Node> 
OFSwitch13Helper::GetSwitchNode (uint32_t idx)
{
  return m_switches.Get (idx);
}

uint32_t
OFSwitch13Helper::GetContainerIndex (Ipv4Address addr)
{
  for (uint32_t i = 0; i < m_address.GetN (); i++)
    {
      if (addr.IsEqual (m_address.GetAddress (i)))
        {
          return i;
        }
    }
  NS_LOG_ERROR ("Switch address not found.");
  return UINT32_MAX;
}

uint32_t
OFSwitch13Helper::GetContainerIndex (Ptr<Node> node)
{
  for (uint32_t i = 0; i < m_switches.GetN (); i++)
    {
      if (node == m_switches.Get (i))
        {
          return i;
        }
    }
  NS_LOG_ERROR ("Switch node not found.");
  return UINT32_MAX;
}

uint32_t
OFSwitch13Helper::GetContainerIndex (Ptr<OFSwitch13NetDevice> dev)
{
  for (uint32_t i = 0; i < m_devices.GetN (); i++)
    {
      if (dev == m_devices.Get (i))
        {
          return i;
        }
    }
  NS_LOG_ERROR ("Switch device not found.");
  return UINT32_MAX;
}

} // namespace ns3
#endif // NS3_OFSWITCH13
