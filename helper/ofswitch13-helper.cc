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
#include "ns3/ofswitch13-learning-controller.h"
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
    m_ctrlDev (0)
{
  NS_LOG_FUNCTION (this);

  m_ndevFactory.SetTypeId ("ns3::OFSwitch13NetDevice");

  m_ipv4helper.SetBase ("10.100.150.0", "255.255.255.0");

  // Connecting all switches to controller over a single CSMA high-speed link
  ObjectFactory m_chanFactory;
  m_chanFactory.SetTypeId ("ns3::CsmaChannel");
  m_chanFactory.Set ("DataRate", DataRateValue (DataRate ("10Gbps")));
  m_csmaChannel = m_chanFactory.Create ()->GetObject<CsmaChannel> ();
  
  // Using large MTU to allow OpenFlow packet in messages with data. This value
  // is tied to the 2960 TCPSocket SegmentSize attribute in switch and
  // controller.
  m_csmaHelper.SetDeviceAttribute ("Mtu", UintegerValue (3000));
}

OFSwitch13Helper::~OFSwitch13Helper ()
{
  m_ctrlNode = 0;
  m_ctrlApp = 0;
  m_ctrlDev = 0;
  m_csmaChannel = 0;
  m_unregSw.clear ();
}

void
OFSwitch13Helper::SetDeviceAttribute (std::string n1, const AttributeValue &v1)
{
  NS_LOG_FUNCTION (this);
  m_ndevFactory.Set (n1, v1);
}

void
OFSwitch13Helper::SetAddressBase (Ipv4Address network, Ipv4Mask mask)
{
  m_ipv4helper.SetBase (network, mask);
}

NetDeviceContainer
OFSwitch13Helper::InstallSwitch (Ptr<Node> swNode, NetDeviceContainer ports)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_DEBUG ("Installing OpenFlow switch device on node " << swNode->GetId ());

  Ptr<OFSwitch13NetDevice> openFlowDev = m_ndevFactory.Create<OFSwitch13NetDevice> ();
  swNode->AddDevice (openFlowDev);
  m_devices.Add (openFlowDev);

  for (NetDeviceContainer::Iterator i = ports.Begin (); i != ports.End (); ++i)
    {
      NS_LOG_INFO (" Adding switch port " << *i);
      openFlowDev->AddSwitchPort (*i);
    }

  // Connecting the switch to csma network
  m_internet.Install (swNode);
  NetDeviceContainer swDev = m_csmaHelper.Install (swNode, m_csmaChannel);
  Ipv4InterfaceContainer swIface = m_ipv4helper.Assign (swDev);

  // If controller address already set, start switch <--> controller connection
  if (!m_ctrlAddr.IsInvalid ())
    {
      openFlowDev->SetAttribute ("ControllerAddr", AddressValue (m_ctrlAddr));
      openFlowDev->StartControllerConnection ();
    }

  // Register switch metadata into controller or save for further registration
  SwitchInfo swInfo;
  swInfo.ipv4   = swIface.GetAddress (0);
  swInfo.netdev = openFlowDev;
  swInfo.node   = swNode;
  if (m_ctrlApp)
    {
      m_ctrlApp->RegisterSwitchMetadata (swInfo);
    }
  else
    {
      m_unregSw.push_back (swInfo);
    }
  return NetDeviceContainer (openFlowDev);
}

NetDeviceContainer
OFSwitch13Helper::InstallSwitchesWithoutPorts (NodeContainer swNodes)
{
  NS_LOG_FUNCTION (this);
  NetDeviceContainer openFlowDevices;
  for (NodeContainer::Iterator it = swNodes.Begin (); it != swNodes.End (); it++)
    {
      Ptr<Node> node = *it;
      NS_LOG_DEBUG ("Installing OpenFlow switch device on node " << node->GetId ());

      Ptr<OFSwitch13NetDevice> openFlowDev = m_ndevFactory.Create<OFSwitch13NetDevice> ();
      node->AddDevice (openFlowDev);
      m_devices.Add (openFlowDev);
      openFlowDevices.Add (openFlowDev);

      // Connecting the switch to csma network
      m_internet.Install (node);
      NetDeviceContainer swDev = m_csmaHelper.Install (node, m_csmaChannel);
      Ipv4InterfaceContainer swIface = m_ipv4helper.Assign (swDev);

      // If controller address already set, start switch <--> controller connection
      if (!m_ctrlAddr.IsInvalid ())
        {
          openFlowDev->SetAttribute ("ControllerAddr", AddressValue (m_ctrlAddr));
          openFlowDev->StartControllerConnection ();
        }

      // Register switch metadata into controller or save for further registration
      SwitchInfo swInfo;
      swInfo.ipv4   = swIface.GetAddress (0);
      swInfo.netdev = openFlowDev;
      swInfo.node   = node;
      if (m_ctrlApp)
        {
          m_ctrlApp->RegisterSwitchMetadata (swInfo);
        }
      else
        {
          m_unregSw.push_back (swInfo);
        }
    }
  return openFlowDevices;
}


Ptr<OFSwitch13Controller>
OFSwitch13Helper::InstallControllerApp (Ptr<Node> cNode, Ptr<OFSwitch13Controller> controller)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_DEBUG ("Installing OpenFlow controller on node " << cNode->GetId ());

  if (m_ctrlApp == 0)
    {
      // Install the controller App into controller node
      m_ctrlApp = controller;
      m_ctrlApp->SetStartTime (Seconds (0));
      cNode->AddApplication (m_ctrlApp);

      // Registering previous configured switches to this controller
      if (!m_unregSw.empty ())
        {
          for (SwitchInfoVector_t::iterator it = m_unregSw.begin (); it != m_unregSw.end (); it++)
            {
              m_ctrlApp->RegisterSwitchMetadata (*it);
            }
          m_unregSw.clear ();
        }
    }
  InstallExternalController (cNode);
  return m_ctrlApp;
}

Ptr<OFSwitch13Controller>
OFSwitch13Helper::InstallControllerApp (Ptr<Node> cNode)
{
  NS_LOG_FUNCTION (this);
  Ptr<OFSwitch13LearningController> ctrl = CreateObject<OFSwitch13LearningController> ();
  return InstallControllerApp (cNode, ctrl);
}

Ptr<NetDevice>
OFSwitch13Helper::InstallExternalController (Ptr<Node> cNode)
{
  if (m_ctrlNode == 0)
    {
      m_ctrlNode = cNode;
      m_internet.Install (m_ctrlNode);
      NetDeviceContainer controlDev = m_csmaHelper.Install (m_ctrlNode, m_csmaChannel);
      Ipv4InterfaceContainer ctrlIface = m_ipv4helper.Assign (controlDev);
      m_ctrlDev = controlDev.Get (0);

      uint16_t port = 6653;
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
  return m_ctrlDev;
}

void
OFSwitch13Helper::EnableOpenFlowPcap (std::string prefix)
{
  NS_LOG_FUNCTION (this);
  m_csmaHelper.EnablePcap (prefix, m_ctrlDev, true);
}

void 
OFSwitch13Helper::EnableDatapathLogs (std::string level)
{
  for (size_t i = 0; i < m_devices.GetN (); i++)
    {
      Ptr<OFSwitch13NetDevice> openFlowDev = DynamicCast<OFSwitch13NetDevice> (m_devices.Get (i));
      openFlowDev->SetLibLogLevel (level);
    }
}

} // namespace ns3
#endif // NS3_OFSWITCH13
