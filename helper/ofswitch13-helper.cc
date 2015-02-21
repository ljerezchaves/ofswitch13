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

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Helper");

class OFSwitch13Controller;

OFSwitch13Helper::OFSwitch13Helper ()
{
  NS_LOG_FUNCTION (this);

  m_ndevFactory.SetTypeId ("ns3::OFSwitch13NetDevice");
  SetAddressBase ("10.100.150.0", "255.255.255.0");
}

OFSwitch13Helper::~OFSwitch13Helper ()
{
  NS_LOG_FUNCTION (this);
}

void
OFSwitch13Helper::SetDeviceAttribute (std::string n1, const AttributeValue &v1)
{
  NS_LOG_FUNCTION (this);
  m_ndevFactory.Set (n1, v1);
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

void
OFSwitch13Helper::SetAddressBase (Ipv4Address network, Ipv4Mask mask, Ipv4Address base)
{
  m_ipv4helper.SetBase (network, mask, base);
}

// ------------------------------------------------------------------------- //
OFSwitch13CsmaHelper::OFSwitch13CsmaHelper ()
  : m_ctrlNode (0),
    m_ctrlApp (0),
    m_ctrlDev (0)
{
  NS_LOG_FUNCTION (this);

  // Connecting all switches to controller over a single CSMA high-speed link
  m_csmaChannel = CreateObject<CsmaChannel> ();
  m_csmaChannel->SetAttribute ("DataRate", DataRateValue (DataRate ("10Gbps")));
  
  // Using large MTU to allow OpenFlow packet in messages with data. This value
  // is tied to the 2960 TCPSocket SegmentSize attribute in switch and
  // controller.
  m_csmaHelper.SetDeviceAttribute ("Mtu", UintegerValue (3000));
}

OFSwitch13CsmaHelper::~OFSwitch13CsmaHelper ()
{
  m_ctrlNode = 0;
  m_ctrlApp = 0;
  m_ctrlDev = 0;
  m_csmaChannel = 0;
  m_unregSw.clear ();
}

NetDeviceContainer
OFSwitch13CsmaHelper::InstallSwitch (Ptr<Node> swNode, NetDeviceContainer ports)
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
OFSwitch13CsmaHelper::InstallSwitchesWithoutPorts (NodeContainer swNodes)
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
OFSwitch13CsmaHelper::InstallControllerApp (Ptr<Node> cNode)
{
  NS_LOG_FUNCTION (this);

  Ptr<OFSwitch13LearningController> ctrl = CreateObject<OFSwitch13LearningController> ();
  return InstallControllerApp (cNode, ctrl);
}

Ptr<OFSwitch13Controller>
OFSwitch13CsmaHelper::InstallControllerApp (Ptr<Node> cNode, Ptr<OFSwitch13Controller> controller)
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

void
OFSwitch13CsmaHelper::EnableOpenFlowPcap (std::string prefix)
{
  NS_LOG_FUNCTION (this);
  m_csmaHelper.EnablePcap (prefix, m_ctrlDev, true);
}

Ptr<NetDevice>
OFSwitch13CsmaHelper::InstallExternalController (Ptr<Node> cNode)
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


// ------------------------------------------------------------------------- //
OFSwitch13P2pHelper::OFSwitch13P2pHelper ()
  : m_ctrlNode (0),
    m_ctrlApp  (0),
    m_ctrlPort (6653)
{
  NS_LOG_FUNCTION (this);

  // For internal controller we use dedicated point-to-point links. Using
  // large MTU to allow OpenFlow packet in messages with data. This value is
  // tied to the 2960 TCPSocket SegmentSize attribute in switch and controller.
  m_p2pHelper.SetDeviceAttribute ("Mtu", UintegerValue (3000));
  m_p2pHelper.SetDeviceAttribute ("DataRate", DataRateValue (DataRate ("1Gbps")));

  // We use a /30 subnet which can hold exactly two addresses.
  SetAddressBase ("10.100.150.0", "255.255.255.252");
}

OFSwitch13P2pHelper::~OFSwitch13P2pHelper ()
{
  m_ctrlNode = 0;
  m_ctrlApp = 0;
}

void
OFSwitch13P2pHelper::SetAddressBase (Ipv4Address network, Ipv4Mask mask, Ipv4Address base)
{
  m_ipv4helper.SetBase (network, "255.255.255.252", base);
}

NetDeviceContainer
OFSwitch13P2pHelper::InstallSwitch (Ptr<Node> swNode, NetDeviceContainer ports)
{
  NS_LOG_FUNCTION (this);
  NS_ASSERT_MSG (m_ctrlApp, "Install the controller before switch.");
  NS_LOG_DEBUG ("Installing OpenFlow switch device on node " << swNode->GetId ());

  Ptr<OFSwitch13NetDevice> openFlowDev = m_ndevFactory.Create<OFSwitch13NetDevice> ();
  swNode->AddDevice (openFlowDev);
  m_devices.Add (openFlowDev);

  for (NetDeviceContainer::Iterator i = ports.Begin (); i != ports.End (); ++i)
    {
      NS_LOG_INFO (" Adding switch port " << *i);
      openFlowDev->AddSwitchPort (*i);
    }

  // Create a p2p link between switch and controller
  m_internet.Install (swNode);
  NetDeviceContainer swDev = m_p2pHelper.Install (swNode, m_ctrlNode);
  Ipv4InterfaceContainer swIface = m_ipv4helper.Assign (swDev);
  m_ipv4helper.NewNetwork ();
  m_ctrlDevs.Add (swDev.Get (1));

  SwitchInfo swInfo;
  swInfo.ipv4   = swIface.GetAddress (0);
  swInfo.netdev = openFlowDev;
  swInfo.node   = swNode;
  Address ctrlAddr = InetSocketAddress (swIface.GetAddress (1), m_ctrlPort);
      
  // Register switch metadata into controller and start switch <--> controller connection
  m_ctrlApp->RegisterSwitchMetadata (swInfo);
  openFlowDev->SetAttribute ("ControllerAddr", AddressValue (ctrlAddr));
  openFlowDev->StartControllerConnection ();

  return NetDeviceContainer (openFlowDev);
}

NetDeviceContainer
OFSwitch13P2pHelper::InstallSwitchesWithoutPorts (NodeContainer swNodes)
{
  NS_LOG_FUNCTION (this);
  NS_ASSERT_MSG (m_ctrlApp, "Install the controller before switch.");

  NetDeviceContainer openFlowDevices;
  for (NodeContainer::Iterator it = swNodes.Begin (); it != swNodes.End (); it++)
    {
      Ptr<Node> node = *it;
      NS_LOG_DEBUG ("Installing OpenFlow switch device on node " << node->GetId ());

      Ptr<OFSwitch13NetDevice> openFlowDev = m_ndevFactory.Create<OFSwitch13NetDevice> ();
      node->AddDevice (openFlowDev);
      m_devices.Add (openFlowDev);
      openFlowDevices.Add (openFlowDev);
      m_internet.Install (node);

      // Create a p2p link between switch and controller
      NetDeviceContainer swDev = m_p2pHelper.Install (node, m_ctrlNode);
      Ipv4InterfaceContainer swIface = m_ipv4helper.Assign (swDev);
      m_ipv4helper.NewNetwork ();
      m_ctrlDevs.Add (swDev.Get (1));

      SwitchInfo swInfo;
      swInfo.ipv4   = swIface.GetAddress (0);
      swInfo.netdev = openFlowDev;
      swInfo.node   = node;
      Address ctrlAddr = InetSocketAddress (swIface.GetAddress (1), m_ctrlPort);
          
      // Register switch metadata into controller and start switch <--> controller connection
      m_ctrlApp->RegisterSwitchMetadata (swInfo);
      openFlowDev->SetAttribute ("ControllerAddr", AddressValue (ctrlAddr));
      openFlowDev->StartControllerConnection ();
    }
  return openFlowDevices;
}

Ptr<OFSwitch13Controller>
OFSwitch13P2pHelper::InstallControllerApp (Ptr<Node> cNode)
{
  NS_LOG_FUNCTION (this);

  Ptr<OFSwitch13LearningController> ctrl = CreateObject<OFSwitch13LearningController> ();
  return InstallControllerApp (cNode, ctrl);
}

Ptr<OFSwitch13Controller>
OFSwitch13P2pHelper::InstallControllerApp (Ptr<Node> cNode, Ptr<OFSwitch13Controller> controller)
{
  NS_LOG_FUNCTION (this);
  NS_ASSERT_MSG (!m_ctrlApp, "The controller is already installed.");
  NS_LOG_DEBUG ("Installing OpenFlow controller on node " << cNode->GetId ());

  // Install the controller App into controller node
  m_ctrlApp = controller;
  m_ctrlNode = cNode;
  m_ctrlApp->SetStartTime (Seconds (0));
  m_ctrlNode->AddApplication (m_ctrlApp);
  m_internet.Install (m_ctrlNode);
  
  // Get the controller port number
  UintegerValue portValue;
  m_ctrlApp->GetAttribute ("Port", portValue);
  m_ctrlPort = portValue.Get ();
  
  return m_ctrlApp;
}

void
OFSwitch13P2pHelper::EnableOpenFlowPcap (std::string prefix)
{
  NS_LOG_FUNCTION (this);
  m_p2pHelper.EnablePcap (prefix, m_ctrlDevs, true);
}

} // namespace ns3
#endif // NS3_OFSWITCH13
