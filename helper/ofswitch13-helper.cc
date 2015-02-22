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
  : m_ctrlNode (0),
    m_ctrlPort (6653)
{
  NS_LOG_FUNCTION (this);

  m_ndevFactory.SetTypeId ("ns3::OFSwitch13NetDevice");
  SetAddressBase ("10.100.150.0", "255.255.255.0");
}

OFSwitch13Helper::~OFSwitch13Helper ()
{
  NS_LOG_FUNCTION (this);
  m_ctrlNode = 0;
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
  Ptr<OFSwitch13NetDevice> openFlowDev;
  for (size_t i = 0; i < m_devices.GetN (); i++)
    {
      openFlowDev = DynamicCast<OFSwitch13NetDevice> (m_devices.Get (i));
      openFlowDev->SetLibLogLevel (level);
    }
}

void
OFSwitch13Helper::SetAddressBase (Ipv4Address network, Ipv4Mask mask, Ipv4Address base)
{
  m_ipv4helper.SetBase (network, mask, base);
}

NetDeviceContainer
OFSwitch13Helper::InstallSwitchesWithoutPorts (NodeContainer swNodes)
{
  NS_LOG_FUNCTION (this);

  NetDeviceContainer openFlowDevices;
  for (NodeContainer::Iterator it = swNodes.Begin (); it != swNodes.End (); it++)
    {
      Ptr<Node> swNode = *it;
      openFlowDevices.Add (InstallSwitch (swNode, NetDeviceContainer ()));
    }
  return openFlowDevices;
}


Ptr<OFSwitch13Controller>
OFSwitch13Helper::InstallDefaultController (Ptr<Node> cNode)
{
  NS_LOG_FUNCTION (this);

  return InstallControllerApp (cNode, CreateObject<OFSwitch13LearningController> ());
}


// ------------------------------------------------------------------------- //
OFSwitch13P2pHelper::OFSwitch13P2pHelper ()
  : m_ctrlApp  (0)
{
  NS_LOG_FUNCTION (this);

  // For internal controller we use dedicated point-to-point links. Using
  // large MTU to allow OpenFlow packet in messages with data. This value is
  // tied to the 2960 TCPSocket SegmentSize attribute in switch and controller.
  m_p2pHelper.SetDeviceAttribute ("Mtu", UintegerValue (3100));
  m_p2pHelper.SetDeviceAttribute ("DataRate", DataRateValue (DataRate ("1Gbps")));

  // We use a /30 subnet which can hold exactly two addresses.
  SetAddressBase ("10.100.150.0", "255.255.255.252");
}

OFSwitch13P2pHelper::~OFSwitch13P2pHelper ()
{
  m_ctrlApp = 0;
}

void
OFSwitch13P2pHelper::SetAddressBase (Ipv4Address network, Ipv4Mask mask, Ipv4Address base)
{
  // Forcing a /30 network mask
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
  
  // This name thing is not necessary, but I'm currently using it in my simulations
  if (!Names::FindName (swNode).empty () && !Names::FindName (m_ctrlNode).empty ())
    {
      Names::Add (Names::FindName (swNode) + "+" + 
                  Names::FindName (m_ctrlNode), swDev.Get (0));     
      Names::Add (Names::FindName (m_ctrlNode) + "+" + 
                  Names::FindName (swNode), swDev.Get (1));
    }

  // Register switch metadata and start switch <--> controller connection
  SwitchInfo swInfo;
  swInfo.ipv4   = swIface.GetAddress (0);
  swInfo.netdev = openFlowDev;
  swInfo.node   = swNode;
  Address ctrlAddr = InetSocketAddress (swIface.GetAddress (1), m_ctrlPort);
  m_ctrlApp->RegisterSwitchMetadata (swInfo);
  openFlowDev->SetAttribute ("ControllerAddr", AddressValue (ctrlAddr));
  openFlowDev->StartControllerConnection ();

  return NetDeviceContainer (openFlowDev);
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


// ------------------------------------------------------------------------- //
OFSwitch13CsmaHelper::OFSwitch13CsmaHelper ()
  : m_csmaChannel (0),
    m_ctrlApp (0)
{
  NS_LOG_FUNCTION (this);

  // Connecting all switches to controller over a single CSMA high-speed link
  m_csmaChannel = CreateObject<CsmaChannel> ();
  m_csmaChannel->SetAttribute ("DataRate", DataRateValue (DataRate ("10Gbps")));
  
  // Using large MTU to allow OpenFlow packet in messages with data. This value
  // is tied to the 2960 TCPSocket SegmentSize attribute in switch and
  // controller.
  m_csmaHelper.SetDeviceAttribute ("Mtu", UintegerValue (3100));
}

OFSwitch13CsmaHelper::~OFSwitch13CsmaHelper ()
{
  m_ctrlApp = 0;
  m_csmaChannel = 0;
}

NetDeviceContainer
OFSwitch13CsmaHelper::InstallSwitch (Ptr<Node> swNode, NetDeviceContainer ports)
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

  // Connecting the switch to common csma network
  m_internet.Install (swNode);
  NetDeviceContainer swDev = m_csmaHelper.Install (swNode, m_csmaChannel);
  Ipv4InterfaceContainer swIface = m_ipv4helper.Assign (swDev);

  // Register switch metadata and start switch <--> controller connection
  SwitchInfo swInfo;
  swInfo.ipv4   = swIface.GetAddress (0);
  swInfo.netdev = openFlowDev;
  swInfo.node   = swNode;
  m_ctrlApp->RegisterSwitchMetadata (swInfo);
  openFlowDev->SetAttribute ("ControllerAddr", AddressValue (m_ctrlAddr));
  openFlowDev->StartControllerConnection ();

  return NetDeviceContainer (openFlowDev);
}

Ptr<OFSwitch13Controller>
OFSwitch13CsmaHelper::InstallControllerApp (Ptr<Node> cNode, Ptr<OFSwitch13Controller> controller)
{
  NS_LOG_FUNCTION (this);
  NS_ASSERT_MSG (!m_ctrlApp, "The controller is already installed.");
  NS_LOG_DEBUG ("Installing OpenFlow controller on node " << cNode->GetId ());

  // Install the controller App into controller node
  m_ctrlApp = controller;
  m_ctrlNode = cNode;
  m_ctrlApp->SetStartTime (Seconds (0));
  cNode->AddApplication (m_ctrlApp);

  // Connecting the controller to common csma network
  m_internet.Install (m_ctrlNode);
  m_ctrlDevs.Add (m_csmaHelper.Install (m_ctrlNode, m_csmaChannel));
  Ipv4InterfaceContainer ctrlIface = m_ipv4helper.Assign (m_ctrlDevs);

  // Get the controller port number
  UintegerValue portValue;
  m_ctrlApp->GetAttribute ("Port", portValue);
  m_ctrlPort = portValue.Get ();
  m_ctrlAddr = InetSocketAddress (ctrlIface.GetAddress (0), m_ctrlPort);
  
  return m_ctrlApp;
}

void
OFSwitch13CsmaHelper::EnableOpenFlowPcap (std::string prefix)
{
  NS_LOG_FUNCTION (this);
  m_csmaHelper.EnablePcap (prefix, m_ctrlDevs, true);
}


// ------------------------------------------------------------------------- //
OFSwitch13ExtHelper::OFSwitch13ExtHelper ()
  : m_csmaChannel (0)
{
  NS_LOG_FUNCTION (this);

  // Connecting all switches to controller over a single CSMA high-speed link
  m_csmaChannel = CreateObject<CsmaChannel> ();
  m_csmaChannel->SetAttribute ("DataRate", DataRateValue (DataRate ("10Gbps")));
  
  // Using large MTU to allow OpenFlow packet in messages with data. This value
  // is tied to the 2960 TCPSocket SegmentSize attribute in switch and
  // controller.
  m_csmaHelper.SetDeviceAttribute ("Mtu", UintegerValue (3100));
}

OFSwitch13ExtHelper::~OFSwitch13ExtHelper ()
{
  m_csmaChannel = 0;
}

NetDeviceContainer
OFSwitch13ExtHelper::InstallSwitch (Ptr<Node> swNode, NetDeviceContainer ports)
{
  NS_LOG_FUNCTION (this);
  NS_ASSERT_MSG (m_ctrlNode, "Configure the controller node first.");
  NS_LOG_DEBUG ("Installing OpenFlow switch device on node " << swNode->GetId ());

  Ptr<OFSwitch13NetDevice> openFlowDev = m_ndevFactory.Create<OFSwitch13NetDevice> ();
  swNode->AddDevice (openFlowDev);
  m_devices.Add (openFlowDev);

  for (NetDeviceContainer::Iterator i = ports.Begin (); i != ports.End (); ++i)
    {
      NS_LOG_INFO (" Adding switch port " << *i);
      openFlowDev->AddSwitchPort (*i);
    }

  // Connecting the switch to common csma network
  m_internet.Install (swNode);
  NetDeviceContainer swDev = m_csmaHelper.Install (swNode, m_csmaChannel);
  Ipv4InterfaceContainer swIface = m_ipv4helper.Assign (swDev);

  // Start switch <--> controller connection
  openFlowDev->SetAttribute ("ControllerAddr", AddressValue (m_ctrlAddr));
  openFlowDev->StartControllerConnection ();

  return NetDeviceContainer (openFlowDev);
}

Ptr<OFSwitch13Controller>
OFSwitch13ExtHelper::InstallControllerApp (Ptr<Node> cNode, Ptr<OFSwitch13Controller> controller)
{
  NS_LOG_FUNCTION (this);
  NS_LOG_ERROR ("Invalid command for this helper. "
                "Consider using InstallExternalController ()");
  return 0;
}

void
OFSwitch13ExtHelper::EnableOpenFlowPcap (std::string prefix)
{
  NS_LOG_FUNCTION (this);
  m_csmaHelper.EnablePcap (prefix, m_ctrlDevs, true);
}

Ptr<NetDevice>
OFSwitch13ExtHelper::InstallExternalController (Ptr<Node> cNode)
{
  NS_LOG_FUNCTION (this << cNode);
  NS_ASSERT_MSG (!m_ctrlNode, "External controller already configured.");

   // Connecting the controller node (TapBridge) to common csma network
  m_ctrlNode = cNode;
  m_internet.Install (m_ctrlNode);
  m_ctrlDevs.Add (m_csmaHelper.Install (m_ctrlNode, m_csmaChannel));
  Ipv4InterfaceContainer ctrlIface = m_ipv4helper.Assign (m_ctrlDevs);
  m_ctrlAddr = InetSocketAddress (ctrlIface.GetAddress (0), m_ctrlPort);

  return m_ctrlDevs.Get (0);
}

} // namespace ns3
#endif // NS3_OFSWITCH13
