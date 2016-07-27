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

#ifdef NS3_OFSWITCH13

#include "ofswitch13-helper.h"
#include "ns3/ofswitch13-learning-controller.h"
#include "ns3/uinteger.h"
#include "ns3/node.h"
#include "ns3/log.h"
#include "ns3/string.h"
#include "ns3/enum.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Helper");
NS_OBJECT_ENSURE_REGISTERED (OFSwitch13Helper);

class OFSwitch13Controller;

OFSwitch13Helper::OFSwitch13Helper ()
  : m_csmaChannel (0),
    m_ctrlNode (0),
    m_ctrlApp (0),
    m_ctrlPort (6653)
{
  NS_LOG_FUNCTION (this);

  m_devFactory.SetTypeId ("ns3::OFSwitch13Device");
}

OFSwitch13Helper::~OFSwitch13Helper ()
{
  NS_LOG_FUNCTION (this);
}

TypeId
OFSwitch13Helper::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OFSwitch13Helper")
    .SetParent<Object> ()
    .SetGroupName ("OFSwitch13")
    .AddConstructor<OFSwitch13Helper> ()
    .AddAttribute ("ChannelType",
                   "The configuration used to create the OpenFlow channel",
                   EnumValue (OFSwitch13Helper::SINGLECSMA),
                   MakeEnumAccessor (&OFSwitch13Helper::SetChannelType),
                   MakeEnumChecker (
                     OFSwitch13Helper::SINGLECSMA, "SingleCsma",
                     OFSwitch13Helper::DEDICATEDCSMA, "DedicatedCsma",
                     OFSwitch13Helper::DEDICATEDP2P, "DedicatedP2p"))
    .AddAttribute ("ChannelDataRate",
                   "The data rate to be used for the OpenFlow channel.",
                   DataRateValue (DataRate ("10Gb/s")),
                   MakeDataRateAccessor (&OFSwitch13Helper::SetChannelDataRate),
                   MakeDataRateChecker ())
  ;
  return tid;
}

void
OFSwitch13Helper::DoDispose ()
{
  NS_LOG_FUNCTION (this);
  m_ctrlNode = 0;
  m_ctrlApp = 0;
  m_csmaChannel = 0;
}

void
OFSwitch13Helper::SetDeviceAttribute (std::string n1, const AttributeValue &v1)
{
  NS_LOG_FUNCTION (this);
  m_devFactory.Set (n1, v1);
}

void
OFSwitch13Helper::SetChannelType (ChannelType type)
{
  NS_LOG_FUNCTION (this << type);

  m_channelType = type;
  switch (m_channelType)
    {
    case OFSwitch13Helper::SINGLECSMA:
      {
        // We use a /24 subnet which can hold up to 254 addresses.
        SetAddressBase ("10.100.150.0", "255.255.255.0");

        // Creating the common channel
        m_csmaChannel = CreateObject<CsmaChannel> ();
        m_csmaChannel->SetAttribute ("DataRate",
                                     DataRateValue (m_channelDataRate));
        break;
      }
    case OFSwitch13Helper::DEDICATEDCSMA:
    case OFSwitch13Helper::DEDICATEDP2P:
      {
        // We use a /30 subnet which can hold exactly two addresses.
        SetAddressBase ("10.100.150.0", "255.255.255.252");
        break;
      }
    default:
      {
        NS_FATAL_ERROR ("Invalid OpenflowChannelType.");
      }
    }
}

void
OFSwitch13Helper::SetChannelDataRate (DataRate datarate)
{
  NS_LOG_FUNCTION (this << datarate);

  m_channelDataRate = datarate;
  switch (m_channelType)
    {
    case OFSwitch13Helper::SINGLECSMA:
    case OFSwitch13Helper::DEDICATEDCSMA:
      {
        m_csmaHelper.SetChannelAttribute ("DataRate",
                                          DataRateValue (m_channelDataRate));
        m_csmaHelper.SetDeviceAttribute ("Mtu", UintegerValue (9000));
        m_csmaHelper.SetQueue ("ns3::DropTailQueue",
                               "MaxPackets", UintegerValue (65536));
        break;
      }
    case OFSwitch13Helper::DEDICATEDP2P:
      {
        m_p2pHelper.SetDeviceAttribute ("DataRate",
                                        DataRateValue (m_channelDataRate));
        m_p2pHelper.SetDeviceAttribute ("Mtu", UintegerValue (9000));
        m_p2pHelper.SetQueue ("ns3::DropTailQueue",
                              "MaxPackets", UintegerValue (65536));
        break;
      }
    default:
      {
        NS_FATAL_ERROR ("Invalid OpenflowChannelType.");
      }
    }
}

void
OFSwitch13Helper::EnableDatapathLogs (std::string level)
{
  Ptr<OFSwitch13Device> openFlowDev;
  for (size_t i = 0; i < m_devices.GetN (); i++)
    {
      m_devices.Get (i)->SetLibLogLevel (level);
    }
}

void
OFSwitch13Helper::SetAddressBase (Ipv4Address network, Ipv4Mask mask,
                                  Ipv4Address base)
{
  switch (m_channelType)
    {
    case OFSwitch13Helper::SINGLECSMA:
      {
        m_ipv4helper.SetBase (network, mask, base);
        break;
      }
    case OFSwitch13Helper::DEDICATEDCSMA:
    case OFSwitch13Helper::DEDICATEDP2P:
      {
        // Forcing a /30 network mask
        m_ipv4helper.SetBase (network, "255.255.255.252", base);
        break;
      }
    default:
      {
        NS_FATAL_ERROR ("Invalid OpenflowChannelType.");
      }
    }
}

OFSwitch13DeviceContainer
OFSwitch13Helper::InstallSwitchesWithoutPorts (NodeContainer swNodes)
{
  NS_LOG_FUNCTION (this);

  OFSwitch13DeviceContainer openFlowDevices;
  NodeContainer::Iterator it;
  for (it = swNodes.Begin (); it != swNodes.End (); it++)
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

  return InstallControllerApp (cNode,
                               CreateObject<OFSwitch13LearningController> ());
}

OFSwitch13DeviceContainer
OFSwitch13Helper::InstallSwitch (Ptr<Node> swNode, NetDeviceContainer ports)
{
  NS_LOG_FUNCTION (this);
  NS_ASSERT_MSG (m_ctrlNode, "Install the controller before switch.");
  NS_LOG_DEBUG ("Install OpenFlow switch device on node " << swNode->GetId ());

  Ptr<OFSwitch13Device> openFlowDev =
    m_devFactory.Create<OFSwitch13Device> ();
  swNode->AggregateObject (openFlowDev);
  m_devices.Add (openFlowDev);
  m_internet.Install (swNode);

  for (NetDeviceContainer::Iterator i = ports.Begin (); i != ports.End (); ++i)
    {
      NS_LOG_INFO (" Adding switch port " << *i);
      openFlowDev->AddSwitchPort (*i);
    }

  Address ctrlAddr;
  Ipv4InterfaceContainer swIface;
  switch (m_channelType)
    {
    case OFSwitch13Helper::SINGLECSMA:
      {
        // Connecting the switch to common csma network
        NetDeviceContainer swDev =
          m_csmaHelper.Install (swNode, m_csmaChannel);
        swIface = m_ipv4helper.Assign (swDev);
        ctrlAddr = m_ctrlAddr;
        break;
      }
    case OFSwitch13Helper::DEDICATEDCSMA:
      {
        // Create a dedicated csma link between switch and controller
        NodeContainer pair;
        pair.Add (swNode);
        pair.Add (m_ctrlNode);

        NetDeviceContainer swDev = m_csmaHelper.Install (pair);
        swIface = m_ipv4helper.Assign (swDev);
        m_ipv4helper.NewNetwork ();
        m_ctrlDevs.Add (swDev.Get (1));
        ctrlAddr = InetSocketAddress (swIface.GetAddress (1), m_ctrlPort);
        break;
      }
    case OFSwitch13Helper::DEDICATEDP2P:
      {
        // Create a dedicated p2p link between switch and controller
        NetDeviceContainer swDev = m_p2pHelper.Install (swNode, m_ctrlNode);
        swIface = m_ipv4helper.Assign (swDev);
        m_ipv4helper.NewNetwork ();
        m_ctrlDevs.Add (swDev.Get (1));
        ctrlAddr = InetSocketAddress (swIface.GetAddress (1), m_ctrlPort);
        break;
      }
    default:
      {
        NS_FATAL_ERROR ("Invalid OpenflowChannelType.");
      }
    }

  // FIXME We need to handle multiple controllers here
  // Register switch metadata and start switch <--> controller connection
  SwitchInfo swInfo;
  swInfo.ipv4 = swIface.GetAddress (0);
  swInfo.swDev = openFlowDev;
  swInfo.node = swNode;
  if (m_ctrlApp)
    {
      m_ctrlApp->RegisterSwitchMetadata (swInfo);
    }
  openFlowDev->StartControllerConnection (ctrlAddr);

  return OFSwitch13DeviceContainer (openFlowDev);
}

Ptr<OFSwitch13Controller>
OFSwitch13Helper::InstallControllerApp (Ptr<Node> cNode,
                                        Ptr<OFSwitch13Controller> controller)
{
  // FIXME We need to handle multiple controllers here. This helper must be
  // able to install more than a single controller on the network.
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

  Ipv4InterfaceContainer ctrlIface;
  switch (m_channelType)
    {
    case OFSwitch13Helper::SINGLECSMA:
      {
        // Connecting the controller to common csma network
        m_ctrlDevs.Add (m_csmaHelper.Install (m_ctrlNode, m_csmaChannel));
        ctrlIface = m_ipv4helper.Assign (m_ctrlDevs);
        m_ctrlAddr = InetSocketAddress (ctrlIface.GetAddress (0), m_ctrlPort);
        break;
      }
    case OFSwitch13Helper::DEDICATEDCSMA:
    case OFSwitch13Helper::DEDICATEDP2P:
      {
        // Nothing to do here.
        break;
      }
    default:
      {
        NS_FATAL_ERROR ("Invalid OpenflowChannelType.");
      }
    }
  return m_ctrlApp;
}

Ptr<NetDevice>
OFSwitch13Helper::InstallExternalController (Ptr<Node> cNode)
{
  NS_LOG_FUNCTION (this << cNode);
  NS_ASSERT_MSG (m_channelType == OFSwitch13Helper::SINGLECSMA,
                 "External controller must use SINGLECSMA openflow channel");

  // Connecting the controller node (TapBridge) to common csma network
  m_ctrlNode = cNode;
  m_internet.Install (m_ctrlNode);
  m_ctrlDevs.Add (m_csmaHelper.Install (m_ctrlNode, m_csmaChannel));
  Ipv4InterfaceContainer ctrlIface = m_ipv4helper.Assign (m_ctrlDevs);
  m_ctrlAddr = InetSocketAddress (ctrlIface.GetAddress (0), m_ctrlPort);

  return m_ctrlDevs.Get (0);
}

void
OFSwitch13Helper::EnableOpenFlowPcap (std::string prefix)
{
  NS_LOG_FUNCTION (this);
  switch (m_channelType)
    {
    case OFSwitch13Helper::SINGLECSMA:
    case OFSwitch13Helper::DEDICATEDCSMA:
      {
        m_csmaHelper.EnablePcap (prefix, m_ctrlDevs, true);
        break;
      }
    case OFSwitch13Helper::DEDICATEDP2P:
      {
        m_p2pHelper.EnablePcap (prefix, m_ctrlDevs, true);
        break;
      }
    default:
      {
        NS_FATAL_ERROR ("Invalid OpenflowChannelType.");
      }
    }
}

void
OFSwitch13Helper::EnableOpenFlowAscii (std::string prefix)
{
  NS_LOG_FUNCTION (this);
  AsciiTraceHelper ascii;
  switch (m_channelType)
    {
    case OFSwitch13Helper::SINGLECSMA:
    case OFSwitch13Helper::DEDICATEDCSMA:
      {
        m_csmaHelper.EnableAsciiAll (ascii.CreateFileStream (prefix + ".txt"));
        break;
      }
    case OFSwitch13Helper::DEDICATEDP2P:
      {
        m_p2pHelper.EnableAsciiAll (ascii.CreateFileStream (prefix + ".txt"));
        break;
      }
    default:
      {
        NS_FATAL_ERROR ("Invalid OpenflowChannelType.");
      }
    }
}

} // namespace ns3
#endif // NS3_OFSWITCH13
