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
  : m_blocked (false)
{
  NS_LOG_FUNCTION (this);

  m_devFactory.SetTypeId ("ns3::OFSwitch13Device");

  // Creating the single shared CSMA channel, which will be used only if the
  // SINGLECSMA channel type (default) is selected.
  m_csmaChannel = CreateObject<CsmaChannel> ();

  // To avoid IP datagram fragmentation, we are configuring the OpenFlow
  // channel devices with a very large MTU value. The TCP sockets used to send
  // packets to theses devices are also configured to use a large segment size
  // at OFSwitch13Controller and OFSwitch13Device.
  m_csmaHelper.SetDeviceAttribute ("Mtu", UintegerValue (9000));
  m_p2pHelper.SetDeviceAttribute ("Mtu", UintegerValue (9000));

  // Using large queues on devices to avoid loosing packets.
  m_csmaHelper.SetQueue ("ns3::DropTailQueue",
                         "MaxPackets", UintegerValue (65536));
  m_p2pHelper.SetQueue ("ns3::DropTailQueue",
                        "MaxPackets", UintegerValue (65536));
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
        // For a shared CSMA channel we use a /24 subnet which can hold up to
        // 254 IP addresses.
        SetAddressBase ("10.100.150.0", "255.255.255.0");
        break;
      }
    case OFSwitch13Helper::DEDICATEDCSMA:
    case OFSwitch13Helper::DEDICATEDP2P:
      {
        // For dedicated channels we use a /30 subnet which can hold exactly
        // 2 IP addresses.
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

  // We are setting the data rate attribute for all channel types, regardless
  // which one will be used.
  m_csmaChannel->SetAttribute (
    "DataRate", DataRateValue (m_channelDataRate));
  m_csmaHelper.SetChannelAttribute (
    "DataRate", DataRateValue (m_channelDataRate));
  m_p2pHelper.SetDeviceAttribute (
    "DataRate", DataRateValue (m_channelDataRate));
}

void
OFSwitch13Helper::EnableDatapathLogs (std::string level)
{
  NS_LOG_FUNCTION (this << level);

  OFSwitch13DeviceContainer::Iterator it;
  for (it = m_openFlowDevs.Begin (); it != m_openFlowDevs.End (); it++)
    {
      (*it)->SetLibLogLevel (level);
    }
}

void
OFSwitch13Helper::EnableOpenFlowPcap (std::string prefix)
{
  NS_LOG_FUNCTION (this << prefix);

  switch (m_channelType)
    {
    case OFSwitch13Helper::SINGLECSMA:
    case OFSwitch13Helper::DEDICATEDCSMA:
      {
        m_csmaHelper.EnablePcap (prefix, m_controlDevs, true);
        break;
      }
    case OFSwitch13Helper::DEDICATEDP2P:
      {
        m_p2pHelper.EnablePcap (prefix, m_controlDevs, true);
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
  NS_LOG_FUNCTION (this << prefix);

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

void
OFSwitch13Helper::SetAddressBase (Ipv4Address network, Ipv4Mask mask,
                                  Ipv4Address base)
{
  NS_LOG_FUNCTION (this << network << mask << base);

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
OFSwitch13Helper::InstallSwitch (Ptr<Node> swNode, NetDeviceContainer ports)
{
  NS_LOG_FUNCTION (this << swNode);
  NS_LOG_DEBUG ("Installing OpenFlow device on node " << swNode->GetId ());
  NS_ASSERT_MSG (!m_blocked, "OpenFlow channels already configured.");

  // Create and aggregate the OpenFlow device to the switch node
  Ptr<OFSwitch13Device> openFlowDev = m_devFactory.Create<OFSwitch13Device> ();
  swNode->AggregateObject (openFlowDev);
  m_openFlowDevs.Add (openFlowDev);
  m_switchNodes.Add (swNode);

  // Add physical switch ports
  NetDeviceContainer::Iterator it;
  for (it = ports.Begin (); it != ports.End (); it++)
    {
      NS_LOG_INFO (" Adding physical switch port " << *it);
      openFlowDev->AddPhysicalPort (*it);
    }

  return OFSwitch13DeviceContainer (openFlowDev);
}

OFSwitch13DeviceContainer
OFSwitch13Helper::InstallSwitchesWithoutPorts (NodeContainer swNodes)
{
  NS_LOG_FUNCTION (this);

  // Iterate over the container and add OpenFlow devices to switch nodes
  OFSwitch13DeviceContainer openFlowDevices;
  NodeContainer::Iterator it;
  for (it = swNodes.Begin (); it != swNodes.End (); it++)
    {
      openFlowDevices.Add (InstallSwitch (*it, NetDeviceContainer ()));
    }

  return openFlowDevices;
}

Ptr<OFSwitch13Controller>
OFSwitch13Helper::InstallControllerApp (Ptr<Node> cNode,
                                        Ptr<OFSwitch13Controller> controller)
{
  NS_LOG_FUNCTION (this << cNode << controller);
  NS_LOG_DEBUG ("Installing OpenFlow controller on node " << cNode->GetId ());
  NS_ASSERT_MSG (!m_blocked, "OpenFlow channels already configured.");

  // Install the controller App into controller node
  controller->SetStartTime (Seconds (0));
  cNode->AddApplication (controller);
  m_controlApps.Add (controller);
  m_controlNodes.Add (cNode);

  return controller;
}

Ptr<OFSwitch13Controller>
OFSwitch13Helper::InstallDefaultController (Ptr<Node> cNode)
{
  NS_LOG_FUNCTION (this);

  // Install the learning controller into cNode
  return InstallControllerApp (
           cNode, CreateObject<OFSwitch13LearningController> ());
}

void
OFSwitch13Helper::CreateOpenFlowChannels (void)
{
  NS_LOG_FUNCTION (this);
  NS_ASSERT_MSG (!m_blocked, "OpenFlow channels already configured.");

  // Block this helper to avoid further calls to install methods
  m_blocked = true;

  // Install the TCP/IP stack into controller and switche nodes
  m_internet.Install (m_controlNodes);
  m_internet.Install (m_switchNodes);

  // Create and start the connections between switches and controllers
  switch (m_channelType)
    {
    case OFSwitch13Helper::SINGLECSMA:
      {
        // Create a common channel for all switches and controllers
        NS_LOG_INFO ("Attach all switches and controllers to the common "
                     "single CSMA network.");
        m_controlDevs = m_csmaHelper.Install (m_controlNodes, m_csmaChannel);
        Ipv4InterfaceContainer controlAddrs =
          m_ipv4helper.Assign (m_controlDevs);
        NetDeviceContainer swDevs =
          m_csmaHelper.Install (m_switchNodes, m_csmaChannel);
        m_ipv4helper.Assign (swDevs);

        // Start the connections between each controller and all switches.
        UintegerValue portValue;
        for (uint32_t ctIdx = 0; ctIdx < controlAddrs.GetN (); ctIdx++)
          {
            m_controlApps.Get (ctIdx)->GetAttribute ("Port", portValue);
            InetSocketAddress addr (controlAddrs.GetAddress (ctIdx),
                                    portValue.Get ());

            OFSwitch13DeviceContainer::Iterator ofDev;
            for (ofDev = m_openFlowDevs.Begin ();
                 ofDev != m_openFlowDevs.End (); ofDev++)
              {
                NS_LOG_INFO ("Connect switch " << (*ofDev)->GetDatapathId () <<
                             " to controller " << addr.GetIpv4 () <<
                             " port " << addr.GetPort ());
                Simulator::ScheduleNow (
                  &OFSwitch13Device::StartControllerConnection, *ofDev, addr);
              }
          }
        break;
      }
    case OFSwitch13Helper::DEDICATEDCSMA:
    case OFSwitch13Helper::DEDICATEDP2P:
      {
        // Create invididual channels for each pair switch/controller
        UintegerValue portValue;
        for (uint32_t swIdx = 0; swIdx < m_switchNodes.GetN (); swIdx++)
          {
            Ptr<Node> swNode = m_switchNodes.Get (swIdx);
            Ptr<OFSwitch13Device> ofDev = m_openFlowDevs.Get (swIdx);

            for (uint32_t ctIdx = 0; ctIdx < m_controlNodes.GetN (); ctIdx++)
              {
                Ptr<Node> ctNode = m_controlNodes.Get (ctIdx);
                Ptr<Application> ctApp = m_controlApps.Get (ctIdx);

                NetDeviceContainer pairDevs = Connect (swNode, ctNode);
                m_controlDevs.Add (pairDevs.Get (1));
                Ipv4InterfaceContainer pairIfaces =
                  m_ipv4helper.Assign (pairDevs);

                // Start this individual connection
                m_controlApps.Get (ctIdx)->GetAttribute ("Port", portValue);
                InetSocketAddress addr (pairIfaces.GetAddress (1),
                                        portValue.Get ());

                NS_LOG_INFO ("Connect switch " << ofDev->GetDatapathId () <<
                             " to controller " << addr.GetIpv4 () <<
                             " port " << addr.GetPort ());
                Simulator::ScheduleNow (
                  &OFSwitch13Device::StartControllerConnection, ofDev, addr);
                m_ipv4helper.NewNetwork ();
              }
          }
        break;
      }
    default:
      {
        NS_FATAL_ERROR ("Invalid OpenflowChannelType.");
      }
    }
}

NetDeviceContainer
OFSwitch13Helper::Connect (Ptr<Node> swtch, Ptr<Node> ctrl)
{
  NS_LOG_FUNCTION (this << swtch << ctrl);

  NodeContainer pairNodes (swtch, ctrl);
  switch (m_channelType)
    {
    case OFSwitch13Helper::DEDICATEDCSMA:
      {
        return m_csmaHelper.Install (pairNodes);
      }
    case OFSwitch13Helper::DEDICATEDP2P:
      {
        return m_p2pHelper.Install (pairNodes);
      }
    case OFSwitch13Helper::SINGLECSMA:
    default:
      {
        NS_FATAL_ERROR ("Invalid OpenflowChannelType.");
      }
    }
}

} // namespace ns3
#endif // NS3_OFSWITCH13
