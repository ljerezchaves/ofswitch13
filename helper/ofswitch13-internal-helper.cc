/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017 University of Campinas (Unicamp)
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

#include "ofswitch13-internal-helper.h"
#include <ns3/ofswitch13-learning-controller.h>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13InternalHelper");
NS_OBJECT_ENSURE_REGISTERED (OFSwitch13InternalHelper);

class OFSwitch13Controller;

OFSwitch13InternalHelper::OFSwitch13InternalHelper ()
{
  NS_LOG_FUNCTION (this);
}

OFSwitch13InternalHelper::~OFSwitch13InternalHelper ()
{
  NS_LOG_FUNCTION (this);
}

TypeId
OFSwitch13InternalHelper::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OFSwitch13InternalHelper")
    .SetParent<OFSwitch13Helper> ()
    .SetGroupName ("OFSwitch13")
    .AddConstructor<OFSwitch13InternalHelper> ()
  ;
  return tid;
}

void
OFSwitch13InternalHelper::CreateOpenFlowChannels (void)
{
  NS_LOG_FUNCTION (this);

  NS_LOG_INFO ("Creating OpenFlow channels.");
  NS_ABORT_MSG_IF (m_blocked, "OpenFlow channels already configured.");

  // Block this helper to avoid further calls to install methods.
  m_blocked = true;

  // Create and start the connections between switches and controllers.
  switch (m_channelType)
    {
    case OFSwitch13InternalHelper::SINGLECSMA:
      {
        NS_LOG_INFO ("Attach all switches and controllers to the same "
                     "CSMA network.");

        // Create the common channel for all switches and controllers.
        Ptr<CsmaChannel> csmaChannel =
          CreateObjectWithAttributes<CsmaChannel> (
            "DataRate", DataRateValue (m_channelDataRate));

        // Connecting all switches and controllers to the common channel.
        NetDeviceContainer switchDevices;
        Ipv4InterfaceContainer controllerAddrs;
        m_controlDevs = m_csmaHelper.Install (m_controlNodes, csmaChannel);
        switchDevices = m_csmaHelper.Install (m_switchNodes,  csmaChannel);
        controllerAddrs = m_ipv4helper.Assign (m_controlDevs);
        m_ipv4helper.Assign (switchDevices);

        // Start the connections between controllers and switches.
        UintegerValue portValue;
        for (uint32_t ctIdx = 0; ctIdx < controllerAddrs.GetN (); ctIdx++)
          {
            m_controlApps.Get (ctIdx)->GetAttribute ("Port", portValue);
            InetSocketAddress addr (controllerAddrs.GetAddress (ctIdx),
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
        m_ipv4helper.NewNetwork ();
        break;
      }
    case OFSwitch13InternalHelper::DEDICATEDCSMA:
    case OFSwitch13InternalHelper::DEDICATEDP2P:
      {
        // Setting channel/device data rates.
        m_p2pHelper.SetDeviceAttribute (
          "DataRate", DataRateValue (m_channelDataRate));
        m_csmaHelper.SetChannelAttribute (
          "DataRate", DataRateValue (m_channelDataRate));

        // To avoid IP datagram fragmentation, we are configuring the OpenFlow
        // channel devices with a very large MTU value. The TCP sockets used to
        // send packets to theses devices are also configured to use a large
        // segment size at OFSwitch13Controller and OFSwitch13Device.
        m_csmaHelper.SetDeviceAttribute ("Mtu", UintegerValue (9000));
        m_p2pHelper.SetDeviceAttribute ("Mtu", UintegerValue (9000));

        // Using large queues on devices to avoid losing packets.
        m_csmaHelper.SetQueue ("ns3::DropTailQueue<Packet>",
                               "MaxSize", StringValue ("65536p"));
        m_p2pHelper.SetQueue ("ns3::DropTailQueue<Packet>",
                              "MaxSize", StringValue ("65536p"));

        // Create individual channels for each pair switch/controller.
        UintegerValue portValue;
        for (uint32_t swIdx = 0; swIdx < m_switchNodes.GetN (); swIdx++)
          {
            Ptr<Node> swNode = m_switchNodes.Get (swIdx);
            Ptr<OFSwitch13Device> ofDev = m_openFlowDevs.Get (swIdx);

            for (uint32_t ctIdx = 0; ctIdx < m_controlNodes.GetN (); ctIdx++)
              {
                Ptr<Node> ctNode = m_controlNodes.Get (ctIdx);
                Ptr<Application> ctApp = m_controlApps.Get (ctIdx);

                NetDeviceContainer pairDevs = Connect (ctNode, swNode);
                m_controlDevs.Add (pairDevs.Get (0));
                Ipv4InterfaceContainer pairIfaces =
                  m_ipv4helper.Assign (pairDevs);

                // Start this single connection between switch and controller.
                m_controlApps.Get (ctIdx)->GetAttribute ("Port", portValue);
                InetSocketAddress addr (pairIfaces.GetAddress (0),
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
        NS_ABORT_MSG ("Invalid OpenflowChannelType.");
      }
    }
}

Ptr<OFSwitch13Controller>
OFSwitch13InternalHelper::InstallController (
  Ptr<Node> cNode, Ptr<OFSwitch13Controller> controller)
{
  NS_LOG_FUNCTION (this << cNode << controller);

  NS_LOG_INFO ("Installing OpenFlow controller on node " << cNode->GetId ());
  NS_ABORT_MSG_IF (m_blocked, "OpenFlow channels already configured.");

  // Install the TCP/IP stack and the controller application into node.
  m_internet.Install (cNode);
  controller->SetStartTime (Seconds (0));
  cNode->AddApplication (controller);
  m_controlApps.Add (controller);
  m_controlNodes.Add (cNode);

  return controller;
}

void
OFSwitch13InternalHelper::DoDispose ()
{
  NS_LOG_FUNCTION (this);

  OFSwitch13Helper::DoDispose ();
}

NetDeviceContainer
OFSwitch13InternalHelper::Connect (Ptr<Node> ctrl, Ptr<Node> swtch)
{
  NS_LOG_FUNCTION (this << ctrl << swtch);

  NodeContainer pairNodes (ctrl, swtch);
  switch (m_channelType)
    {
    case OFSwitch13InternalHelper::DEDICATEDCSMA:
      {
        return m_csmaHelper.Install (pairNodes);
      }
    case OFSwitch13InternalHelper::DEDICATEDP2P:
      {
        return m_p2pHelper.Install (pairNodes);
      }
    case OFSwitch13InternalHelper::SINGLECSMA:
    default:
      {
        NS_ABORT_MSG ("Invalid OpenflowChannelType.");
      }
    }
}

} // namespace ns3
#endif // NS3_OFSWITCH13
