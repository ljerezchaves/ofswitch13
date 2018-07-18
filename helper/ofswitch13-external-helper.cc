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

#include "ofswitch13-external-helper.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13ExternalHelper");
NS_OBJECT_ENSURE_REGISTERED (OFSwitch13ExternalHelper);

class OFSwitch13Controller;

OFSwitch13ExternalHelper::OFSwitch13ExternalHelper ()
{
  NS_LOG_FUNCTION (this);

  // Create the common channel for all switches and controllers.
  m_csmaChannel = CreateObject<CsmaChannel> ();
}

OFSwitch13ExternalHelper::~OFSwitch13ExternalHelper ()
{
  NS_LOG_FUNCTION (this);
}

TypeId
OFSwitch13ExternalHelper::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OFSwitch13ExternalHelper")
    .SetParent<OFSwitch13Helper> ()
    .SetGroupName ("OFSwitch13")
    .AddConstructor<OFSwitch13ExternalHelper> ()
    .AddAttribute ("Port",
                   "The port number where controller will be available.",
                   UintegerValue (6653),
                   MakeUintegerAccessor (
                     &OFSwitch13ExternalHelper::m_controlPort),
                   MakeUintegerChecker<uint16_t> ())
  ;
  return tid;
}

void
OFSwitch13ExternalHelper::SetChannelType (ChannelType type)
{
  NS_LOG_FUNCTION (this << type);

  // Check for valid channel type for this helper.
  NS_ABORT_MSG_IF (type != OFSwitch13Helper::SINGLECSMA, "Invalid channel "
                   "type for OFSwitch13ExternalHelper (use SingleCsma).");
  OFSwitch13Helper::SetChannelType (type);
}

void
OFSwitch13ExternalHelper::SetChannelDataRate (DataRate rate)
{
  NS_LOG_FUNCTION (this << rate);

  OFSwitch13Helper::SetChannelDataRate (rate);
  m_csmaChannel->SetAttribute ("DataRate", DataRateValue (rate));
}

void
OFSwitch13ExternalHelper::CreateOpenFlowChannels (void)
{
  NS_LOG_FUNCTION (this);

  NS_LOG_INFO ("Creating OpenFlow channels.");
  NS_ABORT_MSG_IF (m_blocked, "OpenFlow channels already configured.");

  // Block this helper to avoid further calls to install methods.
  m_blocked = true;

  // Create and start the connections between switches and controllers.
  switch (m_channelType)
    {
    case OFSwitch13ExternalHelper::SINGLECSMA:
      {
        NS_LOG_INFO ("Attach all switches and controllers to the same "
                     "CSMA network.");

        // Connecting all switches to the common channel.
        NetDeviceContainer switchDevices;
        switchDevices = m_csmaHelper.Install (m_switchNodes, m_csmaChannel);
        m_ipv4helper.Assign (switchDevices);
        InetSocketAddress addr (m_controlAddr, m_controlPort);

        // Start the connections between controller and switches.
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
        m_ipv4helper.NewNetwork ();
        break;
      }
    case OFSwitch13ExternalHelper::DEDICATEDCSMA:
    case OFSwitch13ExternalHelper::DEDICATEDP2P:
    default:
      {
        NS_ABORT_MSG ("Invalid OpenflowChannelType.");
      }
    }
}

Ptr<NetDevice>
OFSwitch13ExternalHelper::InstallExternalController (Ptr<Node> cNode)
{
  NS_LOG_FUNCTION (this << cNode);

  NS_LOG_INFO ("Installing OpenFlow controller on node " << cNode->GetId ());
  NS_ABORT_MSG_IF (m_blocked || m_controlDevs.GetN () != 0,
                   "OpenFlow controller/channels already configured.");

  // Install the TCP/IP stack and the controller application into node.
  m_internet.Install (cNode);
  m_controlNode = cNode;

  // Connect the controller node to the common channel and configure IP addrs.
  m_controlDevs = m_csmaHelper.Install (cNode, m_csmaChannel);
  Ipv4InterfaceContainer ctrlIface = m_ipv4helper.Assign (m_controlDevs);
  m_controlAddr = ctrlIface.GetAddress (0);

  return m_controlDevs.Get (0);
}

void
OFSwitch13ExternalHelper::DoDispose ()
{
  NS_LOG_FUNCTION (this);

  m_csmaChannel = 0;
  OFSwitch13Helper::DoDispose ();
}

} // namespace ns3
#endif // NS3_OFSWITCH13
