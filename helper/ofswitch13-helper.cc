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

#include <ns3/ofswitch13-port.h>
#include "ofswitch13-helper.h"
#include "ofswitch13-stats-calculator.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Helper");
NS_OBJECT_ENSURE_REGISTERED (OFSwitch13Helper);

Ipv4AddressHelper OFSwitch13Helper::m_ipv4helper =
  Ipv4AddressHelper ("10.100.0.0", "255.255.255.0");

class OFSwitch13Controller;

OFSwitch13Helper::OFSwitch13Helper ()
  : m_blocked (false)
{
  NS_LOG_FUNCTION (this);

  // Set OpenFlow device factory TypeId.
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
    .AddAttribute ("ChannelDataRate",
                   "The data rate to be used for the OpenFlow channel.",
                   DataRateValue (DataRate ("10Gb/s")),
                   MakeDataRateAccessor (&OFSwitch13Helper::SetChannelDataRate),
                   MakeDataRateChecker ())
    .AddAttribute ("ChannelType",
                   "The configuration used to create the OpenFlow channel",
                   TypeId::ATTR_GET | TypeId::ATTR_CONSTRUCT,
                   EnumValue (OFSwitch13Helper::SINGLECSMA),
                   MakeEnumAccessor (&OFSwitch13Helper::SetChannelType),
                   MakeEnumChecker (
                     OFSwitch13Helper::SINGLECSMA,    "SingleCsma",
                     OFSwitch13Helper::DEDICATEDCSMA, "DedicatedCsma",
                     OFSwitch13Helper::DEDICATEDP2P,  "DedicatedP2p"))
  ;
  return tid;
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

  // Set the channel type and address, which will select proper netowrk mask.
  m_channelType = type;
}

void
OFSwitch13Helper::SetChannelDataRate (DataRate rate)
{
  NS_LOG_FUNCTION (this << rate);

  m_channelDataRate = rate;
}

void
OFSwitch13Helper::EnableOpenFlowPcap (std::string prefix, bool promiscuous)
{
  NS_LOG_FUNCTION (this << prefix);

  NS_ABORT_MSG_IF (!m_blocked, "OpenFlow channels not configured yet.");
  switch (m_channelType)
    {
    case OFSwitch13Helper::SINGLECSMA:
    case OFSwitch13Helper::DEDICATEDCSMA:
      {
        m_csmaHelper.EnablePcap (prefix, m_controlDevs, promiscuous);
        break;
      }
    case OFSwitch13Helper::DEDICATEDP2P:
      {
        m_p2pHelper.EnablePcap (prefix, m_controlDevs, promiscuous);
        break;
      }
    default:
      {
        NS_ABORT_MSG ("Invalid OpenflowChannelType.");
      }
    }
}

void
OFSwitch13Helper::EnableOpenFlowAscii (std::string prefix)
{
  NS_LOG_FUNCTION (this << prefix);

  NS_ABORT_MSG_IF (!m_blocked, "OpenFlow channels not configured yet.");
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
        NS_ABORT_MSG ("Invalid OpenflowChannelType.");
      }
    }
}

void
OFSwitch13Helper::EnableDatapathStats (std::string prefix, bool useNodeNames)
{
  NS_LOG_FUNCTION (this << prefix);

  NS_ABORT_MSG_IF (!m_blocked, "OpenFlow channels not configured yet.");
  NS_ASSERT_MSG (prefix.size (), "Empty prefix string.");
  if (prefix.back () != '-')
    {
      prefix += "-";
    }

  ObjectFactory statsFactory ("ns3::OFSwitch13StatsCalculator");
  Ptr<OFSwitch13StatsCalculator> statsCalculator;
  const std::string extension = ".log";

  // Iterate over the container and for each OpenFlow devices create a stats
  // calculator to monitor datapath statistcs.
  OFSwitch13DeviceContainer::Iterator it;
  for (it = m_openFlowDevs.Begin (); it != m_openFlowDevs.End (); it++)
    {
      Ptr<OFSwitch13Device> dev = *it;
      std::string filename = prefix;
      std::string nodename;

      if (useNodeNames)
        {
          Ptr<Node> node = dev->GetObject<Node> ();
          nodename = Names::FindName (node);
        }
      if (nodename.size ())
        {
          filename += nodename;
        }
      else
        {
          filename += std::to_string (dev->GetDatapathId ());
        }
      filename += extension;

      statsFactory.Set ("OutputFilename", StringValue (filename));
      statsCalculator = statsFactory.Create<OFSwitch13StatsCalculator> ();
      statsCalculator->AggregateObject (dev);
      statsCalculator->HookSinks (dev);
    }
}

Ptr<OFSwitch13Device>
OFSwitch13Helper::InstallSwitch (Ptr<Node> swNode, NetDeviceContainer &swPorts)
{
  NS_LOG_FUNCTION (this << swNode);

  // Install the OpenFlow device into switch node.
  Ptr<OFSwitch13Device> openFlowDev = InstallSwitch (swNode);

  // Add switch ports.
  NetDeviceContainer::Iterator it;
  for (it = swPorts.Begin (); it != swPorts.End (); it++)
    {
      NS_LOG_INFO (" Adding switch port " << *it);
      openFlowDev->AddSwitchPort (*it);
    }

  return openFlowDev;
}

Ptr<OFSwitch13Device>
OFSwitch13Helper::InstallSwitch (Ptr<Node> swNode)
{
  NS_LOG_FUNCTION (this << swNode);

  NS_LOG_INFO ("Installing OpenFlow device on node " << swNode->GetId ());
  NS_ASSERT_MSG (!m_blocked, "OpenFlow channels already configured.");

  // Install the TCP/IP stack into switch node.
  m_internet.Install (swNode);

  // Create and aggregate the OpenFlow device to the switch node.
  Ptr<OFSwitch13Device> openFlowDev = m_devFactory.Create<OFSwitch13Device> ();
  swNode->AggregateObject (openFlowDev);
  m_openFlowDevs.Add (openFlowDev);
  m_switchNodes.Add (swNode);

  return openFlowDev;
}

OFSwitch13DeviceContainer
OFSwitch13Helper::InstallSwitch (NodeContainer &swNodes)
{
  NS_LOG_FUNCTION (this);

  // Iterate over the container and add OpenFlow devices to switch nodes.
  OFSwitch13DeviceContainer openFlowDevices;
  NodeContainer::Iterator it;
  for (it = swNodes.Begin (); it != swNodes.End (); it++)
    {
      openFlowDevices.Add (InstallSwitch (*it));
    }

  return openFlowDevices;
}

void
OFSwitch13Helper::SetAddressBase (Ipv4Address network, Ipv4Mask mask,
                                  Ipv4Address base)
{
  NS_LOG_FUNCTION_NOARGS ();

  m_ipv4helper.SetBase (network, mask, base);
}

void
OFSwitch13Helper::EnableDatapathLogs (std::string prefix,
                                      bool explicitFilename)
{
  NS_LOG_FUNCTION_NOARGS ();

  // Saving library logs into output file.
  ofs::EnableLibraryLog (true, prefix, explicitFilename);
}

void
OFSwitch13Helper::DoDispose ()
{
  NS_LOG_FUNCTION (this);
}

} // namespace ns3
#endif // NS3_OFSWITCH13
