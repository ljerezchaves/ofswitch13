/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014 University of Campinas (Unicamp)
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

#include <iostream>
#include <fstream>

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/log.h"

NS_LOG_COMPONENT_DEFINE ("OFSwitch13SingleExample");

using namespace ns3;

#ifdef NS3_OFSWITCH13
#include "ns3/ofswitch13-module.h"

int
main (int argc, char *argv[])
{
  bool verbose = true;

  CommandLine cmd;
  cmd.AddValue ("verbose", "Tell application to log if true", verbose);
  cmd.Parse (argc,argv);

  if (verbose)
    {
      LogComponentEnable ("OFSwitch13SingleExample", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Helper", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13NetDevice", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Controller", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13LearningController", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Interface", LOG_LEVEL_WARN);
    }

  // Enabling Checksum computations
  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

  // Create the terminal nodes
  NodeContainer terminals;
  terminals.Create (2);

  // Create the switches node
  NodeContainer switches;
  switches.Create (1);
  Ptr<Node> switchNode = switches.Get (0);

  // Create the controller node
  NodeContainer controller;
  controller.Create (1);
  Ptr<Node> controllerNode = controller.Get (0);

  // Connect the terminals to the switch using csma links
  CsmaHelper csmaHelper;
  csmaHelper.SetChannelAttribute ("DataRate", DataRateValue (DataRate ("100Mbps")));
  csmaHelper.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (2)));
  NetDeviceContainer terminalDevices;
  NetDeviceContainer switchDevices;
  for (size_t i = 0; i < terminals.GetN (); i++)
    {
      NetDeviceContainer link = csmaHelper.Install (NodeContainer (terminals.Get (i), switches));
      terminalDevices.Add (link.Get (0));
      switchDevices.Add (link.Get (1));
    }

  // Configure OpenFlow network using the CSMA helper
  NetDeviceContainer of13Device;
  OFSwitch13CsmaHelper ofHelper;
  Ptr<OFSwitch13Controller> controlApp = ofHelper.InstallDefaultController (controllerNode);
  of13Device = ofHelper.InstallSwitch (switchNode, switchDevices);

  // Installing the tcp/ip stack onto terminals
  InternetStackHelper internet;
  internet.Install (terminals);

  // Set IPv4 terminal address
  Ipv4AddressHelper ipv4switches;
  Ipv4InterfaceContainer internetIpIfaces;
  ipv4switches.SetBase ("10.1.1.0", "255.255.255.0");
  internetIpIfaces = ipv4switches.Assign (terminalDevices);

  // Create a ping application from terminal 0 to 1
  Ipv4Address t0Addr = internetIpIfaces.GetAddress (0);
  Ipv4Address t1Addr = internetIpIfaces.GetAddress (1);
  V4PingHelper ping = V4PingHelper (t1Addr);
  ApplicationContainer pingApp = ping.Install (terminals.Get (0));
  pingApp.Start (Seconds (1.));

  // Send TCP traffic from terminal 1 to 0
  BulkSendHelper senderHelper ("ns3::TcpSocketFactory", InetSocketAddress (t0Addr, 50000));
  senderHelper.SetAttribute ("MaxBytes", UintegerValue (0));
  ApplicationContainer senderApp  = senderHelper.Install (terminals.Get (1));
  PacketSinkHelper sinkHelper ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 50000));
  ApplicationContainer sinkApp = sinkHelper.Install (terminals.Get (0));
  senderApp.Start (Seconds (1.));
  sinkApp.Start (Seconds (1.));

  // Enable pcap traces
  ofHelper.EnableOpenFlowPcap ();
  csmaHelper.EnablePcap ("ofswitch", switchDevices, true);  // promisc
  csmaHelper.EnablePcap ("terminals", terminalDevices);

  // Run the simulation
  Simulator::Stop (Seconds (30));
  Simulator::Run ();
  Simulator::Destroy ();

  Ptr<PacketSink> sink1 = DynamicCast<PacketSink> (sinkApp.Get (0));
  std::cout << "Total Bytes Received: " << sink1->GetTotalRx () << std::endl;
}

#else

int
main (int argc, char *argv[])
{
  NS_LOG_UNCOND ("OpenFlow 1.3 not enabled! Aborting...");
}

#endif // NS3_OFSWITCH13
