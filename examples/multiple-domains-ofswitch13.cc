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
 * Author: Vitor M. Eichemberger <vitor.marge@gmail.com>
 *         Luciano Chaves <luciano@lrc.ic.unicamp.br>
 *
 * Two hosts connected through two OpenFlow switch managed by different
 * learning controllers. TCP traffic flows from host 0 to host 1.
 *
 *               Learning Controller
 *                       |
 *                       |        Learning Controller
 *                       |                |
 *                  +----------+     +----------+
 *       Host 0 === | Switch 0 | === | Switch 1 | === Host 1
 *                  +----------+     +----------+
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/ofswitch13-module.h"

using namespace ns3;

int
main (int argc, char *argv[])
{
  bool verbose = false;
  bool trace = false;
  uint16_t simTime = 30;

  // Configure command line parameters
  CommandLine cmd;
  cmd.AddValue ("verbose", "Enable verbose output", verbose);
  cmd.AddValue ("trace", "Enable pcap trace files output", trace);
  cmd.AddValue ("simTime", "Simulation time", simTime);
  cmd.Parse (argc, argv);

  if (verbose)
    {
      LogComponentEnable ("OFSwitch13Interface", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Helper", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Device", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Controller", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13LearningController", LOG_LEVEL_ALL);
    }

  // Enabling Checksum computations
  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

  // Creating two host nodes
  NodeContainer hosts;
  hosts.Create (2);

  // Create the two switch nodes
  NodeContainer switches;
  switches.Create (2);

  // Create the two controller nodes
  NodeContainer controllers;
  controllers.Create (2);

  // Use the CsmaHelper to connect the host nodes to the switch.
  CsmaHelper csmaHelper;
  csmaHelper.SetChannelAttribute ("DataRate", DataRateValue (DataRate ("100Mbps")));
  csmaHelper.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (2)));

  NodeContainer pair;
  NetDeviceContainer pairDevs;
  NetDeviceContainer hostDevices;
  NetDeviceContainer switchPorts [2];
  switchPorts [0] = NetDeviceContainer ();
  switchPorts [1] = NetDeviceContainer ();

  // Connect host 0 to first switch
  pair = NodeContainer (hosts.Get (0), switches.Get (0));
  pairDevs = csmaHelper.Install (pair);
  hostDevices.Add (pairDevs.Get (0));
  switchPorts [0].Add (pairDevs.Get (1));

  // Connect host 1 to second switch
  pair = NodeContainer (hosts.Get (1), switches.Get (1));
  pairDevs = csmaHelper.Install (pair);
  hostDevices.Add (pairDevs.Get (0));
  switchPorts [1].Add (pairDevs.Get (1));

  // Connect the switches
  pair = NodeContainer (switches.Get (0), switches.Get (1));
  pairDevs = csmaHelper.Install (pair);
  switchPorts [0].Add (pairDevs.Get (0));
  switchPorts [1].Add (pairDevs.Get (1));

  // Configure the OpenFlow network
  Ptr<OFSwitch13Helper> of13Helper0 = CreateObject<OFSwitch13Helper> ();
  of13Helper0->InstallDefaultController (controllers.Get (0));
  of13Helper0->InstallSwitch (switches.Get (0), switchPorts [0]);
  of13Helper0->CreateOpenFlowChannels ();

  Ptr<OFSwitch13Helper> of13Helper1 = CreateObject<OFSwitch13Helper> ();
  of13Helper1->SetAddressBase ("10.100.151.0", "255.255.255.0");
  of13Helper1->InstallDefaultController (controllers.Get (1));
  of13Helper1->InstallSwitch (switches.Get (1), switchPorts [1]);
  of13Helper1->CreateOpenFlowChannels ();

  // Install the TCP/IP stack into hosts
  InternetStackHelper internet;
  internet.Install (hosts);

  // Set IPv4 terminal address
  Ipv4AddressHelper ipv4switches;
  Ipv4InterfaceContainer internetIpIfaces;
  ipv4switches.SetBase ("10.1.1.0", "255.255.255.0");
  internetIpIfaces = ipv4switches.Assign (hostDevices);

  // Send TCP traffic from host 0 to 1
  Ipv4Address dstAddr = internetIpIfaces.GetAddress (1);
  BulkSendHelper senderHelper ("ns3::TcpSocketFactory", InetSocketAddress (dstAddr, 9));
  senderHelper.Install (hosts.Get (0));
  PacketSinkHelper sinkHelper ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 9));
  ApplicationContainer sinkApp = sinkHelper.Install (hosts.Get (1));

  // Enable datapath logs
  if (verbose)
    {
      of13Helper0->EnableDatapathLogs ("all");
      of13Helper1->EnableDatapathLogs ("all");
    }

  // Enable pcap traces
  if (trace)
    {
      of13Helper0->EnableOpenFlowPcap ();
      of13Helper1->EnableOpenFlowPcap ();
      csmaHelper.EnablePcap ("ofswitch", switches, true);
      csmaHelper.EnablePcap ("host", hostDevices);
    }

  // Run the simulation
  Simulator::Stop (Seconds (simTime));
  Simulator::Run ();
  Simulator::Destroy ();

  // Print transmitted bytes
  Ptr<PacketSink> sink = DynamicCast<PacketSink> (sinkApp.Get (0));
  std::cout << "Total bytes sent from host 0 to host 1: " << sink->GetTotalRx () << std::endl;
}
