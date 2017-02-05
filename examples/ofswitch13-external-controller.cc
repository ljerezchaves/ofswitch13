/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
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
 *
 * Two hosts connected through two OpenFlow switches, both managed by the same
 * external controller. UDP traffic (ping) flows between host 0 and host 1.
 *
 *                       External Controller
 *                                |
 *                       +-----------------+
 *                       |                 |
 *                  +----------+     +----------+
 *       Host 0 === | Switch 0 | === | Switch 1 | === Host 1
 *                  +----------+     +----------+
 */

#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/csma-module.h>
#include <ns3/internet-module.h>
#include <ns3/applications-module.h>
#include <ns3/ofswitch13-module.h>
#include <ns3/tap-bridge-module.h>
#include <ns3/internet-apps-module.h>

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
      OFSwitch13Helper::EnableDatapathLogs ();

      LogComponentEnable ("OFSwitch13Interface", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Helper", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13InternalHelper", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Device", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Controller", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13LearningController", LOG_LEVEL_ALL);
    }

  // Enabling Checksum computations and setting realtime simulator
  GlobalValue::Bind ("SimulatorImplementationType", StringValue ("ns3::RealtimeSimulatorImpl"));
  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

  // Create the hosts nodes
  NodeContainer hosts;
  hosts.Create (2);

  // Create the two switch nodes
  NodeContainer switches;
  switches.Create (2);

  // Create the controller node
  Ptr<Node> controllerNode = CreateObject<Node> ();

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

  // Configure the OpenFlow network using an external controller
  Ptr<OFSwitch13ExternalHelper> of13Helper = CreateObject<OFSwitch13ExternalHelper> ();
  of13Helper->InstallSwitch (switches.Get (0), switchPorts [0]);
  of13Helper->InstallSwitch (switches.Get (1), switchPorts [1]);
  Ptr<NetDevice> ctrlDev = of13Helper->InstallExternalController (controllerNode);
  of13Helper->CreateOpenFlowChannels ();

  // TapBridge the controller device to local machine
  // The default configuration expects a controller on local port 6653
  TapBridgeHelper tapBridge;
  tapBridge.SetAttribute ("Mode", StringValue ("ConfigureLocal"));
  tapBridge.SetAttribute ("DeviceName", StringValue ("ctrl"));
  tapBridge.Install (controllerNode, ctrlDev);

  // Install the TCP/IP stack into hosts
  InternetStackHelper internet;
  internet.Install (hosts);

  // Set IPv4 terminal address
  Ipv4AddressHelper ipv4switches;
  Ipv4InterfaceContainer internetIpIfaces;
  ipv4switches.SetBase ("10.1.1.0", "255.255.255.0");
  internetIpIfaces = ipv4switches.Assign (hostDevices);

  // Create the ping application from terminal 0 to 1
  Ipv4Address destAddr = internetIpIfaces.GetAddress (1);
  V4PingHelper pingHelper = V4PingHelper (destAddr);
  pingHelper.SetAttribute ("Verbose", BooleanValue (true));
  ApplicationContainer apps = pingHelper.Install (hosts.Get (0));
  apps.Start (Seconds (3));

  // Enable pcap traces and datapath stats
  if (trace)
    {
      of13Helper->EnableOpenFlowPcap ();
      of13Helper->EnableDatapathStats ();
      csmaHelper.EnablePcap ("ofswitch", switches, true);
      csmaHelper.EnablePcap ("host", hostDevices);
    }

  // Run the simulation
  Simulator::Stop (Seconds (simTime));
  Simulator::Run ();
  Simulator::Destroy ();
}
