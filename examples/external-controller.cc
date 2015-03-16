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
 *
 * Connecting a single OpenFlow 1.3 switch to a external controller. 
 * Traffic flows from host H0 to host H1.
 *
 *          H0
 *          |
 *       -------
 *       | Sw0 | --- External controller (TapBrigde)
 *       -------
 *          |
 *          H1
 *
 * FIXME: Not sure that this example is ok. 
 */

#include <iostream>
#include <fstream>
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/ofswitch13-module.h"
#include "ns3/tap-bridge-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("ExtCtrlOFSwitch13");

int
main (int argc, char *argv[])
{
  bool verbose = true;
  bool trace = false;
  std::string tapName = "thetap";

  CommandLine cmd;
  cmd.AddValue ("verbose", "Tell application to log if true", verbose);
  cmd.AddValue ("trace", "Tracing traffic to files", trace);
  cmd.Parse (argc, argv);

  if (verbose)
    {
      LogComponentEnable ("ExtCtrlOFSwitch13", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Helper", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13NetDevice", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Controller", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13LearningController", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Interface", LOG_LEVEL_ALL);
    }

  // Enabling Checksum computations and setting realtime simulator
  GlobalValue::Bind ("SimulatorImplementationType", StringValue ("ns3::RealtimeSimulatorImpl"));
  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

  // Create the hosts nodes
  NodeContainer hosts;
  hosts.Create (2);

  // Create the switch
  Ptr<Node> of13SwitchNode = CreateObject<Node> ();

  // Configure the CsmaHelper
  CsmaHelper csmaHelper;
  csmaHelper.SetChannelAttribute ("DataRate", DataRateValue (DataRate ("100Mbps")));
  csmaHelper.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (2)));
  
  NetDeviceContainer hostDevices;
  NetDeviceContainer of13SwitchPorts;
  for (size_t i = 0; i < hosts.GetN (); i++)
    {
      NodeContainer nc (hosts.Get (i), of13SwitchNode);
      NetDeviceContainer link = csmaHelper.Install (nc);
      hostDevices.Add (link.Get (0));
      of13SwitchPorts.Add (link.Get (1));
    }

  // First configure OpenFlow network with external controller
  Ptr<Node> controllerNode = CreateObject<Node> ();
  Ptr<OFSwitch13Helper> of13Helper = CreateObject<OFSwitch13Helper> ();
  of13Helper->SetAttribute ("ChannelType", EnumValue (OFSwitch13Helper::SINGLECSMA));
  Ptr<NetDevice> ctrlDev = of13Helper->InstallExternalController (controllerNode);

  // TapBridge to local machine
  // The default configuration expects a controller on you local machine at port 6653
  TapBridgeHelper tapBridge;
  tapBridge.SetAttribute ("Mode", StringValue ("ConfigureLocal"));
  tapBridge.SetAttribute ("DeviceName", StringValue ("ctrl"));
  tapBridge.Install (controllerNode, ctrlDev);

  // Then install the switches (now they will start a connection to controller)
  NetDeviceContainer of13Device;
  of13Device = of13Helper->InstallSwitch (of13SwitchNode, of13SwitchPorts);

  // Installing the tcp/ip stack onto hosts
  InternetStackHelper internet;
  internet.Install (hosts);

  // Set IPv4 terminal address
  Ipv4AddressHelper ipv4switches;
  Ipv4InterfaceContainer internetIpIfaces;
  ipv4switches.SetBase ("10.1.1.0", "255.255.255.0");
  internetIpIfaces = ipv4switches.Assign (hostDevices);

  // Create a ping application from terminal 0 to 1
  Ipv4Address destAddr = internetIpIfaces.GetAddress (1);
  V4PingHelper ping = V4PingHelper (destAddr);
  ApplicationContainer apps = ping.Install (hosts.Get (0));
  apps.Start (Seconds (5.));

  // Enable datapath logs
  if (verbose)
    {
      of13Helper->EnableDatapathLogs ("all");
    }

  // Enable pcap traces
  if (trace)
    {
      of13Helper->EnableOpenFlowPcap ("ofCtrl");
      csmaHelper.EnablePcap ("ofswitch", NodeContainer (of13SwitchNode), true);
      csmaHelper.EnablePcap ("host", hostDevices);
    }

  // Run the simulation
  Simulator::Stop (Seconds (30));
  Simulator::Run ();
  Simulator::Destroy ();
}

