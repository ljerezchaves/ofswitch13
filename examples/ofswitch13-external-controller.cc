/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017 University of Campinas (Unicamp)
 *               2020 Federal University of Juiz de Fora (UFJF)
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
 *         Arthur Boechat Mazzi <arthurmazzi@ice.ufjf.br>
 *
 * There are N switches connected in line and managed by an external controller.
 * There are M hosts equally distributed among the switches.
 * Random pings among hosts.
 *
 *               External controller
 *                       |
 *               +----------------+-------- ... --------+
 *               |                |                     |
 *         +----------+     +----------+           +----------+
 *         | Switch 1 | === | Switch 2 | == ... == | Switch N |
 *         +----------+     +----------+           +----------+
 *              ||               ||                     ||
 *            Hosts            Hosts                  Hosts
 *          1, N+1, ...      2, N+2, ...            N, 2N, ...
 */

#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/csma-module.h>
#include <ns3/internet-module.h>
#include <ns3/ofswitch13-module.h>
#include <ns3/internet-apps-module.h>
#include <ns3/tap-bridge-module.h>

using namespace ns3;

int
main (int argc, char *argv[])
{
  uint16_t simTime = 100;
  bool verbose = false;
  bool trace = false;
  uint16_t numHosts = 20;
  uint16_t numSwitches = 3;
  uint16_t numPings = 20;
  uint16_t pingTime = 10;

  // Configure command line parameters
  CommandLine cmd;
  cmd.AddValue ("simTime", "Simulation time (seconds)", simTime);
  cmd.AddValue ("verbose", "Enable verbose output", verbose);
  cmd.AddValue ("trace", "Enable datapath stats and pcap traces", trace);
  cmd.AddValue ("numHosts", "Number of hosts in the simulation", numHosts);
  cmd.AddValue ("numSwitches", "Number of switches in the simulation", numSwitches);
  cmd.AddValue ("numPings", "Number of ping apps int the simulation", numPings);
  cmd.AddValue ("pingTime", "Ping time (seconds)", pingTime);
  cmd.Parse (argc, argv);

  if (verbose)
    {
      OFSwitch13Helper::EnableDatapathLogs ();
      LogComponentEnable ("OFSwitch13Interface", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Device", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Port", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Queue", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13SocketHandler", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Controller", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13LearningController", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Helper", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13InternalHelper", LOG_LEVEL_ALL);
    }

  // Enable checksum computations (required by OFSwitch13 module)
  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

  // Set simulator to real time mode
  GlobalValue::Bind ("SimulatorImplementationType", StringValue ("ns3::RealtimeSimulatorImpl"));

  // Create host nodes
  NodeContainer hosts;
  hosts.Create (numHosts);

  // Create switch nodes
  NodeContainer switches;
  switches.Create (numSwitches);

  // Use the CsmaHelper to connect host and switch
  CsmaHelper csmaHelper;
  csmaHelper.SetChannelAttribute ("DataRate", DataRateValue (DataRate ("100Mbps")));
  csmaHelper.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (2)));

  NodeContainer pair;
  NetDeviceContainer pairDevs;
  NetDeviceContainer hostDevices;
  NetDeviceContainer switchPorts [numSwitches];
  for (int i = 0; i < numSwitches; i++)
  	{
    	switchPorts [i] = NetDeviceContainer ();
  	}

  // Connect hosts to switches in round robin
  for (size_t i = 0; i < numHosts; i++)
    {
       int j = i % numSwitches;
       pair = NodeContainer (hosts.Get (i), switches.Get (j));
       pairDevs = csmaHelper.Install (pair);
       hostDevices.Add (pairDevs.Get (0));
       switchPorts [j].Add (pairDevs.Get (1));
    }

  // Connect the switches in chain
  for (int i = 0; i < numSwitches - 1; i++)
    {
      pair = NodeContainer (switches.Get (i), switches.Get (i + 1));
      pairDevs = csmaHelper.Install (pair);
      switchPorts [i].Add (pairDevs.Get (0));
      switchPorts [i + 1].Add (pairDevs.Get (1));
    }

  // Create the controller node
  Ptr<Node> controllerNode = CreateObject<Node> ();

  // Configure the OpenFlow network domain using an external controller
  Ptr<OFSwitch13ExternalHelper> of13Helper = CreateObject<OFSwitch13ExternalHelper> ();
  Ptr<NetDevice> ctrlDev = of13Helper->InstallExternalController (controllerNode);
  for (int i = 0; i < numSwitches; i++)
    {
      of13Helper->InstallSwitch (switches.Get (i), switchPorts [i]);
    }
  of13Helper->CreateOpenFlowChannels ();

  // TapBridge the controller device to local machine
  // The default configuration expects a controller on local port 6653
  TapBridgeHelper tapBridge;
  tapBridge.SetAttribute ("Mode", StringValue ("ConfigureLocal"));
  tapBridge.SetAttribute ("DeviceName", StringValue ("ctrl"));
  tapBridge.Install (controllerNode, ctrlDev);

  // Install the TCP/IP stack into hosts nodes
  InternetStackHelper internet;
  internet.Install (hosts);

  // Set IPv4 host addresses
  Ipv4AddressHelper ipv4helpr;
  Ipv4InterfaceContainer hostIpIfaces;
  ipv4helpr.SetBase ("10.1.1.0", "255.255.255.0");
  hostIpIfaces = ipv4helpr.Assign (hostDevices);

  // Random number generators for ping applications
  Ptr<UniformRandomVariable> randomHostRng = CreateObject<UniformRandomVariable> ();
  randomHostRng->SetAttribute ("Min", DoubleValue (0));
  randomHostRng->SetAttribute ("Max", DoubleValue (numHosts - 1));

  Ptr<ExponentialRandomVariable> randomStartRng = CreateObject<ExponentialRandomVariable> ();
  randomStartRng->SetAttribute ("Mean", DoubleValue (20));

  // Configure ping application between random hosts
  Time startTime = Seconds (1);
  for (int i = 0; i < numPings; i++)
    {
      int srcHost = randomHostRng->GetInteger ();
      int dstHost = randomHostRng->GetInteger ();

      V4PingHelper pingHelper = V4PingHelper (hostIpIfaces.GetAddress (dstHost));
      pingHelper.SetAttribute ("Verbose", BooleanValue (true));
      Ptr<Application> pingApp = pingHelper.Install (hosts.Get (srcHost)).Get (0);

      startTime += Seconds (std::abs (randomStartRng->GetValue ()));
      pingApp->SetStartTime (startTime);
      pingApp->SetStopTime (startTime + Seconds (pingTime));
    }

  // Enable datapath stats and pcap traces at hosts, switch(es), and controller(s)
  if (trace)
    {
      of13Helper->EnableOpenFlowPcap ("openflow");
      of13Helper->EnableDatapathStats ("switch-stats");
      csmaHelper.EnablePcap ("host", hostDevices);
      for (int i = 0; i < numSwitches; i++)
        {
          csmaHelper.EnablePcap ("switch", switchPorts [i], true);
        }
    }

  // Run the simulation
  Simulator::Stop (Seconds (simTime));
  Simulator::Run ();
  Simulator::Destroy ();
}
