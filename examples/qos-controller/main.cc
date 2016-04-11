/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2016 University of Campinas (Unicamp)
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
 * Author:  Luciano Chaves <luciano@lrc.ic.unicamp.br>
 */

/**
 *   Servers                 OpenFlow controllers                Clients
 *  +-------+             +-------+       +-------+             +-------+
 *  | Srv 0 |=======+   +=| Ctr 0 |=+     | Ctr 1 |=+   +=======| Cli 0 |
 *  +-------+       |   | +-------+ |     +-------+ |   |       +-------+
 *                  |   |           |               |   |
 *                +-------+       +-------+       +-------+     +-------+
 *                | Swt 0 |#######| Swt 1 |=======| Swt 2 |=====| Cli 1 |
 *                +-------+       +-------+       +-------+     +-------+
 *                  |         OpenFlow switches         |          ...
 *  +-------+       |                                   |       +-------+
 *  | Srv 1 |=======+                                   +=======| Cli N |
 *  +-------+                                                   +-------+
 *
 *  Swt 0 --> Border switch
 *  Swt 1 --> Aggregation switch
 *  Swt 2 --> Client switch
 *
 *  Ctr 0 --> QoS controller
 *  Ctr 1 --> Learning controller
 *
 *  ====  --> 100 Mbps CSMA links
 *  ####  --> 2 x 10 Mbps CSMA links
 *
 **/

#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/csma-module.h>
#include <ns3/internet-module.h>
#include <ns3/applications-module.h>
#include <ns3/ofswitch13-module.h>
#include "qos-controller.h"

using namespace ns3;

int
main (int argc, char *argv[])
{
  // Configure dedicated connections between controller and switches
  Config::SetDefault ("ns3::OFSwitch13Helper::ChannelType",
                      EnumValue (OFSwitch13Helper::DEDICATEDCSMA));

  // Increase TCP MSS for larger packets
  Config::SetDefault ("ns3::TcpSocket::SegmentSize", UintegerValue (1400));

  // Enable Checksum computations
  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

  bool verbose = false;
  bool trace = false;
  uint16_t numNodes = 4;
  uint16_t simTime = 101;

  CommandLine cmd;
  cmd.AddValue ("verbose", "Verbose log if true", verbose);
  cmd.AddValue ("trace", "Trace files if true", trace);
  cmd.AddValue ("clientNodes", "Number of client nodes", numNodes);
  cmd.AddValue ("simulationTime", "Simulation time", simTime);
  cmd.Parse (argc, argv);

  if (verbose)
    {
      LogComponentEnable ("OFSwitch13Helper", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Device", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Interface", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Controller", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13LearningController", LOG_LEVEL_ALL);
      LogComponentEnable ("QosController", LOG_LEVEL_ALL);
    }

  // Discard the firt MAC address for border switch
  Mac48Address::Allocate ();

  // Create the server, client, switch and controller nodes
  NodeContainer serverNodes, clientNodes, switchNodes, controllerNodes;
  serverNodes.Create (2);
  switchNodes.Create (3);
  controllerNodes.Create (2);
  clientNodes.Create (numNodes);

  // Create device containers
  NetDeviceContainer serverDevices, clientDevices;
  NetDeviceContainer switch0Ports, switch1Ports, switch2Ports;
  NetDeviceContainer link;

  // Create two connections between switch 0 and switch 1, with narrowband connection
  CsmaHelper csmaHelper;
  csmaHelper.SetChannelAttribute ("DataRate", DataRateValue (DataRate ("10Mbps")));

  link = csmaHelper.Install (NodeContainer (switchNodes.Get (0), switchNodes.Get (1)));
  switch0Ports.Add (link.Get (0));
  switch1Ports.Add (link.Get (1));

  link = csmaHelper.Install (NodeContainer (switchNodes.Get (0), switchNodes.Get (1)));
  switch0Ports.Add (link.Get (0));
  switch1Ports.Add (link.Get (1));

  // Configure the CsmaHelper for broadband connection
  csmaHelper.SetChannelAttribute ("DataRate", DataRateValue (DataRate ("100Mbps")));

  // Connect switch 1 to switch 2
  link = csmaHelper.Install (NodeContainer (switchNodes.Get (1), switchNodes.Get (2)));
  switch1Ports.Add (link.Get (0));
  switch2Ports.Add (link.Get (1));

  // Connect server 0 and 1 to switch 0
  link = csmaHelper.Install (NodeContainer (serverNodes.Get (0), switchNodes.Get (0)));
  serverDevices.Add (link.Get (0));
  switch0Ports.Add (link.Get (1));

  link = csmaHelper.Install (NodeContainer (serverNodes.Get (1), switchNodes.Get (0)));
  serverDevices.Add (link.Get (0));
  switch0Ports.Add (link.Get (1));

  // Connect client nodes to switch 2
  for (size_t i = 0; i < numNodes; i++)
    {
      link = csmaHelper.Install (NodeContainer (clientNodes.Get (i), switchNodes.Get (2)));
      clientDevices.Add (link.Get (0));
      switch2Ports.Add (link.Get (1));
    }

  // Configure OpenFlow QoS controller for switchs 0 and 1 into controller node 0
  Ptr<OFSwitch13Helper> ofQosHelper = CreateObject<OFSwitch13Helper> ();
  Ptr<QosController> qosCtrl = CreateObject<QosController> ();
  ofQosHelper->InstallControllerApp (controllerNodes.Get (0), qosCtrl);

  // Configure OpenFlow learning controller for switch 2 into controller node 1
  // Note that for using two different controllers in the same simulation
  // script it is necessary to change the addresse network used by the helper
  // to configure the OpenFlow channels.
  Ptr<OFSwitch13Helper> ofLearningHelper = CreateObject<OFSwitch13Helper> ();
  ofLearningHelper->SetAddressBase ("10.100.151.0", "255.255.255.252");
  Ptr<OFSwitch13LearningController> learningCtrl = CreateObject<OFSwitch13LearningController> ();
  ofLearningHelper->InstallControllerApp (controllerNodes.Get (1), learningCtrl);

  // Install OpenFlow switches 0 and 1 with border controller
  OFSwitch13DeviceContainer ofSwitchDevices;
  ofSwitchDevices.Add (ofQosHelper->InstallSwitch (switchNodes.Get (0), switch0Ports));
  ofSwitchDevices.Add (ofQosHelper->InstallSwitch (switchNodes.Get (1), switch1Ports));

  // Install OpenFlow switches 2 with learning controller
  ofSwitchDevices.Add (ofLearningHelper->InstallSwitch (switchNodes.Get (2), switch2Ports));

  // Install the tcp/ip stack into hosts
  InternetStackHelper internet;
  internet.Install (serverNodes);
  internet.Install (clientNodes);

  // Set IPv4 server and client addresses
  Ipv4AddressHelper ipv4switches;
  Ipv4InterfaceContainer internetIpIfaces;
  ipv4switches.SetBase ("10.1.1.0", "255.255.255.0", "0.0.0.2");
  internetIpIfaces = ipv4switches.Assign (serverDevices);
  internetIpIfaces = ipv4switches.Assign (clientDevices);

  // Configure applications for traffic generation. Client hosts send traffic to
  // server. The server IP address 10.1.1.1 is attended by the border switch,
  // which redirects the traffic to  internal servers, equalizing the number of
  // connections to each server.
  Ipv4Address serverAddr ("10.1.1.1");

  // Installing a sink application at server nodes
  PacketSinkHelper sinkHelper ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 9));
  ApplicationContainer sinkApps = sinkHelper.Install (serverNodes);
  sinkApps.Start (Seconds (0));

  // Installing a sender application at client nodes
  BulkSendHelper senderHelper ("ns3::TcpSocketFactory", InetSocketAddress (serverAddr, 9));
  ApplicationContainer senderApps = senderHelper.Install (clientNodes);

  // Get random start times
  Ptr<UniformRandomVariable> randomStart = CreateObject<UniformRandomVariable> ();
  randomStart->SetAttribute ("Min", DoubleValue (0));
  randomStart->SetAttribute ("Max", DoubleValue (1));
  ApplicationContainer::Iterator appIt;
  for (appIt = senderApps.Begin (); appIt != senderApps.End (); ++appIt)
    {
      (*appIt)->SetStartTime (Seconds (randomStart->GetValue ()));
    }

  // Enable datapath logs
  if (verbose)
    {
      ofLearningHelper->EnableDatapathLogs ("all");
      ofQosHelper->EnableDatapathLogs ("all");
    }

  // Enable pcap traces
  if (trace)
    {
      ofLearningHelper->EnableOpenFlowPcap ();
      ofQosHelper->EnableOpenFlowPcap ();
      csmaHelper.EnablePcap ("ofswitch", switchNodes, true);
      csmaHelper.EnablePcap ("server", serverDevices);
      csmaHelper.EnablePcap ("client", clientDevices);
    }

  // Run the simulation for simTime seconds
  Simulator::Stop (Seconds (simTime));
  Simulator::Run ();
  Simulator::Destroy ();

  // Dump total of received bytes by sink applications
  Ptr<PacketSink> sink1 = DynamicCast<PacketSink> (sinkApps.Get (0));
  Ptr<PacketSink> sink2 = DynamicCast<PacketSink> (sinkApps.Get (1));
  std::cout << "Bytes received by server 1: " << sink1->GetTotalRx () << " ("
            << (8. * sink1->GetTotalRx ()) / 1000000 / simTime << " Mbps)" << std::endl;
  std::cout << "Bytes received by server 2: " << sink2->GetTotalRx () << " ("
            << (8. * sink2->GetTotalRx ()) / 1000000 / simTime << " Mbps)" << std::endl;
}

