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
 *
 * - This is the internal network of an organization.
 * - 2 servers and N client nodes are located far from each other.
 * - Between border and aggregation switches there are two narrowband links of
 *   10 Mbps each. Other local connections have links of 100 Mbps.
 * - The default learning application manages the client switch.
 * - An specialized OpenFlow QoS controller is used to manage the border and
 *   aggregation switches, balancing traffic among internal servers and
 *   aggregating narrowband links to increase throughput.
 *
 *                          QoS controller       Learning controller
 *                                |                       |
 *                         +--------------+               |
 *  +----------+           |              |               |           +----------+
 *  | Server 0 | ==== +--------+      +--------+      +--------+ ==== | Client 0 |
 *  +----------+      | Border | ~~~~ | Aggreg |      | Client |      +----------+
 *  +----------+      | Switch | ~~~~ | Switch | ==== | Switch |      +----------+
 *  | Server 1 | ==== +--------+      +--------+      +--------+ ==== | Client N |
 *  +----------+                 2x10            100                  +----------+
 *                               Mbps            Mbps
 **/

#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/csma-module.h>
#include <ns3/internet-module.h>
#include <ns3/applications-module.h>
#include <ns3/ofswitch13-module.h>
#include <ns3/netanim-module.h>
#include <ns3/mobility-module.h>
#include "qos-controller.h"

using namespace ns3;

int
main (int argc, char *argv[])
{
  uint16_t clients = 2;
  uint16_t simTime = 10;
  bool verbose = false;
  bool trace = false;

  // Configure command line parameters
  CommandLine cmd;
  cmd.AddValue ("clients", "Number of client nodes", clients);
  cmd.AddValue ("simTime", "Simulation time (seconds)", simTime);
  cmd.AddValue ("verbose", "Enable verbose output", verbose);
  cmd.AddValue ("trace", "Enable datapath stats and pcap traces", trace);
  cmd.Parse (argc, argv);

  if (verbose)
    {
      OFSwitch13Helper::EnableDatapathLogs ();
      LogComponentEnable ("OFSwitch13Device", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Port", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Queue", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13SocketHandler", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Controller", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13LearningController", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Helper", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13InternalHelper", LOG_LEVEL_ALL);
      LogComponentEnable ("QosController", LOG_LEVEL_ALL);
    }

  // Configure dedicated connections between controller and switches
  Config::SetDefault ("ns3::OFSwitch13Helper::ChannelType", EnumValue (OFSwitch13Helper::DEDICATEDCSMA));

  // Increase TCP MSS for larger packets
  Config::SetDefault ("ns3::TcpSocket::SegmentSize", UintegerValue (1400));

  // Enable checksum computations (required by OFSwitch13 module)
  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

  // Discard the first MAC address ("00:00:00:00:00:01") which will be used by
  // the border switch in association with the first IP address ("10.1.1.1")
  // for the Internet service.
  Mac48Address::Allocate ();

  // Create nodes for servers, switches, controllers and clients
  NodeContainer serverNodes, switchNodes, controllerNodes, clientNodes;
  serverNodes.Create (2);
  switchNodes.Create (3);
  controllerNodes.Create (2);
  clientNodes.Create (clients);

  // Setting node positions for NetAnim support
  Ptr<ListPositionAllocator> listPosAllocator;
  listPosAllocator = CreateObject<ListPositionAllocator> ();
  listPosAllocator->Add (Vector (  0,  0, 0));  // Server 0
  listPosAllocator->Add (Vector (  0, 75, 0));  // Server 1
  listPosAllocator->Add (Vector ( 50, 50, 0));  // Border switch
  listPosAllocator->Add (Vector (100, 50, 0));  // Aggregation switch
  listPosAllocator->Add (Vector (150, 50, 0));  // Client switch
  listPosAllocator->Add (Vector ( 75, 25, 0));  // QoS controller
  listPosAllocator->Add (Vector (150, 25, 0));  // Learning controller
  for (size_t i = 0; i < clients; i++)
    {
      listPosAllocator->Add (Vector (200, 25 * i, 0)); // Clients
    }

  MobilityHelper mobilityHelper;
  mobilityHelper.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobilityHelper.SetPositionAllocator (listPosAllocator);
  mobilityHelper.Install (NodeContainer (serverNodes, switchNodes, controllerNodes, clientNodes));

  // Create device containers
  NetDeviceContainer serverDevices, clientDevices;
  NetDeviceContainer switch0Ports, switch1Ports, switch2Ports;
  NetDeviceContainer link;

  // Create two 10Mbps connections between border and aggregation switches
  CsmaHelper csmaHelper;
  csmaHelper.SetChannelAttribute ("DataRate", DataRateValue (DataRate ("10Mbps")));

  link = csmaHelper.Install (NodeContainer (switchNodes.Get (0), switchNodes.Get (1)));
  switch0Ports.Add (link.Get (0));
  switch1Ports.Add (link.Get (1));

  link = csmaHelper.Install (NodeContainer (switchNodes.Get (0), switchNodes.Get (1)));
  switch0Ports.Add (link.Get (0));
  switch1Ports.Add (link.Get (1));

  // Configure the CsmaHelper for 100Mbps connections
  csmaHelper.SetChannelAttribute ("DataRate", DataRateValue (DataRate ("100Mbps")));

  // Connect aggregation switch to client switch
  link = csmaHelper.Install (NodeContainer (switchNodes.Get (1), switchNodes.Get (2)));
  switch1Ports.Add (link.Get (0));
  switch2Ports.Add (link.Get (1));

  // Connect servers to border switch
  link = csmaHelper.Install (NodeContainer (serverNodes.Get (0), switchNodes.Get (0)));
  serverDevices.Add (link.Get (0));
  switch0Ports.Add (link.Get (1));

  link = csmaHelper.Install (NodeContainer (serverNodes.Get (1), switchNodes.Get (0)));
  serverDevices.Add (link.Get (0));
  switch0Ports.Add (link.Get (1));

  // Connect client nodes to client switch
  for (size_t i = 0; i < clients; i++)
    {
      link = csmaHelper.Install (NodeContainer (clientNodes.Get (i), switchNodes.Get (2)));
      clientDevices.Add (link.Get (0));
      switch2Ports.Add (link.Get (1));
    }

  // Configure OpenFlow QoS controller for border and aggregation switches
  // (#0 and #1) into controller node 0.
  Ptr<OFSwitch13InternalHelper> ofQosHelper =
    CreateObject<OFSwitch13InternalHelper> ();
  Ptr<QosController> qosCtrl = CreateObject<QosController> ();
  ofQosHelper->InstallController (controllerNodes.Get (0), qosCtrl);

  // Configure OpenFlow learning controller for client switch (#2) into controller node 1
  Ptr<OFSwitch13InternalHelper> ofLearningHelper = CreateObject<OFSwitch13InternalHelper> ();
  Ptr<OFSwitch13LearningController> learnCtrl = CreateObject<OFSwitch13LearningController> ();
  ofLearningHelper->InstallController (controllerNodes.Get (1), learnCtrl);

  // Install OpenFlow switches 0 and 1 with border controller
  OFSwitch13DeviceContainer ofSwitchDevices;
  ofSwitchDevices.Add (ofQosHelper->InstallSwitch (switchNodes.Get (0), switch0Ports));
  ofSwitchDevices.Add (ofQosHelper->InstallSwitch (switchNodes.Get (1), switch1Ports));
  ofQosHelper->CreateOpenFlowChannels ();

  // Install OpenFlow switches 2 with learning controller
  ofSwitchDevices.Add (ofLearningHelper->InstallSwitch (switchNodes.Get (2), switch2Ports));
  ofLearningHelper->CreateOpenFlowChannels ();

  // Install the TCP/IP stack into hosts nodes
  InternetStackHelper internet;
  internet.Install (serverNodes);
  internet.Install (clientNodes);

  // Set IPv4 server and client addresses (discarding the first server address)
  Ipv4AddressHelper ipv4switches;
  Ipv4InterfaceContainer internetIpIfaces;
  ipv4switches.SetBase ("10.1.0.0", "255.255.0.0", "0.0.1.2");
  internetIpIfaces = ipv4switches.Assign (serverDevices);
  ipv4switches.SetBase ("10.1.0.0", "255.255.0.0", "0.0.2.1");
  internetIpIfaces = ipv4switches.Assign (clientDevices);

  // Configure applications for traffic generation. Client hosts send traffic
  // to server. The server IP address 10.1.1.1 is attended by the border
  // switch, which redirects the traffic to internal servers, equalizing the
  // number of connections to each server.
  Ipv4Address serverAddr ("10.1.1.1");

  // Installing a sink application at server nodes
  PacketSinkHelper sinkHelper ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 9));
  ApplicationContainer sinkApps = sinkHelper.Install (serverNodes);
  sinkApps.Start (Seconds (0));

  // Installing a sender application at client nodes
  BulkSendHelper senderHelper ("ns3::TcpSocketFactory", InetSocketAddress (serverAddr, 9));
  ApplicationContainer senderApps = senderHelper.Install (clientNodes);

  // Get random start times
  Ptr<UniformRandomVariable> rngStart = CreateObject<UniformRandomVariable> ();
  rngStart->SetAttribute ("Min", DoubleValue (0));
  rngStart->SetAttribute ("Max", DoubleValue (1));
  ApplicationContainer::Iterator appIt;
  for (appIt = senderApps.Begin (); appIt != senderApps.End (); ++appIt)
    {
      (*appIt)->SetStartTime (Seconds (rngStart->GetValue ()));
    }

  // Enable pcap traces and datapath stats
  if (trace)
    {
      ofLearningHelper->EnableOpenFlowPcap ("openflow");
      ofLearningHelper->EnableDatapathStats ("switch-stats");
      ofQosHelper->EnableOpenFlowPcap ("openflow");
      ofQosHelper->EnableDatapathStats ("switch-stats");
      csmaHelper.EnablePcap ("switch", switchNodes, true);
      csmaHelper.EnablePcap ("server", serverDevices);
      csmaHelper.EnablePcap ("client", clientDevices);
    }

  // Creating NetAnim output file
  AnimationInterface anim ("qosctrl-netanim.xml");
  anim.SetStartTime (Seconds (0));
  anim.SetStopTime (Seconds (4));

  // Set NetAnim node descriptions
  anim.UpdateNodeDescription (0, "Server 0");
  anim.UpdateNodeDescription (1, "Server 1");
  anim.UpdateNodeDescription (2, "Border switch");
  anim.UpdateNodeDescription (3, "Aggregation switch");
  anim.UpdateNodeDescription (4, "Client switch");
  anim.UpdateNodeDescription (5, "QoS controller");
  anim.UpdateNodeDescription (6, "Learning controller");
  for (size_t i = 0; i < clients; i++)
    {
      std::ostringstream desc;
      desc << "Client " << i;
      anim.UpdateNodeDescription (7 + i, desc.str ());
    }

  // Set NetAnim icon images and size
  char cwd [1024];
  if (getcwd (cwd, sizeof (cwd)) != NULL)
    {
      std::string path = std::string (cwd) +
        "/src/ofswitch13/examples/qos-controller/images/";
      uint32_t serverImg = anim.AddResource (path + "server.png");
      uint32_t switchImg = anim.AddResource (path + "switch.png");
      uint32_t controllerImg = anim.AddResource (path + "controller.png");
      uint32_t clientImg = anim.AddResource (path + "client.png");

      anim.UpdateNodeImage (0, serverImg);
      anim.UpdateNodeImage (1, serverImg);
      anim.UpdateNodeImage (2, switchImg);
      anim.UpdateNodeImage (3, switchImg);
      anim.UpdateNodeImage (4, switchImg);
      anim.UpdateNodeImage (5, controllerImg);
      anim.UpdateNodeImage (6, controllerImg);
      for (size_t i = 0; i < clients; i++)
        {
          anim.UpdateNodeImage (i + 7, clientImg);
        }
      for (size_t i = 0; i < clients + 7U; i++)
        {
          anim.UpdateNodeSize (i, 10, 10);
        }
    }

  // Run the simulation
  Simulator::Stop (Seconds (simTime));
  Simulator::Run ();
  Simulator::Destroy ();

  // Dump total of received bytes by sink applications
  Ptr<PacketSink> sink1 = DynamicCast<PacketSink> (sinkApps.Get (0));
  Ptr<PacketSink> sink2 = DynamicCast<PacketSink> (sinkApps.Get (1));
  std::cout << "Bytes received by server 1: " << sink1->GetTotalRx () << " ("
            << (8. * sink1->GetTotalRx ()) / 1000000 / simTime << " Mbps)"
            << std::endl;
  std::cout << "Bytes received by server 2: " << sink2->GetTotalRx () << " ("
            << (8. * sink2->GetTotalRx ()) / 1000000 / simTime << " Mbps)"
            << std::endl;
}
