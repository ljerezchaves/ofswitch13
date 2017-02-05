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
 * Author: Luciano Chaves <luciano@lrc.ic.unicamp.br>
 *
 * Two hosts connected through two OpenFlow switches, both managed by the
 * tunnel controller. Traffic between the switches are encapsulated with
 * GTP/UDP/IP protocols, to illustrate how logical ports can be used on
 * OpenFlow switches. The internal switch organization follows the same
 * principles of SgwPgw node from the LTE module.
 * TCP traffic flows from host 0 to host 1.
 *
 *                         Tunnel Controller
 *                                 |
 *                       +-------------------+
 *                       |                   |
 *                  +----------+       +----------+
 *       Host 0 === | Switch 0 | OOOOO | Switch 1 | === Host 1
 *                  +----------+       +----------+
 */

#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/csma-module.h>
#include <ns3/internet-module.h>
#include <ns3/applications-module.h>
#include <ns3/ofswitch13-module.h>
#include "tunnel-controller.h"
#include "tunnel-user-app.h"

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
      LogComponentEnable ("OFSwitch13Device", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Port", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Controller", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13LearningController", LOG_LEVEL_ALL);

      LogComponentEnable ("TunnelController", LOG_LEVEL_ALL);
      LogComponentEnable ("TunnelUserApp", LOG_LEVEL_ALL);
    }

  // Enabling Checksum computations
  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));
  Packet::EnablePrinting ();

  // Creating two host nodes
  NodeContainer hosts;
  hosts.Create (2);

  // Install the TCP/IP stack into hosts
  InternetStackHelper internet;
  internet.Install (hosts);

  // Create the two switch nodes
  NodeContainer switches;
  switches.Create (2);

  // Create the controller node
  Ptr<Node> controllerNode = CreateObject<Node> ();

  // Starting the OpenFlow network configuration
  Ptr<OFSwitch13Helper> of13Helper = CreateObject<OFSwitch13Helper> ();
  Ptr<TunnelController> ofController = CreateObject<TunnelController> ();
  of13Helper->InstallController (controllerNode, ofController);
  OFSwitch13DeviceContainer ofDevices = of13Helper->InstallSwitch (switches);
  Ptr<OFSwitch13Device> sw0 = ofDevices.Get (0);
  Ptr<OFSwitch13Device> sw1 = ofDevices.Get (1);

  // Use the CsmaHelper to connect the host nodes to the switch.
  CsmaHelper csmaHelper;
  csmaHelper.SetChannelAttribute ("DataRate", DataRateValue (DataRate ("100Mbps")));
  csmaHelper.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (2)));

  NetDeviceContainer pairDevs;
  NetDeviceContainer hostDevices;
  NetDeviceContainer hostSwitchDevices;

  // Connect host 0 to switch 0
  pairDevs = csmaHelper.Install (NodeContainer (hosts.Get (0), switches.Get (0)));
  hostDevices.Add (pairDevs.Get (0));
  hostSwitchDevices.Add (pairDevs.Get (1));
  sw0->AddSwitchPort (pairDevs.Get (1));  // Port #1 at switch 0

  // Connect host 1 to switch 1
  pairDevs = csmaHelper.Install (NodeContainer (hosts.Get (1), switches.Get (1)));
  hostDevices.Add (pairDevs.Get (0));
  hostSwitchDevices.Add (pairDevs.Get (1));
  sw1->AddSwitchPort (pairDevs.Get (1));  // Port #1 at switch 1

  // Set IPv4 address to hosts on different networks.
  Ipv4InterfaceContainer hostIpIfaces;
  Ipv4InterfaceContainer ipIfaces;
  Ipv4AddressHelper ipv4Helper;
  Ipv4Address sw0GatewayIp, sw1GatewayIp;

  ipv4Helper.SetBase ("10.1.1.0", "255.255.255.0");
  ipIfaces = ipv4Helper.Assign (NetDeviceContainer (hostDevices.Get (0)));
  hostIpIfaces.Add (ipIfaces.Get (0));
  sw0GatewayIp = ipv4Helper.NewAddress ();    // 10.1.1.2

  ipv4Helper.SetBase ("10.2.2.0", "255.255.255.0");
  ipIfaces = ipv4Helper.Assign (NetDeviceContainer (hostDevices.Get (1)));
  hostIpIfaces.Add (ipIfaces.Get (0));
  sw1GatewayIp = ipv4Helper.NewAddress ();    // 10.2.2.2

  // Configure static routes on host nodes and set the gateway IP address that
  // will be used by the controller to respond ARP requests.
  ofController->SaveArpEntry (
    sw0GatewayIp, Mac48Address::ConvertFrom (
      hostSwitchDevices.Get (0)->GetAddress ()));
  ofController->SaveArpEntry (
    sw1GatewayIp, Mac48Address::ConvertFrom (
      hostSwitchDevices.Get (1)->GetAddress ()));
  ofController->SaveArpEntry (
    hostIpIfaces.GetAddress (0), Mac48Address::ConvertFrom (
      hostDevices.Get (0)->GetAddress ()));
  ofController->SaveArpEntry (
    hostIpIfaces.GetAddress (1), Mac48Address::ConvertFrom (
      hostDevices.Get (1)->GetAddress ()));

  Ipv4StaticRoutingHelper ipv4RoutingHelper;
  Ptr<Ipv4StaticRouting> hostStaticRouting;

  hostStaticRouting =
    ipv4RoutingHelper.GetStaticRouting (hosts.Get (0)->GetObject<Ipv4> ());
  hostStaticRouting->AddNetworkRouteTo (
    Ipv4Address ("10.2.2.0"), Ipv4Mask ("255.255.255.0"),
    Ipv4Address ("10.1.1.2"), 1);

  hostStaticRouting =
    ipv4RoutingHelper.GetStaticRouting (hosts.Get (1)->GetObject<Ipv4> ());
  hostStaticRouting->AddNetworkRouteTo (
    Ipv4Address ("10.1.1.0"), Ipv4Mask ("255.255.255.0"),
    Ipv4Address ("10.2.2.2"), 1);

  //
  // Connect switch 0 to switch 1. These CSMA devices will not be added as
  // switch ports. Instead, each one will be configured as standard ns-3 device
  // (with IP address and an UDP socket binded to it). They will be used to
  // implement the UDP/IP tunneling process. The TunnelUserApp application
  // running on top of the UDP socket will be in change of adding and removing
  // the GTP headers, and forwarding the packets to a VirtualNetDevice device
  // on the same node. This VirtualNetDevice will be configured as switch port
  // and will finally interact with the OpenFlow device.
  //
  pairDevs = csmaHelper.Install (NodeContainer (switches.Get (0),
                                                switches.Get (1)));

  // Set IPv4 tunnel endpoint addresses
  ipv4Helper.SetBase ("192.168.1.0", "255.255.255.0");
  ipv4Helper.Assign (pairDevs);

  // Create the virtual net devices to work as logical ports on the switches.
  // These logical ports will connect to the tunnel handler application.
  Ptr<VirtualNetDevice> logicalPort0 = CreateObject<VirtualNetDevice> ();
  logicalPort0->SetAttribute ("Mtu", UintegerValue (1500));
  logicalPort0->SetAddress (Mac48Address::Allocate ());
  sw0->AddSwitchPort (logicalPort0);  // Port #2 on switch 0

  Ptr<VirtualNetDevice> logicalPort1 = CreateObject<VirtualNetDevice> ();
  logicalPort1->SetAttribute ("Mtu", UintegerValue (1500));
  logicalPort1->SetAddress (Mac48Address::Allocate ());
  sw1->AddSwitchPort (logicalPort1);  // Port #2 on switch 1

  // Creating the tunnel handler applications
  Ptr<TunnelUserApp> tunnelApp0 = CreateObject<TunnelUserApp> (
      logicalPort0, hostIpIfaces.GetAddress (0),
      hostDevices.Get (0)->GetAddress (),
      hostSwitchDevices.Get (0)->GetAddress (), Ipv4Address ("192.168.1.2"));
  switches.Get (0)->AddApplication (tunnelApp0);

  Ptr<TunnelUserApp> tunnelApp1 = CreateObject<TunnelUserApp> (
      logicalPort1, hostIpIfaces.GetAddress (1),
      hostDevices.Get (1)->GetAddress (),
      hostSwitchDevices.Get (1)->GetAddress (), Ipv4Address ("192.168.1.1"));
  switches.Get (1)->AddApplication (tunnelApp1);

  // Finalizing the OpenFlow network configuration
  of13Helper->CreateOpenFlowChannels ();

  // Send TCP traffic from host 0 to 1
  Ipv4Address dstAddr = hostIpIfaces.GetAddress (1);
  BulkSendHelper senderHelper ("ns3::TcpSocketFactory",
                               InetSocketAddress (dstAddr, 9));
  ApplicationContainer senderApp = senderHelper.Install (hosts.Get (0));
  PacketSinkHelper sinkHelper ("ns3::TcpSocketFactory",
                               InetSocketAddress (Ipv4Address::GetAny (), 9));
  ApplicationContainer sinkApp = sinkHelper.Install (hosts.Get (1));
  senderApp.Start (Seconds (1));

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

  // Print transmitted bytes
  Ptr<PacketSink> sink = DynamicCast<PacketSink> (sinkApp.Get (0));
  std::cout << "Total bytes sent from host 0 to host 1: "
            << sink->GetTotalRx () << std::endl;

  // delete tunnel;
}
