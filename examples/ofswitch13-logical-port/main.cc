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
 * - Two hosts connected to different OpenFlow switches.
 * - Both switches are managed by the tunnel controller application.
 * - The ports interconnecting the switches are configured as logical
 *   ports, allowing switches to de/encapsulate IP traffic using the GTP/UDP/IP
 *   tunneling protocol.
 *
 *                         Tunnel Controller
 *                                 |
 *                         +---------------+
 *                         |               |
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
#include <ns3/internet-apps-module.h>
#include "tunnel-controller.h"
#include "tunnel-user-app.h"

using namespace ns3;

int
main (int argc, char *argv[])
{
  uint16_t simTime = 10;
  bool verbose = false;
  bool trace = false;

  // Configure command line parameters
  CommandLine cmd;
  cmd.AddValue ("simTime", "Simulation time (seconds)", simTime);
  cmd.AddValue ("verbose", "Enable verbose output", verbose);
  cmd.AddValue ("trace", "Enable datapath stats and pcap traces", trace);
  cmd.Parse (argc, argv);

  if (verbose)
    {
      OFSwitch13Helper::EnableDatapathLogs ();
      LogComponentEnable ("OFSwitch13Interface", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Device", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Port", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Queue", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Controller", LOG_LEVEL_ALL);
      LogComponentEnable ("TunnelController", LOG_LEVEL_ALL);
      LogComponentEnable ("TunnelUserApp", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Helper", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13InternalHelper", LOG_LEVEL_ALL);
    }

  // Enable checksum computations (required by OFSwitch13 module)
  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

  // Create two host nodes
  NodeContainer hosts;
  hosts.Create (2);

  // Install the TCP/IP stack into hosts nodes
  InternetStackHelper internet;
  internet.Install (hosts);

  // Create two switch nodes
  NodeContainer switches;
  switches.Create (2);

  // Create the controller node
  Ptr<Node> controllerNode = CreateObject<Node> ();

  // Configure the OpenFlow network domain (don't create the OpenFlow channel now)
  Ptr<OFSwitch13InternalHelper> of13Helper = CreateObject<OFSwitch13InternalHelper> ();
  Ptr<TunnelController> tunnelController = CreateObject<TunnelController> ();
  of13Helper->InstallController (controllerNode, tunnelController);
  OFSwitch13DeviceContainer ofDevices = of13Helper->InstallSwitch (switches);
  Ptr<OFSwitch13Device> sw0 = ofDevices.Get (0);
  Ptr<OFSwitch13Device> sw1 = ofDevices.Get (1);

  // Use the CsmaHelper to connect hosts and switches
  CsmaHelper csmaHelper;
  csmaHelper.SetChannelAttribute ("DataRate", DataRateValue (DataRate ("100Mbps")));
  csmaHelper.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (2)));

  NetDeviceContainer pairDevs;
  NetDeviceContainer hostDevices;
  NetDeviceContainer hostSwitchDevices;

  // Connect host 0 to first switch
  pairDevs = csmaHelper.Install (NodeContainer (hosts.Get (0), switches.Get (0)));
  hostDevices.Add (pairDevs.Get (0));
  hostSwitchDevices.Add (pairDevs.Get (1));
  sw0->AddSwitchPort (pairDevs.Get (1));  // Port #1 at switch 0

  // Connect host 1 to second switch
  pairDevs = csmaHelper.Install (NodeContainer (hosts.Get (1), switches.Get (1)));
  hostDevices.Add (pairDevs.Get (0));
  hostSwitchDevices.Add (pairDevs.Get (1));
  sw1->AddSwitchPort (pairDevs.Get (1));  // Port #1 at switch 1

  // Set IPv4 host addresses on different networks
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

  // Save ARP entries on the controller, so it can respond to ARP requests
  tunnelController->SaveArpEntry (
    sw0GatewayIp, Mac48Address::ConvertFrom (hostSwitchDevices.Get (0)->GetAddress ()));
  tunnelController->SaveArpEntry (
    sw1GatewayIp, Mac48Address::ConvertFrom (hostSwitchDevices.Get (1)->GetAddress ()));
  tunnelController->SaveArpEntry (
    hostIpIfaces.GetAddress (0), Mac48Address::ConvertFrom (hostDevices.Get (0)->GetAddress ()));
  tunnelController->SaveArpEntry (
    hostIpIfaces.GetAddress (1), Mac48Address::ConvertFrom (hostDevices.Get (1)->GetAddress ()));

  // Configure static routes on host nodes
  Ipv4StaticRoutingHelper ipv4RoutingHelper;
  Ptr<Ipv4StaticRouting> hostStaticRouting;
  hostStaticRouting = ipv4RoutingHelper.GetStaticRouting (hosts.Get (0)->GetObject<Ipv4> ());
  hostStaticRouting->AddNetworkRouteTo (Ipv4Address ("10.2.2.0"), Ipv4Mask ("255.255.255.0"),
                                        Ipv4Address ("10.1.1.2"), 1);
  hostStaticRouting = ipv4RoutingHelper.GetStaticRouting (hosts.Get (1)->GetObject<Ipv4> ());
  hostStaticRouting->AddNetworkRouteTo (Ipv4Address ("10.1.1.0"), Ipv4Mask ("255.255.255.0"),
                                        Ipv4Address ("10.2.2.2"), 1);

  // Connect switch 0 to switch 1. These CSMA devices will not be added as
  // switch ports. Instead, each one will be configured as standard ns-3 device
  // (with IP address and an UDP socket binded to it). They will be used to
  // implement the UDP/IP tunneling process. The TunnelUserApp application
  // running on top of the UDP socket will be in change of adding and removing
  // the GTP headers, and forwarding the packets to a VirtualNetDevice device
  // on the same node. This VirtualNetDevice will be configured as switch port
  // and will finally interact with the OpenFlow device.
  pairDevs = csmaHelper.Install (NodeContainer (switches.Get (0), switches.Get (1)));

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

  // Create the tunnel handler applications
  Ptr<TunnelUserApp> tunnelApp0 = CreateObject<TunnelUserApp> (
      logicalPort0, hostIpIfaces.GetAddress (0), hostDevices.Get (0)->GetAddress (),
      hostSwitchDevices.Get (0)->GetAddress (), Ipv4Address ("192.168.1.2"));
  switches.Get (0)->AddApplication (tunnelApp0);

  Ptr<TunnelUserApp> tunnelApp1 = CreateObject<TunnelUserApp> (
      logicalPort1, hostIpIfaces.GetAddress (1), hostDevices.Get (1)->GetAddress (),
      hostSwitchDevices.Get (1)->GetAddress (), Ipv4Address ("192.168.1.1"));
  switches.Get (1)->AddApplication (tunnelApp1);

  // Finally, create the OpenFlow channels
  of13Helper->CreateOpenFlowChannels ();

  // Configure ping application between hosts
  V4PingHelper pingHelper = V4PingHelper (hostIpIfaces.GetAddress (1));
  pingHelper.SetAttribute ("Verbose", BooleanValue (true));
  ApplicationContainer pingApps = pingHelper.Install (hosts.Get (0));
  pingApps.Start (Seconds (1));

  // Enable datapath stats and pcap traces at hosts, switch(es), and controller(s)
  if (trace)
    {
      of13Helper->EnableOpenFlowPcap ("openflow");
      of13Helper->EnableDatapathStats ("switch-stats");
      csmaHelper.EnablePcap ("ofswitch", switches, true);
      csmaHelper.EnablePcap ("host", hostDevices);
    }

  // Run the simulation
  Simulator::Stop (Seconds (simTime));
  Simulator::Run ();
  Simulator::Destroy ();
}
