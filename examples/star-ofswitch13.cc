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
 * Author: Vítor M. Eichemberger <vitor.marge@gmail.com>
 *         Luciano Chaves <luciano@lrc.ic.unicamp.br>
 *
 * N hosts connected to a single OpenFlow 1.3 switch with a single controller
 * CTRL. Traffic flows betwenn two random hosts.
 *
 *     H0, H1, H2, ...
 *          |
 *       -------
 *       | Sw0 | --- CTRL
 *       -------
 *          |
 *  ..., H(n-1), Hn
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/ofswitch13-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("StarOFSwitch13");

int
main (int argc, char *argv[])
{
	size_t nHosts = 2;
	bool verbose = false;
	bool trace = false;

	CommandLine cmd;
	cmd.AddValue ("hots", "Number of hosts", nHosts);
	cmd.AddValue ("verbose", "Tell application to log if true", verbose);
  cmd.AddValue ("trace", "Tracing traffic to files", trace);
	cmd.Parse (argc, argv);

	if (verbose)
		{
			LogComponentEnable ("StarOFSwitch13", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Helper", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13NetDevice", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Controller", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13LearningController", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Interface", LOG_LEVEL_ALL);
		}
	
	// Enabling Checksum computations
	GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

	// Create the hosts
	NodeContainer hosts;
	hosts.Create (nHosts);

	// Create the switch
	Ptr<Node> of13SwitchNode = CreateObject<Node> ();

	// Configure the CsmaHelper
	CsmaHelper csmaHelper;
	csmaHelper.SetChannelAttribute ("DataRate", DataRateValue (DataRate ("100Mbps")));
	csmaHelper.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (2)));

	NetDeviceContainer hostDevices;
	NetDeviceContainer of13SwitchPorts;
	for (size_t i = 0; i < nHosts; i++)
		{
			NodeContainer nc (hosts.Get (i), of13SwitchNode);
			NetDeviceContainer link = csmaHelper.Install (nc);
			hostDevices.Add (link.Get (0));
			of13SwitchPorts.Add (link.Get (1));
		}

	// Configure the OpenFlow network
	Ptr<Node> of13ControllerNode = CreateObject<Node> ();
  Ptr<OFSwitch13Helper> of13Helper = CreateObject<OFSwitch13Helper> ();
	of13Helper->InstallDefaultController (of13ControllerNode);
	NetDeviceContainer of13SwitchDevice;
	of13SwitchDevice = of13Helper->InstallSwitch (of13SwitchNode, of13SwitchPorts);

	// Installing the tcp/ip stack into hosts
	InternetStackHelper internet;
	internet.Install (hosts);

	// Set IPv4 terminal address
	Ipv4AddressHelper ipv4switches;
	Ipv4InterfaceContainer internetIpIfaces;
	ipv4switches.SetBase ("10.1.1.0", "255.255.255.0");
	internetIpIfaces = ipv4switches.Assign (hostDevices);

	// Get random hosts
	Ptr<UniformRandomVariable> rand = CreateObject<UniformRandomVariable> ();
	rand->SetAttribute ("Min", DoubleValue (0));
	rand->SetAttribute ("Max", DoubleValue (nHosts - 1));
	
	int src, dst;
	src = rand->GetInteger ();
	dst = rand->GetInteger ();
	while (dst == src)
		{
			dst = rand->GetInteger ();
		}

	// Send TCP traffic from host 0 to 1
	Ipv4Address dstAddr = internetIpIfaces.GetAddress (dst);
	BulkSendHelper senderHelper ("ns3::TcpSocketFactory", 
															 InetSocketAddress (dstAddr, 8080));
	senderHelper.SetAttribute ("MaxBytes", UintegerValue (0));
	ApplicationContainer senderApp  = senderHelper.Install (hosts.Get (src));
	senderApp.Start (Seconds (1));
	PacketSinkHelper sinkHelper ("ns3::TcpSocketFactory", 
			                         InetSocketAddress (Ipv4Address::GetAny (), 8080));
	ApplicationContainer sinkApp = sinkHelper.Install (hosts.Get (dst));
	sinkApp.Start (Seconds (0));

	// Enable datapath logs
  if (verbose)
    {
      of13Helper->EnableDatapathLogs ("all");
    }

	// Enable pcap traces
	if (trace)
		{
			of13Helper->EnableOpenFlowPcap ();
  		csmaHelper.EnablePcap ("ofswitch", NodeContainer (of13SwitchNode), true);
  		csmaHelper.EnablePcap ("host", hostDevices);
		}

	// Install FlowMonitor
	FlowMonitorHelper monitor;
	monitor.Install (hosts);

	// Run the simulation for 30 seconds
	Simulator::Stop (Seconds (30));
	Simulator::Run ();
	Simulator::Destroy ();

	// Transmitted bytes
	Ptr<PacketSink> sink = DynamicCast<PacketSink> (sinkApp.Get (0));
  std::cout << "Total bytes sent from " << src << " to " << dst << ": " 
  	        << sink->GetTotalRx () << std::endl;

	// Dump FlowMonitor results
	monitor.SerializeToXmlFile ("FlowMonitor.xml", false, false);

}
