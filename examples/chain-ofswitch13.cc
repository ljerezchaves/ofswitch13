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
 *
 * Author: Vítor M. Eichemberger <vitor.marge@gmail.com>
 *
 * TOPOLOGY: n of1.3 switches (n >= 2)
 *
 *   h0                 h2
 *   |                  |
 * ------           --------
 * | S0 |--- ... ---| Sn-1 |
 * ------           --------
 *   |                  |
 *   h1                 h3
 * 
 * h# = host #, Sx = of1.3 switch #;
 * OBS: Both switches use the same controller.
 * 
 * Simulation: Transmmit data from h0 to h3.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/log.h"
#include "ns3/flow-monitor-helper.h"

// Log name
NS_LOG_COMPONENT_DEFINE ("chain_ofswitch13");

/* FlowInfo definition:
 * 2 = output flow info in a file
 * 1 = output flow info in cout
 * any other value, or no definition = no flow info output
 */
#define FlowInfo 2


using namespace ns3;


#ifdef NS3_OFSWITCH13
#include "ns3/ofswitch13-module.h"

int
main (int argc, char *argv[])
{
	// Get the argument n, or set to 2 if not given
	size_t n = 2;
	CommandLine cmd;
	cmd.AddValue ("n", "Tell application to log if true", n);
	cmd.Parse (argc,argv);
	if(n < 2)
		n = 2;

	// Enable Log
	LogComponentEnable ("chain_ofswitch13", LOG_LEVEL_ALL);
	
	// Enabling Checksum computations
	GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

	// Create the hosts
	NodeContainer hosts;
	hosts.Create(4);

	// Create the switch
	NodeContainer of13Switches;
	of13Switches.Create(n);

	// Create the controller
	NodeContainer of13Controller;
	of13Controller.Create(1);

	// Configure a ethernet connection and create devices
	CsmaHelper csmaHelper;
	csmaHelper.SetChannelAttribute ("DataRate", DataRateValue (DataRate ("100Mbps")));
	csmaHelper.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (2)));
	NetDeviceContainer hostsDevs;
	NetDeviceContainer of13SwitchDevs[n];
	for(size_t i = 1; i < n; i++) // pre-starting the switchdevs array
	{
		NetDeviceContainer tmp;
		of13SwitchDevs[i] = tmp;
	}
	NetDeviceContainer link;
	
	// Connect h0 to S0
	link = csmaHelper.Install(NodeContainer (hosts.Get(0), of13Switches.Get(0)));
	hostsDevs.Add(link.Get(0));
	of13SwitchDevs[0].Add(link.Get(1));
	
	// Connect h1 to S0
	link = csmaHelper.Install(NodeContainer (hosts.Get(1), of13Switches.Get(0)));
	hostsDevs.Add(link.Get(0));
	of13SwitchDevs[0].Add(link.Get(1));
	
	// Connect h2 to Sn-1
	link = csmaHelper.Install(NodeContainer (hosts.Get(2), of13Switches.Get(n-1)));
	hostsDevs.Add(link.Get(0));
	of13SwitchDevs[n-1].Add(link.Get(1));
	
	// Connect h3 to Sn-1
	link = csmaHelper.Install(NodeContainer (hosts.Get(3), of13Switches.Get(n-1)));
	hostsDevs.Add(link.Get(0));
	of13SwitchDevs[n-1].Add(link.Get(1));

	// Connect the switches between theirselves
	for(size_t i = 1; i < n; i++)
	{
		link = csmaHelper.Install(NodeContainer (of13Switches.Get(i-1), of13Switches.Get(i)));
		of13SwitchDevs[i-1].Add(link.Get(0));
		of13SwitchDevs[i].Add(link.Get(1));
	}	

	// Configure OpenFlow 1.3 network
	//NetDeviceContainer of13Dev;
	OFSwitch13Helper of13Helper;
	Ptr<Node> of13ControllerNode = of13Controller.Get(0);
	Ptr<OFSwitch13Controller> controlApp = of13Helper.InstallControllerApp (of13ControllerNode);

	// Install OpenFlow 1.3 in every switch
	for(size_t i = 0; i < n; i++)
	{
		Ptr<Node> of13SwitchNode = of13Switches.Get(i);
		of13Helper.InstallSwitch (of13SwitchNode, of13SwitchDevs[i]);
		//of13Dev = of13Helper.InstallSwitch (of13SwitchNode, of13SwitchDevs[i]);
	}

	// Installing the tcp/ip stack into hosts
	InternetStackHelper internet;
	internet.Install (hosts);

	// Set IPv4 terminal address
	Ipv4AddressHelper ipv4switches;
	Ipv4InterfaceContainer internetIpIfaces;
	ipv4switches.SetBase ("10.1.1.0", "255.255.255.0");
	internetIpIfaces = ipv4switches.Assign (hostsDevs);

	// Create a ping application from host 0 to 3
	Ipv4Address h0Addr = internetIpIfaces.GetAddress (0);
	//Ipv4Address h3Addr = internetIpIfaces.GetAddress (3);
	//V4PingHelper ping = V4PingHelper (h3Addr);
	//ApplicationContainer pingApp = ping.Install (hosts.Get (0));
	//pingApp.Start (Seconds (1.));

	// Send TCP traffic from host 3 to 0
	BulkSendHelper senderHelper ("ns3::TcpSocketFactory", InetSocketAddress (h0Addr, 50000));
	senderHelper.SetAttribute ("MaxBytes", UintegerValue (0));
	ApplicationContainer senderApp  = senderHelper.Install (hosts.Get (3));
	PacketSinkHelper sinkHelper ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 50000));
	ApplicationContainer sinkApp = sinkHelper.Install (hosts.Get (0));
	senderApp.Start (Seconds (1.));
	sinkApp.Start (Seconds (1.));

	// Enable pcap traces
	#if FlowInfo > 0
		of13Helper.EnableOpenFlowPcap ("ofController");
		for(size_t i = 0; i < n; i++)
			csmaHelper.EnablePcap ("ofSwitch", of13SwitchDevs[i], true);
		csmaHelper.EnablePcap ("host", hostsDevs);
	#endif

	// Configure Flow Monitor for the hosts
	FlowMonitorHelper monitor;
	monitor.Install(hosts);

	// Run the simulation (for 30sec)
	Simulator::Stop (Seconds (30));
	Simulator::Run ();
	Simulator::Destroy ();

	// Output flow info
	#if FlowInfo == 1
		monitor.SerializeToXmlStream(std::cout, 4, false, false);
	#elif FlowInfo == 2
		monitor.SerializeToXmlFile("FlowMonitor.xml", false, false);
	#endif
}

#else

int
main (int argc, char *argv[])
{
  NS_LOG_UNCOND ("OpenFlow 1.3 not enabled! Aborting...");
}

#endif
