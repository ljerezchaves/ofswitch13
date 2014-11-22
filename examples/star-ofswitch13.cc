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
 * TOPOLOGY: n hosts connected to a of1.3 switch (n >= 2)
 *         h0
 *         |
 *       ------
 * hn-1--| S0 |--h1
 *       ------
 *         |
 *        ...
 * 
 * h# = host #, Sx = of1.3 switch #;
 * 
 * Simulation: Transmmit data between 2 random hosts.
 */


#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/log.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/random-variable-stream.h"


NS_LOG_COMPONENT_DEFINE ("star_ofswitch13");

/* XmlInfo definition:
 * 2 = output flow info in a file
 * 1 = output flow info in cout
 * any other value, or no definition = no flow info output
 */
#define XmlInfo 2

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

	// Enable log
	LogComponentEnable ("star_ofswitch13", LOG_LEVEL_ALL);
	
	// Enabling Checksum computations
	GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

	// Create the hosts
	NodeContainer hosts;
	hosts.Create(n);

	// Create the switch
	NodeContainer of13Switch;
	of13Switch.Create(1);
	Ptr<Node> of13SwitchNode = of13Switch.Get(0);

	// Create the controller
	NodeContainer of13Controller;
	of13Controller.Create(1);
	Ptr<Node> of13ControllerNode = of13Controller.Get(0);

	// Configure a ethernet connection
	CsmaHelper csmaHelper;
	csmaHelper.SetChannelAttribute ("DataRate", DataRateValue (DataRate ("100Mbps")));
	csmaHelper.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (2)));

	// Create the devices and connect them
	NetDeviceContainer hostsDevs;
	NetDeviceContainer of13SwitchDev;
	for(size_t i = 0; i < hosts.GetN(); i++)
	{
		NetDeviceContainer link = csmaHelper.Install(NodeContainer (hosts.Get(i), of13Switch));
		hostsDevs.Add(link.Get(0));
		of13SwitchDev.Add(link.Get(1));
	}

	// Configure OpenFlow 1.3 network
	NetDeviceContainer of13Dev;
	OFSwitch13Helper of13Helper;
	Ptr<OFSwitch13Controller> controlApp = of13Helper.InstallControllerApp (of13ControllerNode);
	of13Dev = of13Helper.InstallSwitch (of13SwitchNode, of13SwitchDev);

	// Installing the tcp/ip stack into hosts
	InternetStackHelper internet;
	internet.Install (hosts);

	// Set IPv4 terminal address
	Ipv4AddressHelper ipv4switches;
	Ipv4InterfaceContainer internetIpIfaces;
	ipv4switches.SetBase ("10.1.1.0", "255.255.255.0");
	internetIpIfaces = ipv4switches.Assign (hostsDevs);

	// Get random values, for make a transmission between 2 random hosts
	RngSeedManager::SetSeed (3);
	RngSeedManager::SetRun (7);
	Ptr<UniformRandomVariable> randSource = CreateObject<UniformRandomVariable> ();
	size_t x, y;
	x = randSource->GetInteger(0, (n-1));
	y = randSource->GetInteger(0, (n-1));
	while(x == y) // make sure y != x
		y = randSource->GetInteger(0, (n-1));

	// Create a ping application from host x to y
	Ipv4Address randAddr1 = internetIpIfaces.GetAddress (x);
	Ipv4Address randAddr2 = internetIpIfaces.GetAddress (y);
	V4PingHelper ping = V4PingHelper (randAddr2);
	ApplicationContainer pingApp = ping.Install (hosts.Get (x));
	pingApp.Start (Seconds (1.));
	pingApp.Start (Seconds (20.));

	// Send TCP traffic from host y to x
	BulkSendHelper senderHelper ("ns3::TcpSocketFactory", InetSocketAddress (randAddr1, 50000));
	senderHelper.SetAttribute ("MaxBytes", UintegerValue (x));
	ApplicationContainer senderApp  = senderHelper.Install (hosts.Get (y));
	PacketSinkHelper sinkHelper ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 50000));
	ApplicationContainer sinkApp = sinkHelper.Install (hosts.Get (x));
	senderApp.Start (Seconds (1.));
	sinkApp.Start (Seconds (1.));
	senderApp.Stop (Seconds (20.));
	sinkApp.Stop (Seconds (21.));

	// Enable pcap traces
	#if XmlInfo > 0
		of13Helper.EnableOpenFlowPcap ("ofController");
		csmaHelper.EnablePcap ("ofSwitch", of13SwitchDev, true);
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
	#if XmlInfo == 1
		monitor.SerializeToXmlStream(std::cout, 4, false, false);
	#elif XmlInfo == 2
		monitor.SerializeToXmlFile("FlowMonitor.xml", false, false);
	#endif

	NS_LOG_INFO ("Data transmmited between hosts " << x << " and " << y << ".");
}

#else

int
main (int argc, char *argv[])
{
  NS_LOG_UNCOND ("OpenFlow 1.3 not enabled! Aborting...");
}

#endif
