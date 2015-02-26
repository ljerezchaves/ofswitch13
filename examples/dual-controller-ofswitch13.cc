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
 *
 * TOPOLOGY: 4 of1.3 switches connected to a single host each.
 *
 *   h0       h1        h2       h3
 *   |        |         |        |
 * ------   ------   ------   ------
 * | S0 |---| S1 |---| S2 |---| S3 |
 * ------   ------   ------   ------
 *    :       :         :        :
 *    .........         ..........
 *        :                  :
 *      CTRL0              CTRL1
 * 
 * h# = host #, Sx = of1.3 switch #, CTRL# = controller #;
 * Traffic flowing from h0 to h3.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/log.h"
#include "ns3/flow-monitor-helper.h"


NS_LOG_COMPONENT_DEFINE ("dual_ctrl_ofswitch13");

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
	// Enable log
	LogComponentEnable ("dual_ctrl_ofswitch13", LOG_LEVEL_ALL);
	
	// Enabling Checksum computations
	GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

	// Create the hosts
	NodeContainer hosts;
	hosts.Create(4);

	// Create the switches
	NodeContainer of13Switches;
	of13Switches.Create(4);

	// Create the controller
	NodeContainer of13Controllers;
	of13Controllers.Create(2);

	// Configure a ethernet connection and create net devices
	CsmaHelper csmaHelper;
	csmaHelper.SetChannelAttribute ("DataRate", DataRateValue (DataRate ("100Mbps")));
	csmaHelper.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (2)));
	NetDeviceContainer hostsDevs;
	NetDeviceContainer of13SwitchesDevs[4];
	for(size_t i = 1; i < 4; i++) // pre-starting the switchdevs array
	{
		NetDeviceContainer tmp;
		of13SwitchesDevs[i] = tmp;
	}

	// Connect them
	for(size_t i = 0; i < hosts.GetN(); i++)
	{
		NetDeviceContainer link = csmaHelper.Install(NodeContainer (hosts.Get(i), of13Switches.Get(i)));
		hostsDevs.Add(link.Get(0));
		of13SwitchesDevs[i].Add(link.Get(1));
	}
	for(size_t i = 1; i < of13Switches.GetN(); i++)
	{
		NetDeviceContainer link = csmaHelper.Install(NodeContainer (of13Switches.Get(i-1), of13Switches.Get(i)));
		of13SwitchesDevs[i-1].Add(link.Get(0));
		of13SwitchesDevs[i].Add(link.Get(1));
	}

	// Configure OpenFlow 1.3 network
	Ptr<Node>
		of13ControllersNode0 = of13Controllers.Get(0),
		of13ControllersNode1 = of13Controllers.Get(1),
		of13SwitchesNode0 = of13Switches.Get(0),
		of13SwitchesNode1 = of13Switches.Get(1),
		of13SwitchesNode2 = of13Switches.Get(2),
		of13SwitchesNode3 = of13Switches.Get(3);

  Ptr<OFSwitch13Helper> of13Helper0 = CreateObject<OFSwitch13Helper> ();
  Ptr<OFSwitch13Helper> of13Helper1 = CreateObject<OFSwitch13Helper> ();
	of13Helper0->InstallDefaultController (of13ControllersNode0);
	of13Helper0->InstallSwitch (of13SwitchesNode0, of13SwitchesDevs[0]);
	of13Helper0->InstallSwitch (of13SwitchesNode1, of13SwitchesDevs[1]);
	of13Helper1->SetAddressBase ("10.100.151.0", "255.255.255.0");
	of13Helper1->InstallDefaultController (of13ControllersNode1);
	of13Helper1->InstallSwitch (of13SwitchesNode2, of13SwitchesDevs[2]);
	of13Helper1->InstallSwitch (of13SwitchesNode3, of13SwitchesDevs[3]);

	// Installing the tcp/ip stack into hosts
	InternetStackHelper internet;
	internet.Install (hosts);

	// Set IPv4 terminal address
	Ipv4AddressHelper ipv4switches;
	Ipv4InterfaceContainer internetIpIfaces;
	ipv4switches.SetBase ("10.1.1.0", "255.255.255.0");
	internetIpIfaces = ipv4switches.Assign (hostsDevs);

	// Create a ping application from host 0 to 1
	//Ipv4Address h0Addr = internetIpIfaces.GetAddress (0);
	Ipv4Address h3Addr = internetIpIfaces.GetAddress (3);
	/*V4PingHelper ping = V4PingHelper (h1Addr);
	ApplicationContainer pingApp = ping.Install (hosts.Get (0));
	pingApp.Start (Seconds (1.));
	pingApp.Start (Seconds (20.));*/

	// Send TCP traffic from host 0 to 3
	BulkSendHelper senderHelper ("ns3::TcpSocketFactory", InetSocketAddress (h3Addr, 50000));
	senderHelper.SetAttribute ("MaxBytes", UintegerValue (3));
	ApplicationContainer senderApp  = senderHelper.Install (hosts.Get (0));
	PacketSinkHelper sinkHelper ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 50000));
	ApplicationContainer sinkApp = sinkHelper.Install (hosts.Get (3));
	senderApp.Start (Seconds (1.));
	sinkApp.Start (Seconds (1.));
	senderApp.Stop (Seconds (20.));
	sinkApp.Stop (Seconds (20.));

	// Enable pcap traces
	#if XmlInfo > 0
		of13Helper0->EnableOpenFlowPcap ("ofController0");
		of13Helper1->EnableOpenFlowPcap ("ofController1");
		for(size_t i = 0; i < 4; i++)
			csmaHelper.EnablePcap ("ofSwitch", of13SwitchesDevs[i], true);
		csmaHelper.EnablePcap ("host", hostsDevs);
	#endif

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
}

#else

int
main (int argc, char *argv[])
{
  NS_LOG_UNCOND ("OpenFlow 1.3 not enabled! Aborting...");
}

#endif
