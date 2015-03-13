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
 * Four OpenFlow 1.3 switches connected in sequence, with a single host each.
 * The first pair of switches are controlled by CTRL0, and the second pair by
 * CTRL1. Traffic flows from host H0 to host H2.
 *
 *    H0        H1        H2        H3
 *    |         |         |         |
 * -------   -------   -------   -------
 * | Sw0 |---| Sw1 |---| Sw2 |---| Sw3 |
 * -------   -------   -------   -------
 *    :         :         :         :
 *    ...........         ...........
 *         :                   :
 *       CTRL0               CTRL1
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/ofswitch13-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("DualCtrlOFSwitch13");

int
main (int argc, char *argv[])
{
	bool verbose = false;
	bool trace = false;

	CommandLine cmd;
	cmd.AddValue ("verbose", "Tell application to log if true", verbose);
  cmd.AddValue ("trace", "Tracing traffic to files", trace);
	cmd.Parse (argc, argv);

	if (verbose)
		{
			LogComponentEnable ("DualCtrlOFSwitch13", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Helper", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13NetDevice", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Controller", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13LearningController", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13Interface", LOG_LEVEL_ALL);
		}
	
	// Enabling Checksum computations
	GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

 	// Create the host nodes
	NodeContainer hosts;
	hosts.Create(4);

	// Create the switches nodes
	NodeContainer of13SwitchNodes;
	of13SwitchNodes.Create(4);

	// Configure the CsmaHelper
	CsmaHelper csmaHelper;
	csmaHelper.SetChannelAttribute ("DataRate", DataRateValue (DataRate ("100Mbps")));
	csmaHelper.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (2)));
	
	NetDeviceContainer hostDevices;
	NetDeviceContainer of13SwitchPorts [4];
	for (size_t i = 1; i < 4; i++)
	{
		of13SwitchPorts [i] = NetDeviceContainer ();
	}

	// Connect host to switches
	for (size_t i = 0; i < 4; i++)
		{
			NodeContainer nc (hosts.Get (i), of13SwitchNodes.Get (i));
			NetDeviceContainer link = csmaHelper.Install (nc);
  		hostDevices.Add (link.Get (0));
  		of13SwitchPorts [i].Add (link.Get (1));
		}	
	
	// Connect the switches in chain
	for (size_t i = 1; i < 4; i++)
		{
			NodeContainer nc (of13SwitchNodes.Get (i - 1), of13SwitchNodes.Get (i));
			NetDeviceContainer link = csmaHelper.Install(nc);
			of13SwitchPorts [i - 1].Add (link.Get (0));
			of13SwitchPorts [i].Add (link.Get (1));
		}	

	// Configure the OpenFlow network
	NodeContainer of13Controllers;
	of13Controllers.Create(2);

	Ptr<Node> of13ControllerNode0 = of13Controllers.Get (0);
	Ptr<Node> of13ControllerNode1 = of13Controllers.Get (1);

  Ptr<OFSwitch13Helper> of13Helper0 = CreateObject<OFSwitch13Helper> ();
  Ptr<OFSwitch13Helper> of13Helper1 = CreateObject<OFSwitch13Helper> ();

	of13Helper0->InstallDefaultController (of13ControllerNode0);
	of13Helper0->InstallSwitch (of13SwitchNodes.Get (0), of13SwitchPorts [0]);
	of13Helper0->InstallSwitch (of13SwitchNodes.Get (1), of13SwitchPorts [1]);
	
	of13Helper1->SetAddressBase ("10.100.151.0", "255.255.255.0");
	of13Helper1->InstallDefaultController (of13ControllerNode1);
	of13Helper1->InstallSwitch (of13SwitchNodes.Get (2), of13SwitchPorts [2]);
	of13Helper1->InstallSwitch (of13SwitchNodes.Get (3), of13SwitchPorts [3]);

	// Installing the tcp/ip stack into hosts
	InternetStackHelper internet;
	internet.Install (hosts);

	// Set IPv4 terminal address
	Ipv4AddressHelper ipv4switches;
	Ipv4InterfaceContainer internetIpIfaces;
	ipv4switches.SetBase ("10.1.1.0", "255.255.255.0");
	internetIpIfaces = ipv4switches.Assign (hostDevices);

	// Send TCP traffic from host 0 to 3
	Ipv4Address h3Addr = internetIpIfaces.GetAddress (3);
	BulkSendHelper senderHelper ("ns3::TcpSocketFactory", 
															 InetSocketAddress (h3Addr, 8080));
	senderHelper.SetAttribute ("MaxBytes", UintegerValue (0));
	ApplicationContainer senderApp  = senderHelper.Install (hosts.Get (0));
	senderApp.Start (Seconds (1));
	PacketSinkHelper sinkHelper ("ns3::TcpSocketFactory", 
			                         InetSocketAddress (Ipv4Address::GetAny (), 8080));
	ApplicationContainer sinkApp = sinkHelper.Install (hosts.Get (3));
	sinkApp.Start (Seconds (0));

	// Enable datapath logs
  if (verbose)
    {
      of13Helper0->EnableDatapathLogs ("all");
      of13Helper1->EnableDatapathLogs ("all");
    }

	// Enable pcap traces
	if (trace)
		{
			of13Helper0->EnableOpenFlowPcap ("ofCtrl0");
			of13Helper1->EnableOpenFlowPcap ("ofCtrl1");
  		csmaHelper.EnablePcap ("ofswitch", of13SwitchNodes, true);
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
  std::cout << "Total bytes sent from H0 to H1: " 
  	        << sink->GetTotalRx () << std::endl;

	// Dump FlowMonitor results
	monitor.SerializeToXmlFile ("FlowMonitor.xml", false, false);
}
