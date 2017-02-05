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
 * Two hosts connected through a single OpenFlow switch managed simultaneously
 * by to different controllers (Controller 0 and Controller 1). TCP traffic
 * flows from host 0 to host 1.
 *
 *                      Controller 0
 *                           |
 *                  +-----------------+
 *       Host 0 === | OpenFlow switch | === Host 1
 *                  +-----------------+
 *                           |
 *                      Controller 1
 */

#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/csma-module.h>
#include <ns3/internet-module.h>
#include <ns3/applications-module.h>
#include <ns3/ofswitch13-module.h>

using namespace ns3;

class Controller0;
class Controller1;

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
      LogComponentEnable ("OFSwitch13Controller", LOG_LEVEL_ALL);
      LogComponentEnable ("OFSwitch13LearningController", LOG_LEVEL_ALL);
    }

  // Enabling Checksum computations
  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

  // Creating two host nodes
  NodeContainer hosts;
  hosts.Create (2);

  // Create the switch node
  Ptr<Node> switchNode = CreateObject<Node> ();

  // Create the two controller nodes
  NodeContainer controllers;
  controllers.Create (2);

  // Use the CsmaHelper to connect the host nodes to the switch.
  CsmaHelper csmaHelper;
  csmaHelper.SetChannelAttribute ("DataRate", DataRateValue (DataRate ("100Mbps")));
  csmaHelper.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (2)));

  NetDeviceContainer hostDevices;
  NetDeviceContainer switchPorts;
  for (size_t i = 0; i < hosts.GetN (); i++)
    {
      NodeContainer pair (hosts.Get (i), switchNode);
      NetDeviceContainer link = csmaHelper.Install (pair);
      hostDevices.Add (link.Get (0));
      switchPorts.Add (link.Get (1));
    }

  // Configure the OpenFlow network
  Ptr<OFSwitch13Helper> of13Helper = CreateObject<OFSwitch13Helper> ();
  Ptr<Controller0> ctrl0 = CreateObject<Controller0> ();
  Ptr<Controller1> ctrl1 = CreateObject<Controller1> ();
  of13Helper->InstallController (controllers.Get (0), ctrl0);
  of13Helper->InstallController (controllers.Get (1), ctrl1);
  of13Helper->InstallSwitch (switchNode, switchPorts);
  of13Helper->CreateOpenFlowChannels ();

  // Install the TCP/IP stack into hosts
  InternetStackHelper internet;
  internet.Install (hosts);

  // Set IPv4 terminal address
  Ipv4AddressHelper ipv4switches;
  Ipv4InterfaceContainer internetIpIfaces;
  ipv4switches.SetBase ("10.1.1.0", "255.255.255.0");
  internetIpIfaces = ipv4switches.Assign (hostDevices);

  // Send TCP traffic from host 0 to 1
  Ipv4Address dstAddr = internetIpIfaces.GetAddress (1);
  BulkSendHelper senderHelper ("ns3::TcpSocketFactory", InetSocketAddress (dstAddr, 9));
  senderHelper.Install (hosts.Get (0));
  PacketSinkHelper sinkHelper ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 9));
  ApplicationContainer sinkApp = sinkHelper.Install (hosts.Get (1));

  // Enable pcap traces and datapath stats
  if (trace)
    {
      of13Helper->EnableOpenFlowPcap ();
      of13Helper->EnableDatapathStats ();
      csmaHelper.EnablePcap ("ofswitch", NodeContainer (switchNode), true);
      csmaHelper.EnablePcap ("host", hostDevices);
    }

  // Run the simulation
  Simulator::Stop (Seconds (simTime));
  Simulator::Run ();
  Simulator::Destroy ();

  // Print transmitted bytes
  Ptr<PacketSink> sink = DynamicCast<PacketSink> (sinkApp.Get (0));
  std::cout << "Total bytes sent from host 0 to host 1: " << sink->GetTotalRx () << std::endl;
}

/**
 * Controller 0 is responsible to installs the rule to forward packets from
 * host 0 (port 1) to host 1 (port 2).
 */
class Controller0 : public OFSwitch13Controller
{
protected:
  // Inherited from OFSwitch13Controller
  void HandshakeSuccessful (Ptr<const RemoteSwitch> swtch);
};

void
Controller0::HandshakeSuccessful (Ptr<const RemoteSwitch> swtch)
{
  DpctlExecute (swtch, "flow-mod cmd=add,table=0,prio=1 in_port=1 write:output=2");
}

/**
 * Controller 1 is responsible to installs the rule to forward packets from
 * host 1 (port 2) to host 0 (port 1).
 */
class Controller1 : public OFSwitch13Controller
{
protected:
  // Inherited from OFSwitch13Controller
  void HandshakeSuccessful (Ptr<const RemoteSwitch> swtch);
};

void
Controller1::HandshakeSuccessful (Ptr<const RemoteSwitch> swtch)
{
  DpctlExecute (swtch, "flow-mod cmd=add,table=0,prio=1 in_port=2 write:output=1");
}

