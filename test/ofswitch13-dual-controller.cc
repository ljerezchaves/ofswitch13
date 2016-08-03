/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Author: Vitor M. Eichemberger <vitor.marge@gmail.com>
 *
 */


#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/ofswitch13-module.h"
#include "ns3/test.h"

using namespace ns3;

class Ofswitch13TestCase2 : public TestCase
{
public:
  Ofswitch13TestCase2 ();
  virtual ~Ofswitch13TestCase2 ();

private:
  virtual void DoRun (void);
};

Ofswitch13TestCase2::Ofswitch13TestCase2 ()
  : TestCase ("Tests the transmission of 1024 bytes between two hosts in a sequence of 4 switches with 2 controllers.")
{
}

Ofswitch13TestCase2::~Ofswitch13TestCase2 ()
{
}

// Makes the test
void
Ofswitch13TestCase2::DoRun (void)
{
  // Create the host nodes
  NodeContainer hosts;
  hosts.Create (4);

  // Create the switches nodes
  NodeContainer of13SwitchNodes;
  of13SwitchNodes.Create (4);

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
      NetDeviceContainer link = csmaHelper.Install (nc);
      of13SwitchPorts [i - 1].Add (link.Get (0));
      of13SwitchPorts [i].Add (link.Get (1));
    }

  // Configure the OpenFlow network
  NodeContainer of13Controllers;
  of13Controllers.Create (2);

  Ptr<Node> of13ControllerNode0 = of13Controllers.Get (0);
  Ptr<Node> of13ControllerNode1 = of13Controllers.Get (1);

  Ptr<OFSwitch13Helper> of13Helper0 = CreateObject<OFSwitch13Helper> ();
  Ptr<OFSwitch13Helper> of13Helper1 = CreateObject<OFSwitch13Helper> ();

  Ptr<OFSwitch13LearningController> learningCtrl0;
  learningCtrl0 = DynamicCast<OFSwitch13LearningController> (of13Helper0->InstallDefaultController (of13ControllerNode0));
  of13Helper0->InstallSwitch (of13SwitchNodes.Get (0), of13SwitchPorts [0]);
  of13Helper0->InstallSwitch (of13SwitchNodes.Get (1), of13SwitchPorts [1]);

  of13Helper1->SetAddressBase ("10.100.151.0", "255.255.255.0");
  Ptr<OFSwitch13LearningController> learningCtrl1;
  learningCtrl1 = DynamicCast<OFSwitch13LearningController> (of13Helper1->InstallDefaultController (of13ControllerNode1));
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
  BulkSendHelper senderHelper ("ns3::TcpSocketFactory", InetSocketAddress (h3Addr, 8080));
  senderHelper.SetAttribute ("MaxBytes", UintegerValue (1024));
  ApplicationContainer senderApp  = senderHelper.Install (hosts.Get (0));
  senderApp.Start (Seconds (1));
  PacketSinkHelper sinkHelper ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 8080));
  ApplicationContainer sinkApp = sinkHelper.Install (hosts.Get (3));
  sinkApp.Start (Seconds (0));

  // Run the simulation for 30 seconds
  Simulator::Stop (Seconds (30));
  Simulator::Run ();
  Simulator::Destroy ();

  // Checkout transmitted bytes
  Ptr<PacketSink> sink = DynamicCast<PacketSink> (sinkApp.Get (0));
  NS_TEST_ASSERT_MSG_EQ (sink->GetTotalRx (), 1024, "It hasn't received all the 1024 bytes as expected.");
}

class Ofswitch13TestSuite2 : public TestSuite
{
public:
  Ofswitch13TestSuite2 ();
};

Ofswitch13TestSuite2::Ofswitch13TestSuite2 ()
  : TestSuite ("ofswitch13-dual-controller", UNIT)
{
  AddTestCase (new Ofswitch13TestCase2, TestCase::QUICK);
}

static Ofswitch13TestSuite2 ofswitch13TestSuite2;

