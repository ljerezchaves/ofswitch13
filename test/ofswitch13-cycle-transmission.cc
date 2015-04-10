/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Author: Vítor M. Eichemberger <vitor.marge@gmail.com>
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

class OfswitchCycleTransmissionCase : public TestCase
{
public:
  OfswitchCycleTransmissionCase ();
  virtual ~OfswitchCycleTransmissionCase ();

private:
  virtual void DoRun (void);
};

OfswitchCycleTransmissionCase::OfswitchCycleTransmissionCase ()
  : TestCase ("Tests a single transmission of 1024 bytes between two hosts in a cyclical circuit of switches.")
{
}

OfswitchCycleTransmissionCase::~OfswitchCycleTransmissionCase ()
{
}

// Makes the test
void
OfswitchCycleTransmissionCase::DoRun (void)
{
  size_t nHosts = 2;
  size_t nSwitches = 4;

  // Enabling Checksum computations
  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

  // Create the hosts
  NodeContainer hosts;
  hosts.Create (nHosts);

  // Create the switches
  //Ptr<Node> of13SwitchNode = CreateObject<Node> ();
  NodeContainer switches;
  switches.Create (nSwitches);

  // Configure the CsmaHelper
  CsmaHelper csmaHelper;
  csmaHelper.SetChannelAttribute ("DataRate", DataRateValue (DataRate ("100Mbps")));
  csmaHelper.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (2)));

  // Creates the net devices
  NetDeviceContainer hostDevices;
  NetDeviceContainer of13SwitchPorts [nSwitches];
  for(size_t i = 0; i < nSwitches; i++)
    of13SwitchPorts[i] = NetDeviceContainer ();

  // Connects the switches between themselves
  for (size_t i = 0; i < nSwitches; i++)
    {
      NodeContainer nc (switches.Get (i), switches.Get ((i +1) % nSwitches));
      NetDeviceContainer link = csmaHelper.Install (nc);
      of13SwitchPorts[i].Add (link.Get (0));
      of13SwitchPorts[(i +1) % nSwitches].Add (link.Get (1));
    }

  // Connects hosts in opposite switches
  NodeContainer nc0 (hosts.Get (0), switches.Get (0));
  NetDeviceContainer link0 = csmaHelper.Install (nc0);
  hostDevices.Add (link0.Get (0));
  of13SwitchPorts[0].Add (link0.Get (1));
  NodeContainer nc1 (hosts.Get (1), switches.Get ((nSwitches +1)/2));
  NetDeviceContainer link1 = csmaHelper.Install (nc1);
  hostDevices.Add (link1.Get (0));
  of13SwitchPorts[(nSwitches +1)/2].Add (link1.Get (1));

  // Configure the OpenFlow network
  Ptr<Node> of13ControllerNode = CreateObject<Node> ();
  Ptr<OFSwitch13Helper> of13Helper = CreateObject<OFSwitch13Helper> ();
  Ptr<OFSwitch13Controller> of13ControllerApp;
  of13ControllerApp = of13Helper->InstallDefaultController (of13ControllerNode);
  Ptr<OFSwitch13LearningController> learningCtrl = DynamicCast<OFSwitch13LearningController> (of13ControllerApp);

  // Install OpenFlow device in every switch
  NetDeviceContainer of13SwitchDevices;
  for (size_t i = 0; i < nSwitches; i++)
    {
      of13SwitchDevices.Add (of13Helper->InstallSwitch (switches.Get (i), of13SwitchPorts [i]));
    }

  // Installing the tcp/ip stack into hosts
  InternetStackHelper internet;
  internet.Install (hosts);

  // Set IPv4 terminal address
  Ipv4AddressHelper ipv4switches;
  Ipv4InterfaceContainer internetIpIfaces;
  ipv4switches.SetBase ("10.1.1.0", "255.255.255.0");
  internetIpIfaces = ipv4switches.Assign (hostDevices);

  // Notify controller about hosts IP
  learningCtrl->NotifyNewIpDevice (hostDevices.Get (0), internetIpIfaces.GetAddress (0));
  learningCtrl->NotifyNewIpDevice (hostDevices.Get (1), internetIpIfaces.GetAddress (1));

  // Send TCP traffic from host 0 to 1
  int src=0, dst=1;
  Ipv4Address dstAddr = internetIpIfaces.GetAddress (dst);
  BulkSendHelper senderHelper ("ns3::TcpSocketFactory", InetSocketAddress (dstAddr, 8080));
  senderHelper.SetAttribute ("MaxBytes", UintegerValue (1024));
  ApplicationContainer senderApp  = senderHelper.Install (hosts.Get (src));
  senderApp.Start (Seconds (1));
  PacketSinkHelper sinkHelper ("ns3::TcpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 8080));
  ApplicationContainer sinkApp = sinkHelper.Install (hosts.Get (dst));
  sinkApp.Start (Seconds (0));

  // Makes the simulation
  Simulator::Stop (Seconds (30));
  Simulator::Run ();

  // Checkout transmitted bytes
  Ptr<PacketSink> sink = DynamicCast<PacketSink> (sinkApp.Get (0));
  NS_TEST_ASSERT_MSG_EQ (sink->GetTotalRx (), 1024, "It hasn't received all the 1024 bytes as expected.");
}

class OfswitchCycleTransmissionSuite : public TestSuite
{
public:
  OfswitchCycleTransmissionSuite ();
};

OfswitchCycleTransmissionSuite::OfswitchCycleTransmissionSuite ()
  : TestSuite ("ofswitch13-cycle-transmission", UNIT)
{
  AddTestCase (new OfswitchCycleTransmissionCase, TestCase::QUICK);
}

static OfswitchCycleTransmissionSuite ofswitch13TestSuite;

