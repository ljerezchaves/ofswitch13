/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

// Include a header file from your module to test.

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/ofswitch13-module.h"

// An essential include is test.h
#include "ns3/test.h"

// Do not put your test classes in namespace ns3.  You may find it useful
// to use the using directive to access the ns3 namespace directly
using namespace ns3;

// This is an example TestCase.
class Ofswitch13TestCase1 : public TestCase
{
public:
  Ofswitch13TestCase1 ();
  virtual ~Ofswitch13TestCase1 ();

private:
  virtual void DoRun (void);
};

// Add some help text to this case to describe what it is intended to test
Ofswitch13TestCase1::Ofswitch13TestCase1 ()
  : TestCase ("Ofswitch13 test case (does nothing)")
{
}

// This destructor does nothing but we include it as a reminder that
// the test case should clean up after itself
Ofswitch13TestCase1::~Ofswitch13TestCase1 ()
{
}

//
// This method is the pure virtual method from class TestCase that every
// TestCase must implement
//
void
Ofswitch13TestCase1::DoRun (void)
{
  size_t nHosts = 2;

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
  Ptr<OFSwitch13LearningController> learningCtrl = DynamicCast<OFSwitch13LearningController> (of13Helper->InstallDefaultController (of13ControllerNode));
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

  // Notify controller about hosts IP
  for (uint32_t i = 0; i < hostDevices.GetN (); i++)
    {
      learningCtrl->NotifyNewIpDevice (hostDevices.Get (i), internetIpIfaces.GetAddress (i));
    }

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

  Simulator::Stop (Seconds (10));
  Simulator::Run ();

  // Checkout transmitted bytes
  Ptr<PacketSink> sink = DynamicCast<PacketSink> (sinkApp.Get (0));
  NS_TEST_ASSERT_MSG_EQ (sink->GetTotalRx (), 1024, "It hasn't received all the 1024 bytes as expected.");
}

// The TestSuite class names the TestSuite, identifies what type of TestSuite,
// and enables the TestCases to be run.  Typically, only the constructor for
// this class must be defined
//
class Ofswitch13TestSuite : public TestSuite
{
public:
  Ofswitch13TestSuite ();
};

Ofswitch13TestSuite::Ofswitch13TestSuite ()
  : TestSuite ("ofswitch13", UNIT)
{
  // TestDuration for TestCase can be QUICK, EXTENSIVE or TAKES_FOREVER
  AddTestCase (new Ofswitch13TestCase1, TestCase::QUICK);
}

// Do not forget to allocate an instance of this TestSuite
static Ofswitch13TestSuite ofswitch13TestSuite;

