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
 * Author: Luciano Jerez Chaves <ljerezchaves@gmail.com>
 *         Vitor M. Eichemberger <vitor.marge@gmail.com>
 */

/*
 * Two hosts connected to a single OpenFlow switch.
 * The switch is managed by the default learning controller application.
 *
 *                       Learning Controller
 *                                |
 *                       +-----------------+
 *            Host 0 === | OpenFlow switch | === Host 1
 *                       +-----------------+
 */

#include <ns3/core-module.h>
#include <ns3/csma-module.h>
#include <ns3/internet-apps-module.h>
#include <ns3/internet-module.h>
#include <ns3/network-module.h>
#include <ns3/ofswitch13-module.h>

using namespace ns3;

int
main(int argc, char* argv[])
{
    uint16_t simTime = 10;
    bool verbose = false;
    bool trace = false;

    // Configure command line parameters
    CommandLine cmd;
    cmd.AddValue("simTime", "Simulation time (seconds)", simTime);
    cmd.AddValue("verbose", "Enable verbose output", verbose);
    cmd.AddValue("trace", "Enable datapath stats and pcap traces", trace);
    cmd.Parse(argc, argv);

    if (verbose)
    {
        OFSwitch13Helper::EnableDatapathLogs();
        LogComponentEnable("OFSwitch13Interface", LOG_LEVEL_ALL);
        LogComponentEnable("OFSwitch13Device", LOG_LEVEL_ALL);
        LogComponentEnable("OFSwitch13Port", LOG_LEVEL_ALL);
        LogComponentEnable("OFSwitch13Queue", LOG_LEVEL_ALL);
        LogComponentEnable("OFSwitch13SocketHandler", LOG_LEVEL_ALL);
        LogComponentEnable("OFSwitch13Controller", LOG_LEVEL_ALL);
        LogComponentEnable("OFSwitch13LearningController", LOG_LEVEL_ALL);
        LogComponentEnable("OFSwitch13Helper", LOG_LEVEL_ALL);
        LogComponentEnable("OFSwitch13InternalHelper", LOG_LEVEL_ALL);
    }

    // Enable checksum computations (required by OFSwitch13 module)
    GlobalValue::Bind("ChecksumEnabled", BooleanValue(true));

    // Create two host nodes
    NodeContainer hosts;
    hosts.Create(2);

    // Create the switch node
    Ptr<Node> switchNode = CreateObject<Node>();

    // Use the CsmaHelper to connect host nodes to the switch node
    CsmaHelper csmaHelper;
    csmaHelper.SetChannelAttribute("DataRate", DataRateValue(DataRate("100Mbps")));
    csmaHelper.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));

    NetDeviceContainer hostDevices;
    NetDeviceContainer switchPorts;
    for (size_t i = 0; i < hosts.GetN(); i++)
    {
        NodeContainer pair(hosts.Get(i), switchNode);
        NetDeviceContainer link = csmaHelper.Install(pair);
        hostDevices.Add(link.Get(0));
        switchPorts.Add(link.Get(1));
    }

    // Create the controller node
    Ptr<Node> controllerNode = CreateObject<Node>();

    // Configure the OpenFlow network domain
    Ptr<OFSwitch13InternalHelper> of13Helper = CreateObject<OFSwitch13InternalHelper>();
    of13Helper->InstallController(controllerNode);
    of13Helper->InstallSwitch(switchNode, switchPorts);
    of13Helper->CreateOpenFlowChannels();

    // Install the TCP/IP stack into hosts nodes
    InternetStackHelper internet;
    internet.Install(hosts);

    // Set IPv4 host addresses
    Ipv4AddressHelper ipv4helpr;
    Ipv4InterfaceContainer hostIpIfaces;
    ipv4helpr.SetBase("10.1.1.0", "255.255.255.0");
    hostIpIfaces = ipv4helpr.Assign(hostDevices);

    // Configure ping application between hosts
    PingHelper pingHelper(Ipv4Address(hostIpIfaces.GetAddress(1)));
    pingHelper.SetAttribute("VerboseMode", EnumValue(Ping::VerboseMode::VERBOSE));
    ApplicationContainer pingApps = pingHelper.Install(hosts.Get(0));
    pingApps.Start(Seconds(1));

    // Enable datapath stats and pcap traces at hosts, switch(es), and controller(s)
    if (trace)
    {
        of13Helper->EnableOpenFlowPcap("openflow");
        of13Helper->EnableDatapathStats("switch-stats");
        csmaHelper.EnablePcap("switch", switchPorts, true);
        csmaHelper.EnablePcap("host", hostDevices);
    }

    // Run the simulation
    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    Simulator::Destroy();
}
