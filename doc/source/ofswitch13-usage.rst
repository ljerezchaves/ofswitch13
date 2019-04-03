Usage
*****

.. include:: replace.txt
.. highlight:: cpp

.. heading hierarchy:
   ------------- Chapter
   ************* Section (#.#)
   ============= Subsection (#.#.#)
   ############# Paragraph (no number)

Building the Module
===================

The |ofs13| module was designed as an interface for interconnecting the |ns3|
simulator to the |ofslib| software switch compiled as a library. Follow the
instructions below to compile and link the |ns3| simulator to the |ofslib|
library. *These instructions were tested on Debian 8, Ubuntu 16.04 LTS, and
Ubuntu 18.04 LTS. Other distributions or versions may require different steps,
especially regarding library compilation.*

Before starting
###############

Before starting, ensure you have the following packages installed on your
system [#f1]_:

.. code-block:: bash

  $ sudo apt-get install build-essential gcc g++ python git mercurial unzip cmake
  $ sudo apt-get install pkg-config autoconf libtool libboost-dev

.. [#f1] The *NetBee* library dependence was removed in |ofs13|
         release version 4.0.0.

Compiling the code
##################

Download a recent stable |ns3| code into your machine (we are using the
mercurial repository for ns-3.29):

.. code-block:: bash

  $ hg clone http://code.nsnam.org/ns-3.29

Download the |ofs13| code into the ``src/`` folder (starting with ns-3.28, you
can also download the code into the new ``contrib/`` folder). This procedure
will recursively download the |ofslib| code into the
``ofswitch13/lib/ofsoftswitch13/`` directory.

.. code-block:: bash

  $ cd ns-3.29/src
  $ git clone --recurse-submodules https://github.com/ljerezchaves/ofswitch13.git

Update the code to the desired release version (we are using release 4.0.0,
which is compatible with ns-3.28 or later) [#f2]_:

.. [#f2] For |ofs13| release versions prior to 3.2.2 (when no submodule
         dependence was configured in the git repository), the |ofslib| code
         will not automatically update to the correct version. In this case,
         you must manually updated the |ofslib| code to the proper version
         before compiling the library in the next step (check the release note
         files for versions compatibility).

.. code-block:: bash

  $ cd ofswitch13
  $ git checkout 4.0.0 && git submodule update --recursive

Now it is time to compile the |ofslib| as a static library. Configure and
build the library (don't forget to add the ``--enable-ns3-lib`` during
configuration process):

.. code-block:: bash

  $ cd lib/ofsoftswitch13
  $ ./boot.sh
  $ ./configure --enable-ns3-lib
  $ make

Once everything gets compiled, the static library ``libns3ofswitch13.a`` file
will be available under the ``lib/ofsoftswitch13/udatapath`` directory. Go back
to the |ns3| root directory and patch the |ns3| code with the appropriated
patches available under the ``ofswitch13/utils`` directory (check for the
correct |ns3| version):

.. code-block:: bash

  $ cd ../../../../
  $ patch -p1 < src/ofswitch13/utils/ofswitch13-src-3_29.patch
  $ patch -p1 < src/ofswitch13/utils/ofswitch13-doc-3_29.patch

The ``src`` patch creates the new OpenFlow receive callback at
``CsmaNetDevice`` and ``VirtualNetDevice``, allowing OpenFlow switch to get raw
packets from these devices. These are the only required changes in the |ns3|
code for |ofs13| integration. The ``doc`` patch is optional, and instructs the
simulator to include the module in the |ns3| model library and source code API
documentation, which can be helpful to compile the documentation using Doxygen
and Sphinx.

Now, configure the |ns3|. By default, the configuration script will look for
the |ofslib| library in the ``lib/ofsoftswitch13/`` directory (use the
``--with-ofswitch13`` option to specify a different location):

.. code-block:: bash

  $ ./waf configure

Check for the enabled *NS-3 OpenFlow 1.3 integration* feature after
configuration. Finally, compile the simulator:

.. code-block:: bash

  $ ./waf

That's it! Enjoy your |ns3| fresh compilation with OpenFlow 1.3 capabilities.

Basic usage
===========

Here is the minimal script that is necessary to simulate an OpenFlow 1.3
network domain (code extracted from ``ofswitch13-first.cc`` example). This
script connects two hosts to a single OpenFlow switch using CSMA links, and
configure both the switch and the controller using the
``OFSwitch13InternalHelper`` class.

.. code-block:: cpp

  #include <ns3/core-module.h>
  #include <ns3/network-module.h>
  #include <ns3/csma-module.h>
  #include <ns3/internet-module.h>
  #include <ns3/ofswitch13-module.h>
  #include <ns3/internet-apps-module.h>

  using namespace ns3;

  int
  main (int argc, char *argv[])
  {
    // Enable checksum computations (required by OFSwitch13 module)
    GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

    // Create two host nodes
    NodeContainer hosts;
    hosts.Create (2);

    // Create the switch node
    Ptr<Node> switchNode = CreateObject<Node> ();

    // Use the CsmaHelper to connect the host nodes to the switch.
    CsmaHelper csmaHelper;
    NetDeviceContainer hostDevices;
    NetDeviceContainer switchPorts;
    for (size_t i = 0; i < hosts.GetN (); i++)
      {
        NodeContainer pair (hosts.Get (i), switchNode);
        NetDeviceContainer link = csmaHelper.Install (pair);
        hostDevices.Add (link.Get (0));
        switchPorts.Add (link.Get (1));
      }

    // Create the controller node
    Ptr<Node> controllerNode = CreateObject<Node> ();

    // Configure the OpenFlow network domain
    Ptr<OFSwitch13InternalHelper> of13Helper = CreateObject<OFSwitch13InternalHelper> ();
    of13Helper->InstallController (controllerNode);
    of13Helper->InstallSwitch (switchNode, switchPorts);
    of13Helper->CreateOpenFlowChannels ();

    // Install the TCP/IP stack into hosts nodes
    InternetStackHelper internet;
    internet.Install (hosts);

    // Set IPv4 host addresses
    Ipv4AddressHelper ipv4helpr;
    Ipv4InterfaceContainer hostIpIfaces;
    ipv4helpr.SetBase ("10.1.1.0", "255.255.255.0");
    hostIpIfaces = ipv4helpr.Assign (hostDevices);

    // Configure ping application between hosts
    V4PingHelper pingHelper = V4PingHelper (hostIpIfaces.GetAddress (1));
    pingHelper.SetAttribute ("Verbose", BooleanValue (true));
    ApplicationContainer pingApps = pingHelper.Install (hosts.Get (0));
    pingApps.Start (Seconds (1));

    // Run the simulation
    Simulator::Stop (Seconds (10));
    Simulator::Run ();
    Simulator::Destroy ();
  }

At first, don't forget to enable checksum computations, which are required by
the |ofs13| module. After creating host and switch nodes, the user is
responsible for connect the hosts and switches to create the desired network
topology. Using CSMA links for these connections is mandatory. Note that
``CsmaNetDevices`` created and installed into switch node will be later
configured as switch ports. After connecting hosts and switches, it's time to
create a controller node and configure the OpenFlow network. The
``OFSwitch13InternalHelper`` can be used to configure an OpenFlow network
domain with internal controller application. The ``InstallController()`` method
configures the controller node with a default OpenFlow learning controller
application. The ``InstallSwitch()`` method installs the OpenFlow datapath into
switch node and configures the switch ports. In the end, it's mandatory to call
the ``CreateOpenFlowChannels()`` method to create the connections and start the
communication between switches and controllers.

The rest of this example follows the standard |ns3| usage: installing TCP/IP
stack into host nodes, configuring IP addresses, installing applications and
running the simulation. Don't install the TCP/IP stack into switches and
controllers nodes (the helper does that for you). Also, don't assign an IP
address to devices configured as switch ports. For instructions on how to
compile and run simulation programs, please refer to the |ns3| tutorial.

Helpers
=======

OFSwitch13Helper
################

This module follows the pattern usage of standard helpers. The
``OFSwitch13Helper`` is a base class that must be extended to create and
configure an OpenFlow 1.3 network domain, composed of one or more OpenFlow
switches connected to single or multiple OpenFlow controllers. By default,
the connections between switches and controllers are created using a single
shared out-of-band CSMA channel, with IP addresses assigned to the
10.100.0.0/24 network. Users can modify this configuration by changing the
``OFSwitch13Helper::ChannelType`` attribute (dedicated out-of-band connections
over CSMA or point-to-point channels are also available), or setting a
different IP network address with the ``OFSwitch13Helper::SetAddressBase()``
static method. The use of standard |ns3| channels and devices provides
realistic connections with delay and error models.

This base class brings the methods for configuring the switches (derived
classes configure the controllers). The ``InstallSwitch()`` method can be used
to create and aggregate an ``OFSwitch13Device`` object to each switch node. By
default, the ``InstallSwitch()`` method configures the switches without ports,
so users must add the ports to the switch later, using the device
``AddSwitchPort()``. However, it is possible to send to the ``InstallSwitch()``
method a container with ``NetDevices`` that will be configured as switch ports
of a single switch node.

Each port is configured with the ``CsmaNetDevice`` created during the
connection between switch nodes and other nodes in the simulation (the user
must previously define these connections). It is also possible to use a
``VirtualNetDevice`` as a logical port, allowing the user to configure custom
operations like tunneling.

After installing the switches and controllers, it is mandatory to use the
``CreateOpenFlowChannels()`` member method to effectively create and start the
connections between all switches and all controllers on the same domain. After
calling this method, you will not be allowed to install more switches nor
controllers using this helper. Please note that this helper was designed to
configure a single OpenFlow network domain. If you want to configure separated
OpenFlow domains on your network topology (with their switches and controllers)
so you may need to use a different helper instance for each domain.

This helper also allows users to enable some module outputs that are used for
traffic monitoring and performance evaluation. Please, check the :ref:`output`
section for detailed information.

OFSwitch13InternalHelper
########################

This helper extends the base class and can be instantiated to create and
configure an OpenFlow 1.3 network domain composed of one or more OpenFlow
switches connected to a single or multiple internal simulated OpenFlow
controllers. It brings methods for installing the controller and creating the
OpenFlow channels.

To configure the controller, the ``InstallController()`` method can be used to
create a (default) new learning controller application and install it into the
controller node indicated as parameter. It is also possible to install a
different controller application other than the learning controller using
this same method by setting the proper application parameter. Note that this
helper is prepared to install a single controller application at each
controller node, so don't install a second application on the same node,
otherwise the helper will crash.

OFSwitch13ExternalHelper
########################

This helper extends the base class and can be instantiated to create and
configure an OpenFlow 1.3 network domain composed of one or more OpenFlow
switches connected to a single external real OpenFlow controller. It brings
methods for installing the controller node for TapBridge usage and creating the
OpenFlow channels. The current implementation only supports the single shared
CSMA channel type.

To configure the external controller, the ``InstallExternalController()``
method can be used to prepare the controller node so it can be used to connect
internal simulated switches to an external OpenFlow controller running on the
local machine over a TapBridge device. It installs the TCP/IP stack into
controller node, attach it to the common CSMA channel, configure IP address for
it and returns the ``NetDevice`` that the user will be responsible to bind to
the TabBridge. Note that this helper is prepared to configure a single
controller node. See the :ref:`external-controller` section for more details.

Attributes
==========

OFSwitch13Controller
####################

* ``Port``: The port number on which the controller application listen for
  incoming packets. The default value is port 6653 (the official IANA port
  since 2013-07-18).

OFSwitch13Device
################

* ``DatapathId``: The unique datapath identification of this OpenFlow switch.
  The datapath ID is a read-only attribute, automatically assigned by the
  object constructor.

* ``CpuCapacity``: The data rate used to model the CPU processing capacity
  (throughput). Packets exceeding this capacity are discarded.

* ``FlowTableSize``: The maximum number of entries allowed on each flow table.

* ``GroupTableSize``: The maximum number of entries allowed on group table.

* ``MeterTableSize``: The maximum number of entries allowed on meter table.

* ``PipelineTables``: The number of pipeline flow tables.

* ``PortList``: The list of ports available in this switch.

* ``TcamDelay``: Average time to perform a TCAM operation in the pipeline. This
  value is used to calculate the average pipeline delay based on the
  number of flow entries in the tables, as described in :ref:`switch-device`.

* ``TimeoutInterval``: The time between timeout operations in the pipeline. At
  each interval, the device checks if any flow in any table is timed out and
  update port status.

OFSwitch13Port
##############

* ``PortQueue``: The OpenFlow queue to use as the transmission queue in this
  port. When the port is constructed over a ``CsmaNetDevice``, this queue is
  set for use in the underlying device. When the port is constructed over a
  ``VirtualNetDevice``, this queue is not used.

* ``QueueFactory``: The object factory describing the OpenFlow queue to be
  created for this port.

OFSwitch13Queue
###############

* ``QueueList``: The list of internal queues.

OFSwitch13PriorityQueue
#######################

* ``QueueFactory``: The object factory describing the internal priority queues
  to be created.

* ``NumQueues``: The number of internal priority queues.

OFSwitch13Helper
################

* ``ChannelDataRate``: The data rate for the OpenFlow channel links.

* ``ChannelType``: The configuration used to create the OpenFlow channel. Users
  can select between a single shared CSMA connection, or dedicated connection
  between the controller and each switch, using CSMA or point-to-point links.

OFSwitch13ExternalHelper
########################

* ``Port``: The port number on which the external controller application
  listen for incoming packets. The default value is port 6653 (the official
  IANA port since 2013-07-18).

OFSwitch13StatsCalculator
#########################

* ``EwmaAlpha``: The EWMA alpha parameter, which is the weight given to the
  most recent measured value when updating average metrics values.

* ``DumpTimeout``: The interval between successive dump operations.

* ``OutputFilename``: The filename used to save OpenFlow switch datapath
  performance statistics.

.. _output:

Output
======

This module relies on the |ns3| tracing subsystem for output. The
``OFSwitch13Helper`` base class allows users to monitor control-plane traffic
by enabling PCAP and ASCII trace files for the ``NetDevices`` used to create
the OpenFlow Channel(s). This approach can be useful to analyze the OpenFlow
messages exchanged between switches and controllers on this network domain. To
enable these traces, use the ``EnableOpenFlowPcap()`` and
``EnableOpenFlowAscii()`` helper member functions *after* configuring the
switches and creating the OpenFlow channels. It is also possible to enable
PCAP and ASCII trace files to monitor data-plane traffic on switch ports using
the standard ``CsmaHelper`` trace functions.

For performance evaluation, the ``OFSwitch13StatsCalculator`` class can monitor
statistics of an OpenFlow switch datapath. The instances of this class connect
to a collection of trace sources in the switch device and periodically dumps
the following datapath metrics on the output file:

#. [``LoaKbps``] CPU porocessing load in the last interval (Kbps);
#. [``LoaUsag``] Average CPU processing capacity usage (percent);
#. [``Packets``] Packets processed by the pipeline in the last interval;
#. [``DlyUsec``] EWMA pipeline lookup delay for packet processing (usecs);
#. [``LoaDrop``] Packets dropped by capacity overloaded in the last interval;
#. [``MetDrps``] Packets dropped by meter bands in the last interval;
#. [``FloMods``] Flow-mod operations executed in the last interval;
#. [``MetMods``] Meter-mod operations executed in the last interval;
#. [``GroMods``] Group-mod operations executed in the last interval;
#. [``PktsIn``]  Packets-in sent to the controller in the last interval;
#. [``PktsOut``] Packets-out received from the controller in the last interval;
#. [``FloEntr``] EWMA sum of entries in all pipeline flow tables;
#. [``FloUsag``] Average flow table usage, considering the sum of entries in
all flow tables divided by the aggregated sizes of all flow tables with at
least one flow entry installed (percent);
#. [``MetEntr``] EWMA number of entries in meter table;
#. [``MetUsag``] Average meter table usage (percent);
#. [``GroEntr``] EWMA number of entries in group table;
#. [``GroUsag``] Average group table usage (percent);
#. [``BufPkts``] EWMA number of packets in switch buffer;
#. [``BufUsag``] Average switch buffer usage (percent);

When the FlowTableDetails attribute is set to 'true', the EWMA number of
entries and the average flow table usage for each pipeline flow table is also
available under the columns ``T**Entr`` and ``T**Usag``.

To enable performance monitoring, use the ``EnableDatapathStats()``
helper member function *after* configuring the switches and creating the
OpenFlow channels. By default, statistics are dumped every second, but users
can adjust this timeout by changing the
``OFSwitch13StatsCalculator::DumpTimeout`` attribute. Besides, for the average
metrics, an Exponentially Weighted Moving Average (EWMA) is used to update the
values, and the attribute ``OFSwitch13StatsCalculator::EwmaAlpha`` can be
adjusted to reflect the desired weight given to most recent measured values.

When necessary, it is also possible to enable the internal |ofslib| library
ASCII logging mechanism using two different approaches:

#. The simplified ``OFSwitch13Helper::EnableDatapathLogs()`` static method
   dumps messages at debug level for all library internal modules into the
   output file (users can set the filename prefix);

#. The advanced ``ofs::EnableLibraryLog()`` method allow users to define the
   target log facility (the console or a file), set the filename, and also
   customize the logging levels for different library internal modules.

.. _port-coding:

Porting |ns3| OpenFlow code
===========================

For |ns3| OpenFlow users that want to port existing code to the new |ofs13|
module, keep in mind that this is not an extension of the available
implementation. For simulation scenarios using the existing |ns3| OpenFlow
module configured with the ``ns3::OpenFlowSwitchHelper`` helper and using the
``ns3::ofi::LearningController``, it is possible to port the code to the
|ofs13| module with little effort. The following code, based on the
``openflow-switch.cc`` example, is used for demonstration:

.. code-block:: cpp

  #include "ns3/openflow-module.h"

  // Connecting the terminals to the switchNode using CSMA devices and channels.
  // CsmaNetDevices created at the switchNode are in the switchDevices container.
  // ...

  // Create the OpenFlow helper
  OpenFlowSwitchHelper ofHelper;

  // Create the learning controller app
  Ptr<ns3::ofi::LearningController> controller;
  controller = CreateObject<ns3::ofi::LearningController> ();
  if (!timeout.IsZero ())
    {
      controller->SetAttribute ("ExpirationTime", TimeValue (timeout));
    }

  // Install the switch device, ports and set the controller
  ofHelper.Install (switchNode, switchDevices, controller);

  // Other configurations: TCP/IP stack, apps, monitors, etc.
  // ...

This code creates an ``ns3::ofi::LearningController`` object instance as the
controller. It also sets the internal attribute ``ExpirationTime`` for cache
timeout. Then, the helper installs the OpenFlow switch device into the
``switchNode`` node. The CSMA devices from ``switchDevices`` container are
installed as OpenFlow ports, and the ``controller`` object is set as the
OpenFlow controller for the network. The following code implements the same
logic in the |ofs13| module:

.. code-block:: cpp

  #include "ns3/ofswitch13-module.h"

  // Connecting the terminals to the switchNode using CSMA devices and channels.
  // CsmaNetDevices created at the switchNode are in the switchDevices container.
  // ...

  // Create the OpenFlow 1.3 helper
  Ptr<OFSwitch13InternalHelper> of13Helper = CreateObject<OFSwitch13InternalHelper> ();

  // Create the controller node and install the learning controller app into it
  Ptr<Node> controllerNode = CreateObject<Node> ();
  of13Helper->InstallController (controllerNode);

  // Install the switch device and ports.
  of13Helper->InstallSwitch (switchNode, switchDevices);

  // Create the OpenFlow channel connections.
  of13Helper->CreateOpenFlowChannels ();

  // Other configurations: TCP/IP stack, apps, monitors, etc.
  // ...

  // Arbitrary simulation duration (can be changed for any value)
  Simulator::Stop (Seconds (10));

Note that the |ofs13| module requires a new node to install the controller
application into it. The ``InstallController()`` function creates the learning
application object instance and installs it in the ``controllerNode``. Then,
the ``InstallSwitch()`` function installs the OpenFlow device into
``switchNode`` and configures the CSMA devices from ``switchDevices`` container
as OpenFlow ports. Finally, the ``CreateOpenFlowChannels()`` function
configures the connection between the switch and the controller. Note that the
``OFSwitch13LearningController`` does not provide the ``ExpirationTime``
attribute. Don't forget to include the ``Simulator::Stop()`` command to
schedule the time delay until the Simulator should stop; otherwise, the
simulation will never end.

For users who have implemented new controllers in the |ns3| OpenFlow module,
extending the ``ns3::ofi::Controller`` class, are encouraged to explore the
examples and the Doxygen documentation for the ``OFSwitch13Controller`` base
class. In a nutshell, the ``ReceiveFromSwitch()`` function is replaced by the
internal handlers, used to process each type of OpenFlow message received from
the switch. See the :ref:`extending-controller` section for more details.

Advanced Usage
==============

``dpctl`` commands
##################

For constructing OpenFlow messages and sending them to the switches, the
controller relies on the ``dpctl`` utility to simplify the process. The
``dpctl`` is a management utility that enables some control over the OpenFlow
switch. With this tool, it is possible to add flows to the flow table, query
for switch features and status, and change other configurations. The
``DpctlExecute()`` function can be used by derived controllers to convert a
variety of ``dpctl`` commands into OpenFlow messages and send it to the target
switch. There's also the ``DpctlSchedule()`` variant, which can be used to
schedule commands to be executed just after the handshake procedure between the
controller and the switch (this can be useful for scheduling commands during
the topology creation, before the simulation start).

Check the `utility documentation
<https://github.com/CPqD/ofsoftswitch13/wiki/Dpctl-Documentation>`_ for details
on how to create the commands. Note that the documentation is intended for
terminal usage in Unix systems, which is a little different from the usage in
the ``DpctlExecute()`` function. For this module, ignore the options and switch
reference, and consider only the command and the arguments. You can find some
examples of this syntax at :ref:`qos-controller` source code.

.. _extending-controller:

Extending the controller
########################

The ``OFSwitch13Controller`` base class provides the necessary interface for
controller implementation. It uses the ``dpctl`` commands for sending OpenFlow
messages to the switches. The controller also uses OpenFlow message handlers
to process different OpenFlow message received from the switches. Some handler
methods cannot be modified by derived class, as they must behave as already
implemented. Other handlers can be overridden by derived controllers to proper
parse packets sent from switch to controller and implement the desired control
logic. The current implementation of these virtual handler methods does
nothing: only free the received message and returns 0. Note that handlers
*must* free received messages (msg) when everything is fine. For
``HandleMultipartReply()`` implementation, note that several types of multipart
replies can be filtered.

In the ``OFSwitch13LearningController`` implementation, the
``HandlePacketIn()`` function is used to handle packet-in messages sent from
switch to this controller. It looks for L2 switching information, updates the
structures and sends a packet-out back to the switch. The
``HandleFlowRemoved()`` is used to handle expired flow entries notified by the
switch to this controller. It looks for L2 switching information and removes
associated entry.

The ``QosController`` example includes a non-trivial controller implementation
that is used to configure the network described in :ref:`qos-controller`
section. Several ``dpctl`` commands are used to configure the switches based on
network topology and desired control logic, while the ``HandlePacketIn()`` is
used to filter packets sent to the controller by the switch. Note that the
|ofslib| function ``oxm_match_lookup()`` is used across the code to extract
match information from the message received by the controller. For ARP
messages, ``HandleArpPacketIn()`` exemplifies how to create a new packet at the
controller and send to the network over a packet-out message. Developers are
encouraged to study the library internal structures to understand better how
the handlers are implemented and also how to build an OpenFlow message
manually.

.. _external-controller:

External controller
###################

Considering that the OpenFlow messages traversing the OpenFlow channel follow
the standard wire format, it is possible to use the |ns3| ``TapBridge`` module
to integrate an external OpenFlow 1.3 controller, running on the local system,
to the simulated environment. The experimental ``external-controller.cc``
example uses the ``OFSwitch13ExternalHelper`` to this end, as follows:

.. code-block:: cpp

  // ...
  // Configure the OpenFlow network domain using an external controller
  Ptr<OFSwitch13ExternalHelper> of13Helper = CreateObject<OFSwitch13ExternalHelper> ();
  Ptr<NetDevice> ctrlDev = of13Helper->InstallExternalController (controllerNode);
  of13Helper->InstallSwitch (switches.Get (0), switchPorts [0]);
  of13Helper->InstallSwitch (switches.Get (1), switchPorts [1]);
  of13Helper->CreateOpenFlowChannels ();

  // TapBridge the controller device to local machine
  // The default configuration expects a controller on local port 6653
  TapBridgeHelper tapBridge;
  tapBridge.SetAttribute ("Mode", StringValue ("ConfigureLocal"));
  tapBridge.SetAttribute ("DeviceName", StringValue ("ctrl"));
  tapBridge.Install (controllerNode, ctrlDev);

  // ...

The ``InstallExternalController()`` function configures the controller node as
a "ghost node" on the simulator. This function returns the net device created
at the controller node (``ctrlDev``), and the user is responsible for binding
it to the ``TapBridge`` device, so it appears as if it were replacing the TAP
device in the Linux. The default configuration expects that the OpenFlow
controller is running on the local machine at port 6653 (the helper
automatically sets the IP address). Users can modify the local port number
setting the ``OFSwitch13ExternalHelper::Port`` attribute.

This example was tested with the Floodlight 1.2 controller
(http://www.projectfloodlight.org) running on the local machine. Consistent
behavior was observed once sufficient time elapses (say 3 to 5 minutes) between
any two executions.

Examples
========

The examples are located in ``src/ofswitch13/examples``.

Examples summary
################

* **ofswitch13-first**: Two hosts connected to a single OpenFlow switch. The
  default learning controller application manages the switch.

* **ofswitch13-multiple-controllers**: Two hosts connected to a single OpenFlow
  switch. The default learning controller application manages both switches.

* **ofswitch13-multiple-domains**: Two hosts connected to different OpenFlow
  switches. An independent default learning controller application manages each
  switch.

* **ofswitch13-single-domain**: Two hosts connected to different OpenFlow
  switches. Both switches are managed by the default learning controller
  application.

* **ofswitch13-custom-switch**: Two hosts connected to a single OpenFlow
  switch. The default learning controller application manages the switch. The
  switch datapath can be customized by the command line parameters.

* **ofswitch13-external-controller**: Two hosts connected to different OpenFlow
  switches. The same external controller application manages both switches.

* **ofswitch13-logical-port**: Two hosts connected to different OpenFlow
  switches. The tunnel controller application manages both switches.
  The ports interconnecting the switches are configured as logical ports,
  allowing switches to de/encapsulate IP traffic using the GTP/UDP/IP tunneling
  protocol.

* **ofswitch13-qos-controller**: It represents the internal network of an
  organization, where servers and client nodes are located far from each other.
  A specialized *OpenFlow QoS controller* manages the network,
  implementing some QoS functionalities and exploiting OpenFlow 1.3 features.
  :ref:`qos-controller` section below details this example.

.. _qos-controller:

The QoS controller example
##########################

A case study scenario was used by [Chaves2016]_ to demonstrate how some of the
available OpenFlow 1.3 module features can be employed to improve network
management. Figure :ref:`fig-network-topo` shows the network topology used in
this example. It represents the internal network of an organization, where
servers and client nodes are located far from each other (e.g., in separated
buildings). The "long-distance" connection between the sites is via two links
of 10 Mbps each, while all the other local connections are 100 Mbps. On the
server side, the *OpenFlow border switch* acts as a border router element: it
is responsible for handling connection requests coming from the clients and
redirecting them to the appropriate internal server. On the client side, the
*OpenFlow client switch* is used to interconnect all clients in a star
topology. Between these two switches, there is the *OpenFlow aggregation
switch*, located at the border of the client side and used to provide improved
long-distance communication. The default |ofs13| learning controller is used to
manage the client switch, whereas the new *OpenFlow QoS controller* is used to
manage the other two switches. The latter controller implements some QoS
functionalities exploiting OpenFlow 1.3 features, as described below. Each
client opens a single TCP connection with one of the 2 available servers, and
sends packets in uplink direction as much as possible, trying to fill the
available bandwidth.

.. _fig-network-topo:

.. figure:: figures/ofswitch13-qos-topology.*
   :align: center

   Network topology for QoS controller example

**Link aggregation**:
The link aggregation can be used to combine multiple network connections in
parallel to increase throughput beyond what a single connection could sustain.
The OpenFlow group table is used to split the traffic and implement the link
aggregation.

OpenFlow groups were introduced in OpenFlow 1.1 as a way to perform more
complex operations on packets that cannot be defined within a flow alone. Each
group receives packets as input and performs any OpenFlow actions on these
packets. The power of a group is that it contains separate lists of actions,
and each action list is referred to as an OpenFlow bucket. There are different
types of groups, and the *select* group type can be used to perform link
aggregation. Each bucket in a select group has an assigned weight, and each
packet that enters the group is sent to a single bucket. The bucket selection
algorithm is undefined and is dependent on the switch's implementation (the
|ofslib| library implements the weighted round robin algorithm).

In the proposed network topology, the QoS controller configures both the border
and the aggregation switches to perform link aggregation over the two
narrowband long-distance connections, providing a 20 Mbps connection between
servers and clients (use the ``QosController::LinkAggregation`` attribute to
enable/disable this feature). Each OpenFlow bucket has the same weight in the
select group, so the load is evenly distributed among the links.

**Load balancing**:
A load balancing mechanism can be used to distribute workloads across multiple
servers. Among many goals, it aims to optimize resource use and avoid overload
of any single server. One of the most commonly used applications of load
balancing is to provide single Internet service from multiple servers,
sometimes known as a server farm.

In the proposed network topology, the OpenFlow QoS controller configures the
border switch to listen for new requests on the IP and port where external
clients connect to access the servers. The switch forwards the new request to
the controller, which decides which of the internal servers must take care
of this connection. Then, it installs the match rules into border switch to
forward the subsequent packets from the same connection directly to the chosen
server. All this happen without the client ever knowing about the internal
separation of functions.

To implement this load balancing mechanism, the QoS controller depends on the
extensible match support introduced in OpenFlow 1.2. Prior versions of the
OpenFlow specification used a static fixed length structure to specify matches,
which prevents flexible expression of matches and prevents the inclusion of new
match fields. The extensible match support allows the switch to match ARP
request messages looking for the server IP address and redirect them to the
controller, which creates the ARP reply message and send it back to the
network. The set-field action is used by the border switch to rewrite packet
headers, replacing source/destinations IP addresses for packets
leaving/entering the server farm.

**Per-flow meters**:
OpenFlow meter table, introduced in OpenFlow 1.3, enables the switch to
implement various simple QoS operations. A meter measures the rate of packets
assigned to it and enables controlling the rate of those packets. The meter
triggers a meter band if the packet rate or byte rate passing through the
meter exceeds a predefined threshold. If the meter band drops the packet, it is
called a rate limiter.

To illustrate the meter table usage, the OpenFlow QoS controller can optionally
limit each connection throughput to a predefined data rate threshold,
installing meter rules at the border switch along with the load balancing flow
entries (use the ``QosController::EnableMeter`` and ``MeterRate`` attributes
to enable/disable this feature).

Troubleshooting
===============

* If your simulation go into an infinite loop, check for the required
  ``Simulator::Stop()`` command to schedule the time delay until the Simulator
  should stop.

* Note that the ``OFSwitch13LearningController`` does not implement the
  Spanning Tree Protocol part of 802.1D. Therefore, you have to be careful not
  to create loops on the connections between switches, otherwise, the network
  will collapse.

* For simulating scenarios with more than one OpenFlow network domain
  configured with the ``OFSwtich13InternalHelper``, use a different helper
  instance for each domain.

* For using ASCII traces it is necessary to include the
  ``ns3::PacketMetadata::Enable ()`` at the beginning of the program, before
  any packets being sent.
