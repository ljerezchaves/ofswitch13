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

The ``OFSwitch13`` module was designed to work together with the
``ofsoftswitch13`` library, providing an interface for interconnecting the
|ns3| simulator to the library. To this end, the ``ofsoftswitch13`` project
must be compiled as a *static library* and get proper linked with |ns3|
simulator.

Currently, the user must download and compile the code manually. Follow the
instructions below to compile and link the |ns3| simulator to the
``ofsoftswitch13`` library. *These instructions have been tested on Ubuntu
14.04.3 LTS. Other distributions or versions may require different steps,
specially regarding library compilation.*

Compiling the library
#####################

Before starting, install the following packages on your system:

.. code-block:: bash

  $ sudo apt-get install build-essential gcc g++ python git mercurial unzip cmake
  $ sudo apt-get install libpcap-dev libxerces-c2-dev libpcre3-dev flex bison
  $ sudo apt-get install pkg-config autoconf libtool libboost-dev

First, it is necessary to compile the `ofsoftswitch13` as a static library. The
``ofsoftswitch13`` code relies on another library, called ``NetBee``
(http://www.nbee.org), which is used to parse the network packets. So we need
to compile and install them in the proper order.

Download the `NetBee` and unpack the source code:

.. code-block:: bash

  $ wget https://bitbucket.org/ljerezchaves/ofswitch13-module/downloads/nbeesrc.zip
  $ unzip nbeesrc.zip

Create the build system and compile the library:

.. code-block:: bash

  $ cd netbee/src/
  $ cmake .
  $ make

Add the shared libraries built to your library directory, configure dynamic
linker run-time bindings, and copy the include files:

.. code-block:: bash

  $ sudo cp ../bin/libn*.so /usr/local/lib
  $ sudo ldconfig
  $ sudo cp -R ../include/* /usr/include/

We are done with the ``NetBee`` library. Now, let's proceed with the
``ofsoftswitch13`` code. Clone the repository and update to proper (preferably
latest) release tag at the ``ns3lib`` branch (here, we are using v2.0.x):

.. code-block:: bash

  $ git clone https://github.com/ljerezchaves/ofsoftswitch13
  $ cd ofsoftswitch13
  $ git checkout v2.0.x

Configure and build the library (don't forget to add the ``--enable-ns3-lib``
during configuration process):

.. code-block:: bash

  $ ./boot.sh
  $ ./configure --enable-ns3-lib
  $ make

Once everything gets compiled, the static library ``libns3ofswitch13.a`` will
be available under ``ofsoftswitch13/udatapath/`` directory.

Linking the library to the simulator
####################################

It's time to download a recent (preferably stable) |ns3| code into your
machine (here, we are going to use the mercurial repository for ns-3.24.1):

.. code-block:: bash

  $ hg clone http://code.nsnam.org/ns-3.24
  $ cd ns-3.24
  $ hg update ns-3.24.1

Before configuring and compiling the simulator, download the ``OFSwitch13``
code from the module repository and place it inside a new ``/src/ofswitch13``
folder. Update the code to the latest stable version (here, we are using
2.0.1):

.. code-block:: bash

  $ hg clone https://bitbucket.org/ljerezchaves/ofswitch13-module src/ofswitch13
  $ cd src/ofswitch13
  $ hg update 2.0.1
  $ cd ../../

Also, you need to patch the |ns3| code with the appropriated patches available
under the ``ofswitch13/utils`` directory (use the patches for the correct |ns3|
version):

.. code-block:: bash

  $ patch -p1 < src/ofswitch13/utils/ofswitch13-csma-3_24_1.patch
  $ patch -p1 < src/ofswitch13/utils/ofswitch13-doc-3_24_1.patch

The ``ofswitch13-csma-3_24_1.patch`` creates a simple new ``TraceSource`` at
``CsmaNetDevice``, allowing OpenFlow switch to get raw L2 packets from this
device. This is the only required change in the |ns3| code to allow
``OFSwitch13`` usage. The ``ofswitch13-doc-3_24_1.patch`` is optional. It
instructs the simulator to include the module in the |ns3| model library and
source code API documentation, which can be helpful to compile the
documentation using Doxygen and Sphinx.

Now, you can configure the |ns3| including the ``--with-ofswitch13`` option to
show the simulator where it can find the ``ofsoftswitch13`` main directory:

.. code-block:: bash

  $ ./waf configure --with-ofswitch13=path/to/ofsoftswitch13

Check for the enabled |ns3| *OpenFlow 1.3 Integration* feature at the end of
the configuration process. Finally, compile the simulator:

.. code-block:: bash

  $ ./waf

That's it! Enjoy your |ns3| fresh compilation with OpenFlow 1.3 capabilities.

Basic usage
===========

Here is the minimal simulation program that is needed simulate an OpenFlow 1.3
environment. This code connects two hosts to a single switch using CSMA links,
and install the switch and the controller using the ``OFSwitch13Helper``.

.. code-block:: cpp

  // Initial boilerplate
  #include "ns3/core-module.h"
  #include "ns3/network-module.h"
  #include "ns3/internet-module.h"
  #include "ns3/csma-module.h"
  #include "ns3/ofswitch13-module.h"

  using namespace ns3;

  int
  main (int argc, char *argv[])
  {
    // Creating two host nodes
    NodeContainer hosts;
    hosts.Create (2);

    // Create a switch node
    Ptr<Node> switchNode = CreateObject<Node> ();

    // Create a controller node
    Ptr<Node> controllerNode = CreateObject<Node> ();

    // Using a CsmaHelper to connect the host nodes to the switch.
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

    // Configure the OpenFlow network, installing the controller and switch
    Ptr<OFSwitch13Helper> of13Helper = CreateObject<OFSwitch13Helper> ();
    of13Helper->InstallDefaultController (controllerNode);
    of13Helper->InstallSwitch (switchNode, switchPorts);

    // Other configurations: TCP/IP stack, apps, monitors, etc.
    // ...

    // Simulate
    Simulator::Stop (Seconds (10));
    Simulator::Run ();
    Simulator::Destroy ();
  }

To run this code, users *must install* the TCP/IP stack into host nodes, assign
IP addresses to interfaces, and configure any traffic application. You can also
check for the ``start-ofswitch13.cc`` example, which is very similar to this
code. For instructions on how to compile and run simulation programs, please
refer to the |ns3| tutorial.

Helpers
=======

OFSwitch13Helper
################

The single ``OFSwitch13helper`` follows the pattern usage of normal helpers.
This helper can be used to create and configure an OpenFlow 1.3 network with a
single controller and one or more switches.

With the ``ChannelType`` attribute, it is possible to create an OpenFlow
channel using a single shared CSMA channel (default option), interconnecting
the controller to all switches. It is also possible to create individual
connections between the controller and each switch, using either CSMA or
point-to-point links. For configuring a network with more than one controller,
the ``SetAddressBase()`` can be used to set the base network number, network
mask and base address that are used for creating the OpenFlow channel. Using
standard |ns3| channels and devices, it is possible to provide realistic
connections with delay and error models.

For configuring the controller, the ``InstallDefaultController()`` function
creates a new learning controller application and install it into the
controller node. It is possible to install a different controller through the
``InstallControllerApp()`` function. For configuring the switches, the
``InstallSwitch()`` function is used to create a ``OFSwitch13NetDevice``, add
the device to the switch node, and attach the given device container as switch
ports of the switch. Theses ports are the ``CsmaNetDevices`` created during
the connection between the nodes and the switches (connections previously
defined by the user). It is possible to install the switch without ports, using
the ``InstallSwitchesWithoutPorts()`` function. In this case, users must add
ports to the switch later, using the ``OFSwitch13NetDevice::AddSwitchPort()``.
Note that in all cases, the controller *must* be installed by the helper before
the switches.

The helper allows users to enable PCAP and ASCII traces for the OpenFlow
channel through functions ``EnableOpenFlowPcap()`` and
``EnableOpenFlowAscii()``, respectively. It can also enable the library
internal ASCII logs through the ``EnableDatapathLogs()`` function.

Attributes
==========

OFSwitch13Controller
####################

* ``Port``: The port number on which the controller listen for incoming
  packets. This is a read-only attribute, and the default value is port 6653
  (the official IANA port since 2013-07-18).

OFSwitch13NetDevice
###################

* ``DatapathId``: The unique identification of this OpenFlow switch. This is a
  read-only attribute, and the datapath ID is automatically assigned by the
  object constructor.

* ``PortList``: The list of ports available in this switch.

* ``TCAMDelay``: Average time to perform a TCAM operation in pipeline. The
  default value of 30 nanoseconds is the standard TCAM on a NetFPGA. This value
  will be used to calculate the average pipeline delay for packets, based on
  the number of flow entries in the tables.

* ``DatapathTimeout``: The interval time interval between timeout operations on
  pipeline. At each internal, the device checks if any flow in any table is
  timed out and update port status.

* ``ControllerAddr``: The controller ``InetSocketAddress``, used for TCP
  communication between the switch and controller. The default IP 10.100.150.1
  is the one assigned by the helper when installing the controller application.
  For custom installations, change the address accordingly.

* ``LibLogLevel``: Set the ``ofsoftswitch13`` library logging level. Use *none*
  to turn logging off, or use *all* to maximum verbosity. You can also use a
  custom ``ofsoftswitch13`` verbosity argument.

OFSwitch13Port
##############

* ``PortQueue``: The OpenFlow queue to use as the transmission queue in this
  port. This queue will be set for use in the underlying ``CsmaNetDevice``.

OFSwitch13Queue
###############

* ``QueueList``: The list of internal queues associated to this port queue.

* ``Scheduling``: The output queue scheduling algorithm. Currently, only the
  priority algorithm is available.

OFSwitch13Helper
################

* ``ChannelType``: The configuration used to create the OpenFlow channel. Users
  can select between a single shared CSMA connection, of dedicated connection
  between the controller and each switch, using CSMA or point-to-point links.

* ``ChannelDataRate``: The data rate to be used for the OpenFlow channel.

Output
======

This module relies on the |ns3| tracing subsystem for output. The helper allow
users to enable PCAP and ASCII traces for the ``NetDevices`` used as switch
ports and for the OpenFlow channel. It is also possible to enable the internal
``ofsoftswitch13`` library ASCII logging mechanism, using the
``EnableDatapathLogs()`` helper function for all devices, or the
``SetLibLogLevel()`` device function for individual device logging.

For using ASCII traces it is necessary to manually include the
``ns3::PacketMetadata::Enable ()`` at the beginning of the program, before any
packets are sent.

.. _port-coding:

Porting |ns3| OpenFlow code
===========================

For |ns3| OpenFlow users that want to port existing code to the new
``OFSwitch13`` module, keep in mind that this is not an extension of the
available implementation. For simulation scenarios using the existing |ns3|
OpenFlow module configured with the ``ns3::OpenFlowSwitchHelper`` helper and
using the ``ns3::ofi::LearningController``, it is possible to port the code to
the ``OFSwitch13`` with little effort. The following code, based on the
``openflow-switch.cc`` example, is used for demonstration:

.. code-block:: cpp

  // Including module headers
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

This is the "core" OpenFlow configuration part. Here, the user is creating an
``ns3::ofi::LearningController`` object instance to be used as the controller.
It also set the internal attribute ``ExpirationTime`` that is used for cache
timeout. Then, the helper is used to install the OpenFlow switch device into
the ``switchNode`` node. The CSMA devices from ``switchDevices`` container are
installed as OpenFlow ports, and the ``controller`` object is set as the
OpenFlow controller for the network. The following code implements the same
logic in the ``OFSwitch13`` module:

.. code-block:: cpp

  // Including module headers
  #include "ns3/ofswitch13-module.h"

  // Connecting the terminals to the switchNode using CSMA devices and channels.
  // CsmaNetDevices created at the switchNode are in the switchDevices container.
  // ...

  // Create the OpenFlow 1.3 helper
  Ptr<OFSwitch13Helper> of13Helper = CreateObject<OFSwitch13Helper> ();

  // Create the controller node and install the learning controller app into it
  Ptr<Node> controllerNode = CreateObject<Node> ();
  of13Helper->InstallDefaultController (controllerNode);

  // Install the switch device and ports.
  of13Helper->InstallSwitch (switchNode, switchDevices);

  // Other configurations: TCP/IP stack, apps, monitors, etc.
  // ...

  // Arbitrary simulation duration (can be changed for any value)
  Simulator::Stop (Seconds (10));

Note that we need a new node for the controller. The
``InstallDefaultController()`` function will create the learning application
object instance and will install it in the ``controllerNode``. Then, the
``InstallSwitch()`` function will install the OpenFlow device into
``switchNode``, configure the CSMA devices from ``switchDevices`` container as
OpenFlow ports, and configure the connection between the switch and the
controller. Note that the ``OFSwitch13LearningController`` doesn't provide the
``ExpirationTime`` attribute. Don't forget to include the ``Simulator::Stop()``
command to schedule the time delay until the Simulator should stop, otherwise
the simulation will never end.

For users who have implemented new controllers in the |ns3| OpenFlow module,
extending the ``ns3::ofi::Controller`` class, are encouraged to explore the
Doxygen documentation for the ``OFSwitch13Controller`` base class. In a
nutshell, the ``ReceiveFromSwitch()`` function is replaced by the internal
handlers, used to process each type of OpenFlow message received from the
switch. See the :ref:`extending-controller` section for more details.

Advanced Usage
==============

.. _extending-controller:

Extending the controller
########################

The ``OFSwitch13Controller`` base class provides the basic interface for
controller implementation.  For sending OpenFlow messages to the switches,
there are functions for *barrier request* and *echo request* messages.
Furthermore, the ``DpctlCommand()`` function can be used by derived controllers
to convert a variety of ``dpctl`` commands into OpenFlow messages and send it
to the target switch.

The controller uses OpenFlow message handlers to process different OpenFlow
message received from the switches.  Some handler methods can not be
overwritten by derived class (like echo request and reply), as they must behave
as already implemented. In contrast, ``HandlePacketIn()`` *must be implementd
by the derived controller*, to proper handle packets sent from switch to
controller. The current implementation of other virtual methods does nothing:
just free the received message and returns 0. Derived controllers can
override them as they wish. Note that handlers *must* free received messages
(msg) when everything is fine. For ``HandleMultipartReply()`` implementation,
note that there are several types of multipart replies. Derived controllers can
filter by the type they wish.

In the ``OFSwitch13LearningController`` implementation, the
``HandlePacketIn()`` function is used to handle packet-in messages sent from
switch to this controller. It look for L2 switching information, update the
structures and send a packet-out back to the switch. The
``HandleFlowRemoved()`` is used to handle expired flow entries notified by the
switch to this controller. It looks for L2 switching information and removes
associated entry. Developers are encouraged to study the library internal
structures to better understand the handlers' implementation.

``dpctl`` commands
##################

For constructing OpenFlow messages and send to the switches, the controller
relies on the ``dpctl`` utility to simplify the process. This is a management
utility that enable some control over the OpenFlow switch. With this tool it is
possible to add flows to the flow table, query for switch features and status,
and change other configurations.

Check the `utility documentation
<https://github.com/CPqD/ofsoftswitch13/wiki/Dpctl-Documentation>`_ for details
on how to create the commands. Note that the documentation is intended for
terminal usage in Unix systems, which is a little different from the usage in
the ``DpctlCommand()`` function. For this module, consider only the command and
the arguments.

External controller
###################

Considering that the OpenFlow messages traversing the OpenFlow channel follows
the standard wire format, it is possible to use the |ns3| ``TapBridge`` module
to integrate an external OpenFlow 1.3 controller, running on the local system,
to the simulated environment. The experimental ``external-controller.cc``
example was designed to provide this integration. However, this example has not
been tested and validated yet.

Examples
========

The examples are located in `src/ofswitch13/examples`.

* **chain-ofswitch13.cc**: Two hosts and a chain of N OpenFlow 1.3 switches
  with a single controller. Traffic flows from host H0 to H1 through all
  switches.

* **start-ofswitch13.cc**: N hosts connected to a single switch with a single
  controller. Traffic flows between two random hosts.

* **dual-controller.cc**: Four switches connected in line, with a single
  attached to each one. The first pair of switches are controlled by one
  controller while the other pair are managed by a second controller. Traffic
  flows from host H0 to host H2.

* **external-controller.cc**: A single switch connected to a external
  controller over a ``TapBridge``. The default configuration expects a
  controller on you local machine at port 6653. *This example requires more
  tests and validation.*

Troubleshooting
===============

* If your simulation go into an infinite loop, check for the required
  ``Simulator::Stop()`` command to schedule the time delay until the Simulator
  should stop.

* Note that the Spanning Tree Protocol part of 802.1D is not implemented in the
  ``OFSwitch13LearningController``. Therefore, you have to be careful not to
  create bridging loops, or else the network will collapse.

* For simulating scenarios with more than one OpenFlow controller configured
  with the ``OFSwtich13Helper``, use a different helper instance for each
  controller, and don't forget to change the default controller address with
  the ``SetAddressBase()``. Note that the current implementation don't support
  multiple controller, so each switch must be associated with a single
  controller.

* For using ASCII traces it is necessary to manually include the
  ``ns3::PacketMetadata::Enable ()`` at the beginning of the program, before
  any packets are sent.

