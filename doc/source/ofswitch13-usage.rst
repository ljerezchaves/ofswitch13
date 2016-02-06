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

The ``OFSwitch13`` module was designed to work together with the ``ofsoftswitch13`` library, providing an interface for interconnecting the |ns3| simulator to the library. To this end, the ``ofsoftswitch13`` project must be compiled as a *static library* and get proper linked with |ns3| simulator. 

Currently, the user must download and compile the code manually.  Follow the instructions below to compile and link the |ns3| simulator to the ``ofsoftswitch13`` library. *These instructions have been tested on Ubuntu 14.04.3 LTS. Other distributions or versions may require different steps.*

Compiling the library
#####################

Before starting, install the following packages on your system:

.. code-block:: bash

  $ sudo apt-get install build-essential gcc g++ python git mercurial unzip cmake 
  $ sudo apt-get install libpcap-dev libxerces-c2-dev libpcre3-dev flex bison 
  $ sudo apt-get install pkg-config autoconf libtool libboost-dev

First, it is necessary to compile the `ofsoftswitch13` as a static library. The ``ofsoftswitch13`` code relies on another library, called ``NetBee``, which is used to parse the network packets.  So we need to compile and install them in the proper order.

Download the most recent `NetBee` version and unpack the source code:

.. code-block:: bash

  $ wget https://bitbucket.org/ljerezchaves/ofswitch13-module/downloads/nbeesrc.zip
  $ unzip nbeesrc.zip

Create the build system and compile de library:

.. code-block:: bash

  $ cd netbee/src/
  $ cmake .
  $ make

Add the shared libraries built to your library directory, configure dynamic linker run-time bindings, and copy the include files:

.. code-block:: bash

  $ sudo cp ../bin/libn*.so /usr/local/lib
  $ sudo ldconfig
  $ sudo cp -R ../include/* /usr/include/

Ok! We are done with the ``NetBee`` library. Now, let's proceed with the ``ofsoftswitch13`` code. Clone the repository and update to the ``ns3lib`` branch:

.. code-block:: bash

  $ git clone https://github.com/ljerezchaves/ofsoftswitch13
  $ cd ofsoftswitch13
  $ git checkout ns3lib

Configure and build the library (don't forget to add the ``--enable-ns3-lib`` during configuration process):

.. code-block:: bash

  $ ./boot.sh
  $ ./configure --enable-ns3-lib
  $ make

Once everything gets compiled, the static library ``libns3ofswitch13.a`` will be available under ``ofsoftswitch13/udatapath/`` directory. Let's proceed with the |ns3| simulator compilation and linkage.


Linking the library to the simulator
####################################

It's time to download a recent (preferably stable) |ns3| code into your machine. Here, we are going to use the mercurial repository for ns-3.24.

.. code-block:: bash
  
  $ hg clone http://code.nsnam.org/ns-3.24

Before configuring and compiling the simulator, download the ``OFSwitch13`` code from the module repository and place it inside a new ``/src/ofswitch13`` folder:

.. code-block:: bash

  $ cd ns-3.24/src
  $ hg clone https://ljerezchaves@bitbucket.org/ljerezchaves/ofswitch13-module ofswitch13

Also, you need to path the |ns3| code with the patches available under the ``ofswitch13/utils`` directory: 

.. code-block:: bash

  $ cd ../
  $ patch -p1 < src/ofswitch13/utils/ofswitch13-csma.patch 
  $ patch -p1 < src/ofswitch13/utils/ofswitch13-doc.patch 

The ``ofswitch13-csma.patch`` creates a simple new ``TraceSource`` at ``CsmaNetDevice``, allowing OpenFlow switch to get raw L2 packets from this device. The optional ``ofswitch13-doc.patch`` instructs the simulator to include the module in the expository "user-guide"-style chapters, and source code API documentation.

Now, you can configure the |ns3| including the ``--with-ofswitch13`` option to show the simulator where it can find the ``ofsoftswitch13`` main directory:

.. code-block:: bash

  $ ./waf configure --with-ofswitch13=path/to/ofsoftswitch13

Check for the enabled |ns3| OpenFlow 1.3 Integration feature at the end of the configuration process. Finally, compile the simulator:

.. code-block:: bash

  $ ./waf

That's it! Enjoy your |ns3| fresh compilation with OpenFlow 1.3 capabilities. 


Basic module usage
==================


Here goes a general code example::

    // Nodes and Links Configuration:
    NodeContainer hosts;
    hosts.Create (2);

    NodeContainer switches;
    switches.Create (1);

    NodeContainer controller;
    controller.Create (1);

    CsmaHelper csmaHelper;
    NetDeviceContainer hostDevices;
    NetDeviceContainer switchDevices;
    for (size_t i = 0; i < hosts.GetN (); i++)
    {
        NetDeviceContainer link = csmaHelper.Install (NodeContainer (hosts.Get (i), switches.Get(0)));
        hostDevices.Add (link.Get (0));
        switchDevices.Add (link.Get (1));
    }

    ////////////////////////////
    // ofSwitch13 Configuration:

    // First of all, we need to create 2 pointers, to the controller
    // and switches nodes.
    Ptr<Node> of13ControllerNode = controller.Get(0);
    Ptr<Node> of13SwitchNode = switches.Get(0);

    // Then, we just create and use the helper
    OFSwitch13Helper of13Helper; // creates a Helper
    of13Helper.InstallControllerApp (of13ControllerNode); // installs the controller
    of13Helper.InstallSwitch (of13SwitchNode, switchDevices); // installs the switches
    ////////////////////////////

    // Other configurations (apps, ip/tcp, etc)
    ...

    // Simulating
    Simulator::Run ();
    Simulator::Destroy ();

*OBS:*
    * The example above explain nothing more than how to use and configure the *of13switch* module. If you need exmplanation about other details, please checkout the |ns3| tutorial.
    * If you use more than 1 switch, just multiply the switch pointers, node numbers and installations (.InstallSwitch(...)), and don't forget to use 1 NetDeviceContainer for each switch.
    * If you use more than 1 controller, just multiply the controller pointers, node numbers and installations (.InstallControllerApp(...)), and don't forget to use 1 helper (with the respective switches installations) for each controller.

It is very importante **not to forget to include the module** at the beggining of code::

    #include "ns3/ofswitch13-module.h"


Helpers
=======

The helper API, *ns3::OFSwitch13Helper*,  follows the pattern usage of normal helpers. Through the helper you can:
    * Set attributes;
    * Set the adress base;
    * Install switches;
    * Install a controller;
    * Enable pcap (output);

Checkout the usage for more info about it.
The helper source code can be foun in `src/ofswitch13/helper`, if you need more details.

Attributes
==========

*OFSwitch13NetDevice*
    * **DatapathId:** The identification of the OFSwitch13NetDevice/Datapath.
    * **FlowTableDelay:** Overhead for looking up in the flow table (Default: standard TCAM on an FPGA).
    * **DatapathTimeout:** The interval between timeout operations on pipeline.
    * **ControllerAddr:** The controller InetSocketAddress, used to TCP communication.
    * **LibLogLevel:** Set the ofsoftswitch13 library logging level.Use 'none' to turn logging off, or use all' to maximum verbosity.You can also use a custom ofsoftswitch13 verbosity argument.

*OFSwitch13Controller*
    * **Port:** Port on which we listen for incoming packets.

Output
======

The *helper* can generate pcap files (from the csma/ethernet link) as a output.
To do it, use the method like the example below::

    OFSwitch13Helper of13Helper;
    of13Helper.EnableOpenFlowPcap ("ofController");
    // you can change the "ofController" parameter the any other prefix of your preference
    // this block is usualy placed

The pcap generated corresponds to the packet info trafficked by the controller.

It also has it owns log component, wich can be activated by the default |ns3| log methods.
Every .cc file defines a log component:
    * OFSwitch13Helper;
    * OFSwitch13Controller;
    * OFSwitch13Interface;
    * OFSwitch13LearningController;
    * OFSwitch13NetDevice;

So you can access these log components using the function ``LogComponentEnable()`` (specified at http://www.nsnam.org/docs/doxygen/group__logging.html#gadc4ef4f00bb2f5f4edae67fc3bc27f20, in the API) with any log level of your preference (specified at http://www.nsnam.org/docs/doxygen/group__logging.html#gaa6464a4d69551a9cc968e17a65f39bdb, in the API).
The example bellows show how you can enable ALL files with ALL log messages::
    LogComponentEnable ("OFSwitch13SingleExample", LOG_LEVEL_ALL);
    LogComponentEnable ("OFSwitch13Helper", LOG_LEVEL_ALL);
    LogComponentEnable ("OFSwitch13NetDevice", LOG_LEVEL_ALL);
    LogComponentEnable ("OFSwitch13Controller", LOG_LEVEL_ALL);
    LogComponentEnable ("OFSwitch13LearningController", LOG_LEVEL_ALL);
    LogComponentEnable ("OFSwitch13Interface", LOG_LEVEL_WARN);


Advanced Usage
==============

Go into further details (such as using the API outside of the helpers)
in additional sections, as needed.

Examples
========



The examples are located in `src/ofswitch13/examples`.
Here goes a fast description:
    * **single-ofswitch13.cc:** 2 hosts in 1 switch, and 1 controller;
    * **double-ofswitch13.cc:** 2 switches with 1 host (each), and 1 controller;
    * **star-ofswitch13.cc:** n hosts in 1 switch, and 1 controller;
    * **chain-ofswitch13.cc:** n switches with 2 hosts in each extreme, and 1 controller;
    * **dual-controller-ofswitch13.cc:** 4 switches with 1 host (each), and 2 controllers;
    * **external-controller.cc:** 2 hosts in 1 switch, and 1 external controller;
*OBS:* In all cases `n` is a settable parameter.

We also have a controller implementation example: `ofswitch13-learning-controller`.
You can find it in `src/ofswitch13/model`. With 2 files (.cc and .h), the learning controller is a exemple that shows how to create a simple controller wich works as a default switch.

Troubleshooting
===============

More than 1 controller can be complicated at the beginning, so watch out:
    * For n controllers, use n helpers;
    * In each helper, install each controller and every switch that is connect to that controller;

If you're using more than one helper, don't forget to change the adress base, otherwise you can have errors or bugs.
    * for this use the helper method `SetAddressBase (Ipv4Address network, Ipv4Mask mask);`

More doubts? Checkout the examples or the Usage example.
