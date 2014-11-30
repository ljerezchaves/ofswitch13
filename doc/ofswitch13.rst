Example Module Documentation
----------------------------

.. include:: replace.txt
.. highlight:: cpp

.. heading hierarchy:
   ------------- Chapter
   ************* Section (#.#)
   ============= Subsection (#.#.#)
   ############# Paragraph (no number)

OpenFlow 1.3 module for ns-3 simulator

This module can enhance the ns-3 network simulator with OpenFlow 1.3 capabilities. It provides OpenFlow compatibles switch and controller, allowing the user to simulate software defined networks.

Model Description
*****************

This module was designed to work together with the CPqD ofsoftswitch13 user-space software switch implementation, originally available at `https://github.com/CPqD/ofsoftswitch13`. This user-space switch is based on the Ericsson TrafficLab 1.1 softswitch implementation, with changes in the forwarding plane to support OpenFlow 1.3.

In fact, this module provides an interface for interconnecting the ns-3 OFSwitch13NetDevice to the ofsoftswitch13 datapath. Also, it interconnects the OFSwitch13Controller to the dpctl utility, in order to simplify the process of sending OpenFlow messages to the switch. To this end, the ofsoftswitch13 project must be compiled as a static library and get proper linked with ns-3 simulator.

Design
======

Briefly describe the software design of the model and how it fits into 
the existing ns-3 architecture. 

Scope and Limitations
=====================

What can the model do?  What can it not do?  Please use this section to
describe the scope and limitations of the model.

References
==========

Add academic citations here, such as if you published a paper on this
model, or if readers should read a particular specification or other work.


Usage
*****

Here goes a general code example:

```
// Nodes and links configuration
	...

// ofSwitch13 configuration
	Ptr<Node> // Pointers
		of13ControllerNode = of13ControllersNodeContainer.Get(0), // pointer to the controller node
		of13SwitchNode = of13SwitchesNodeContainer.Get(0); // pointer to the switch node

	OFSwitch13Helper of13Helper; // Helper
	of13Helper.InstallControllerApp (of13ControllersNode); // install the controller
	of13Helper.InstallSwitch (of13SwitchesNode, of13SwitchesNetDevices); // install the switch

// Other configurations (apps, ip/tcp, etc)
	...

// Enabling the pcap output
	of13Helper.EnableOpenFlowPcap ("of13"); // enabling the output with the prefix "of13"

// Simulating
	Simulator::Run ();
	Simulator::Destroy ();
```

*OBS:*
* If you use more than 1 switch, just multiply the switch pointers and installations (.InstallSwitch(...))
* If you use more than 1 controller, just multiply the code between `// ofSwitch13 configuration` and `// Other configurations (apps, ip/tcp, etc)`.


Building the Module
===================

To start using this module, the first step is to download and compile the ofsoftswitch13 as a static library. To this, clone the modified repository https://github.com/ljerezchaves/ofsoftswitch13 and update to the ns3lib branch. Follow the instructions on the ofsoftswitch13 README.md file to build the switch, just **replacing the configure command for the following one**:
```
#!bash

./configure --enable-ns3-lib
```
* **Note**: before compiling the ofsoftswitch13, you must install the NetBee library (as indicated in the installation guide. Some users have experienced erros during this process, and it is possible to find the solution at http://tocai.dia.uniroma3.it/compunet-wiki/index.php/Installing_and_setting_up_OpenFlow_tools.

Once everything gets compiled, the libns3openflow13.a library will be available under ofsoftswitch13/udatapath/ directory. Don't forget to run the sudo make install command, otherwise you will experience the following error:
```
#!bash

Error initializing the NetBee Library; Exception during parsing: The primary document entity could not be opened. Id=/usr/local/share/openflow/customnetpdl.xml.
```

Now, its time to download a recent (and stable) ns-3 code from http://www.nsnam.org/releases/ into your machine. 

Before compiling the simulator, place the code from this repository inside a new /src/ofswitch13 folder (you will have to create it). 

Also, you need to path the ns-3 code with the ofswitch13-csma.path available in this repository. This patch creates a simple new TraceSource at CsmaNetDevice, allowing OpenFlow switch to get raw L2 packets from this NetDevice. To this, go to the root ns-3 directory and run the following command:

```
#!bash

patch -p1 < src/ofswitch13/ofswitch13-csma.patch 
```
Now, you can configure the ns-3 including the --with-ofswitch13 option to show the simulator where it can find the ofsoftswitch13 files.
```
#!bash

./waf configure --with-ofswitch13=path/to/ofsoftswitch13
```

That's it! Compile the simulator using ./waf and have fun!

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

***OFSwitch13NetDevice***
* **DatapathId:** The identification of the OFSwitch13NetDevice/Datapath.
* **FlowTableDelay:** Overhead for looking up in the flow table (Default: standard TCAM on an FPGA).
* **DatapathTimeout:** The interval between timeout operations on pipeline.
* **ControllerAddr:** The controller InetSocketAddress, used to TCP communication.
* **LibLogLevel:** Set the ofsoftswitch13 library logging level.Use 'none' to turn logging off, or use all' to maximum verbosity.You can also use a custom ofsoftswitch13 verbosity argument.

***OFSwitch13Controller***
* **Port:** Port on which we listen for incoming packets.

Output
======

The *helper* can generate pcap files (from the csma/ethernet link) as a output.
To do it, use the method like the example below:
```
OFSwitch13Helper of13Helper;
of13Helper.EnableOpenFlowPcap ("ofController");
```
The pcap generated corresponds to the packet info trafficked by the controller.

It also has it owns log component, wich can be activated by the default NS-3 log methods.
Every .cc file defines a log component.

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

Troubleshooting
===============

More than 1 controller can be complicated at the beginning, so watch out:
* For n controllers, use n helpers;
* In each helper, install each controller and every switch that is connect to that controller;

If you're using more than one helper, don't forget to change the adress base, otherwise you can have errors or bugs.
	* for this use `SetAddressBase (Ipv4Address network, Ipv4Mask mask);`

More doubts? Checkout the examples.

Validation
**********

Describe how the model has been tested/validated.  What tests run in the
test suite?  How much API and code is covered by the tests?  Again, 
references to outside published work may help here.
