Module Description
******************

.. include:: replace.txt
.. highlight:: cpp

.. heading hierarchy:
   ------------- Chapter
   ************* Section (#.#)
   ============= Subsection (#.#.#)
   ############# Paragraph (no number)

Overview
========

The |ofs13| module enhances the `ns-3 Network Simulator <http://www.nsnam.org>`_ with Software-Defined Networking (SDN) support.
Despite the fact that the |ns3| already has a module for simulating OpenFlow switches, it provides a very outdated protocol implementation (OpenFlow 0.8.9, from 2008).
Alternatively, |ofs13| supports OpenFlow protocol version 1.3, bringing both a switch device and a controller application interface to the |ns3| simulator, as depicted in :ref:`fig-ofswitch13-module`, from [Chaves2016a]_.
With |ofs13|, it is possible to interconnect |ns3| nodes to send and receive traffic using ``CsmaNetDevice`` or ``VirtualNetDevice``.
The controller application interface can be extended to implement any desired control logic to orchestrate the network.
The communication between the controller and the switch is realized over standard |ns3| protocol stack, devices, and channels.
The |ofs13| module relies on the external `BOFUSS library for OFSwitch13 <https://github.com/ljerezchaves/ofsoftswitch13>`_.
This library provides the switch datapath implementation, the support for converting OpenFlow messages to/from wire format, and the ``dpctl`` utility tool for configuring the switch from the command line.

.. _fig-ofswitch13-module:

.. figure:: figures/ofswitch13-module.*
   :align: center

   The |ofs13| module overview

Design
======

.. _switch-device:

OpenFlow 1.3 Switch Device
##########################

The OpenFlow 1.3 switch device, namely ``OFSwitch13Device``, can be used to interconnect |ns3| nodes using the existing network devices and channels.
:ref:`fig-ofswitch13-netdevice` figure shows the internal switch device structure. It takes a collection of ``OFSwitch13Port`` acting as input/output ports, each one associated with an |ns3| underlying ``NetDevice``.
In most cases, the ``CsmaNetDevice`` is used to build the ports, which will act as physical ports.
However, it is possible to use the ``VirtualNetDevice`` to implement logical ports.
The switch device acts as the intermediary between the ports, receiving a packet from one port and forwarding it to another.
The |bofuss| library provides the OpenFlow switch datapath implementation (flow tables, group table, and meter table).
Thus, packets entering the switch are sent to the library for OpenFlow pipeline processing before being forwarded to the correct output port(s).
OpenFlow messages received from the controller are also sent to the library for datapath configuration.

.. _fig-ofswitch13-netdevice:

.. figure:: figures/ofswitch13-switch.*
   :align: center

   The ``OFSwitch13Device`` internal structure

A packet enters the switch device through the OpenFlow receive callback in the underlying ``NetDevice``, which is invoked for successfully received packets.
This callback is a promiscuous one, but in contrast to a promiscuous protocol handler, the packet sent to this callback includes all the headers required for OpenFlow pipeline processing.
Including this new callback in the ``NetDevice`` is the only required modification to the |ns3| source code for |ofs13| usage.

The incoming packet is checked for conformance to the CPU processing capacity (throughput) defined by the ``OFSwitch13Device::CpuCapacity`` attribute.
Packets exceeding CPU processing capacity are dropped, while conformant packets are sent to the pipeline at the |bofuss| library.
The module considers the concept of *virtual TCAM* (Ternary Content-Addressable Memory) to estimate the average flow table search time to model OpenFlow hardware operations.
It considers that real OpenFlow implementations use sophisticated search algorithms for packet matching such as hierarchical hash tables or binary search trees.
Because of that, the equation *K \* log_2 (n)* is used to estimate the delay, where *K* is the ``OFSwitch13Device::TcamDelay`` attribute set to the time for a single TCAM operation, and *n* is the current number of entries on pipeline flow tables.

Packets coming back from the library for output action are sent to the OpenFlow queue provided by the module.
An OpenFlow switch provides limited QoS support employing a simple queuing mechanism, where each port can have one or more queues attached to it.
Packets sent to a specific queue are treated according to that queue's configuration.
Queue configuration takes place outside the OpenFlow protocol.
The ``OFSwitch13Queue`` abstract base class implements the queue interface, extending the |ns3| ``Queue<Packet>`` class to allow compatibility with the ``CsmaNetDevice`` used within ``OFSwitch13Port`` objects (``VirtualNetDevice`` does not use queues).
In this way, it is possible to replace the standard ``CsmaNetDevice::TxQueue`` attribute by this modified ``OFSwitch13Queue`` object.
Internally, it can hold a collection of N (possibly different) queues, each one identified by a unique ID ranging from 0 to N-1. Packets sent to the OpenFlow queue for transmission by the ``CsmaNetDevice`` are expected to carry the ``QueueTag``, which is used by the ``OFSwitch13Queue::Enqueue`` method to identify the internal queue that will hold the packet.
Specialized ``OFSwitch13Queue`` subclasses can perform different output scheduling algorithms by implementing the ``Peek``, ``Dequeue``, and ``Remove`` pure virtual methods from |ns3| ``Queue``.
The last two methods must call the ``NotifyDequeue`` and ``NotifyRemoved`` methods respectively, which are used by the ``OFSwitch13Queue`` to keep consistent statistics.

The OpenFlow port type queue can be configured by the ``OFSwitch13Port::QueueFactory`` attribute at construction time.
Currently, the ``OFSwitch13PriorityQueue`` is the only specialized OpenFlow queue available for use.
It implements the priority queuing discipline for a collection of N priority queues, identified by IDs ranging from 0 to N-1 with decreasing priority (queue ID 0 has the highest priority).
The output scheduling algorithm ensures that higher-priority queues are always served first.
The ``OFSwitch13PriorityQueue::QueueFactory`` and ``OFSwitch13PriorityQueue::NumQueues`` attributes can be used to configure the type and the number of internal priority queues, respectively.
By default, it creates a single ``DropTailQueue`` operating in packet mode with the maximum number of packets set to 100.

OpenFlow 1.3 Controller Application Interface
#############################################

The OpenFlow 1.3 controller application interface, namely ``OFSwitch13Controller``, provides the necessary functionalities for controller implementation.
It can handle a collection of OpenFlow switches, as illustrated in :ref:`fig-ofswitch13-controller` figure.
For constructing OpenFlow configuration messages and sending them to the switches, the controller interface relies on the ``dpctl`` utility provided by the |bofuss| library.
With a simple command-line syntax, this utility can be used to add flows to the pipeline, query for switch features and status, and change other configurations.

.. _fig-ofswitch13-controller:

.. figure:: figures/ofswitch13-controller.*
  :align: center

  The ``OFSwitch13Controller`` internal structure

For OpenFlow messages coming from the switches, the controller interface provides a collection of internal handlers to deal with the different types of messages.
Some handlers cannot be modified by derived class, as they must behave as already implemented. Other handlers can be overridden to implement the desired control logic.

The |ofs13| module brings the ``OFSwitch13LearningController`` class that implements the controller interface to work as a "learning bridge controller" (see 802.1D).
This learning controller instructs the OpenFlow switches to forward incoming unicast frames from one port to the single correct output port whenever possible (similar to the ``ns3::BridgeNetDevice``).

OpenFlow channel
################

The OpenFlow channel is the interface that connects switches to OpenFlow controllers.
Through this interface, the controller configures and manages the switch.
In the |ofs13| module, the controller interface can manage the switch devices remotely over a separate dedicated network (out-of-band controller connection).
It is possible to use standard |ns3| protocol stack, channels and devices to create the OpenFlow channel connections using a single shared channel or individual links between the controller interface and each switch device.
This model provides realistic control plane connections, including communication delay and, optionally, error models.
It also simplifies the OpenFlow protocol analysis, as the |ns3| tracing subsystem can be used for outputting PCAP files.

Considering that the OpenFlow messages traversing the OpenFlow channel follow the standard wire format, it is also possible to use the |ns3| ``TapBridge`` module to integrate an external OpenFlow controller, running on the local machine, to the simulated environment.

BOFUSS library integration
##########################

This module was designed to work together with a OpenFlow user-space software switch implementation.
The original `Basic OpenFlow User Space Software Switch (BOFUSS) project <https://github.com/CPqD/ofsoftswitch13>`_ (previously known as *ofsoftswitch13*) [Fernandes2020]_ was forked and modified for proper integration with |ns3|, resulting in the `BOFUSS library for OFSwitch13 <https://github.com/ljerezchaves/ofsoftswitch13>`_ library.
The ``master`` branch does not modify the original switch datapath implementation, which is currently maintained in the original repository and regularly synced to this one.
The modified ``ns3lib`` branch includes only the necessary files for building the |bofuss| library and integrating it with the |ofs13| module.

The |bofuss| library provides the complete OpenFlow switch datapath implementation, including input and output ports, the flow-table pipeline for packet matching, the group table, and the meter table.
It also provides support for converting internal messages to and from OpenFlow 1.3 wire format and delivers the ``dpctl`` utility for converting text commands into internal messages.

For proper |ofs13| integration, the library was modified to receive and send packets directly to the |ns3| environment.
To this, all library functions related to sending and receiving packets over ports were annotated as *weak symbols*, allowing the |ofs13| module to override them at link time.
This same strategy was used for overriding time-related functions, ensuring time consistency between the library and the simulator.
The integration also relies on *callbacks*, which are used by |bofuss| to notify the |ofs13| module about internal packet events, like packets dropped by meter bands, packet content modifications by pipeline instructions, packets cloned by group actions, and buffered packets sent to the controller.
As this integration involves callbacks and overridden functions, the module uses a global map to save pointers to all ``OFSwitch13Devices`` objects in the simulation, allowing faster object retrieve by datapath IP.

One potential performance drawback is the conversion between the |ns3| packet representation and the serialized packet buffer used by the library.
This problem is even more critical for empty packets, as |ns3| provides optimized internal representation for them.
To improve the performance, when a packet is sent to the library for pipeline processing, the module keeps track of its original |ns3| packet using the ``PipelinePacket`` structure.
For packets processed by the pipeline without content changes, the switch device forwards the original |ns3| packet to the specified output port.
In the face of content changes, the switch device creates a new |ns3| packet with the modified content (discarding the original packet, eventually copying all packet and byte tags [#f1]_ to the new one).
This approach is more expensive than the previous one but is far more simple than identifying which changes were made to the packet by the library.

.. [#f1] Note that the byte tags in the new packet will cover the entire packet, regardless of the byte range in the original packet.

Scope and Limitations
=====================

This module is intended for simulating OpenFlow networks, considering the main features available in OpenFlow version 1.3.
The module provides a complete OpenFlow switch device and the OpenFlow controller interface.
The switch is fully functional, while the controller interface is intended to allow users to write more sophisticated controllers to exploit the real benefits offered by SDN paradigm.
However, some features are not yet supported:

* **Auxiliary connections**: Only a single connection between each switch and controller is available.
  According to the OpenFlow specifications, auxiliary connections could be created by the switch to improve the switch processing performance and exploit the parallelism of most switch implementations.

* **OpenFlow channel encryption**: The switch and controller may communicate through a TLS connection to provide authentication and encryption of the connection.
  However, as there is no straightforward TLS support on |ns3|, the OpenFlow channel is implemented over a plain TCP connection, without encryption.

* **In-band control**: The OpenFlow controller manages the switches remotely over a separate dedicated network (out-of-band controller connection), as the switch port representing the switch's local networking stack and its management stack is not implemented.

* **Platform support**: This module is currently supported only for GNU/Linux platforms, as the code relies on an external library linked to the simulator that *must* be compiled with GCC.

|ns3| OpenFlow comparison
=========================

Note that the |ofs13| is not an extension of the available |ns3| OpenFlow module.
They share some design principles, like the use of an external software library linked to the simulator, the virtual TCAM, and the collection of ``CsmaNetDevices`` to work as OpenFlow ports.
However, this is an entirely new code and can be used to simulate a broad number of scenarios in comparison to the available implementation.

One difference between the |ns3| OpenFlow model and the |ofs13| is the introduction of the OpenFlow channel, using |ns3| devices and channels to provide the control connection between the controller and the switches.
It allows the user to collect PCAP traces for this control channel, simplifying the analysis of OpenFlow messages.
It is also possible the use of the |ns3| ``TapBridge`` module to integrate a local external OpenFlow 1.3 controller to the simulated environment.

In respect to the controller, this module provides a more flexible interface.
Instead of dealing with the internal library structures, the user can use simplified ``dpctl`` commands to build OpenFlow messages and send them to the switches.
However, for processing OpenFlow messages received by the controller, the user still need to understand internal library structures and functions to extract the desired information.

In respect to the OpenFlow protocol implementation, the |ofs13| module brings many improved features from version 1.3 in comparison to the available |ns3| model (version 0.8.9).
Some of the most important features are:

* **Multiple tables**: Prior versions of the OpenFlow specification did expose to the controller the abstraction of a single table.
  OpenFlow 1.1 introduces a more flexible pipeline with multiple tables.
  Packets are processed through the pipeline, they are matched and processed in the first table, and may be matched and processed in other subsequent tables.

* **Groups**: The new group abstraction enables OpenFlow to represent a set of ports as a single entity for forwarding packets.
  Different types of groups are provided to represent different abstractions such as multicasting or multipathing.
  Each group is composed of a set group buckets, and each group bucket contains the set of actions to be applied before forwarding to the port.
  Groups buckets can also forward to other groups.

* **Logical ports**: Prior versions of the OpenFlow specification assumed that all the ports of the OpenFlow switch were physical ports.
  This version of the specification adds support for logical ports, which can represent complex forwarding abstractions such as tunnels.
  In the |ofs13| module, logical ports are implemented with the help of ``VirtualNetDevice``, where the user can configure callbacks to handle packets properly.

* **Extensible match support**: Prior versions of the OpenFlow specification used a static fixed length structure to specify ``ofp_match``, which prevents flexible expression of matches and prevents inclusion of new match fields.
  The ``ofp_match`` has been changed to a TLV structure, called OpenFlow Extensible Match (OXM), which dramatically increases flexibility.

* **IPv6 support**: Basic support for IPv6 match and header rewrite has been added, via the OXM match support.

* **Per-flow meters**: Per-flow meters can be attached to flow entries and can measure and control the rate of packets.
  One of the primary applications of per-flow meters is to rate limit packets sent to the controller.

For |ns3| OpenFlow users who want to port existing code to this new module, please, check the :ref:`port-coding` section for detailed instructions.

|ns3| code compatibility
========================

The only required modification to the |ns3| source code for |ofs13| integration is the inclusion of the new OpenFlow receive callback in the ``CsmaNetDevice`` and ``VirtualNetDevice``.
The module brings the patch for including this receive callback into |ns3| source code, available under ``utils/`` directory.

The current |ofs13| stable version is 5.2.2.
This version is compatible with |ns3| versions 3.38 and 3.39, and will not compile with older |ns3| versions.
If you need to use another |ns3| release, you can check the RELEASE_NOTES file for previous |ofs13| releases and their |ns3| version compatibility, but keep in mind that old releases may have known bugs and an old API.
It is strongly recommended to use the latest module version.

References
==========
#. The reference [Chaves2016a]_ presents the |ofs13| module, including details about module design and implementation.
   A case study scenario is also used to illustrate some of the available OpenFlow 1.3 module features.

#. The reference [Fernandes2020]_ describes the design, implementation, evolution and the current state of the |bofuss| project.

#. The references [Chaves2015]_, [Chaves2016b]_, and [Chaves2017]_ are related to the integration between OpenFlow and LTE technologies.
   The |ns3| simulator, enhanced with the |ofs13| module, was used as the performance evaluation tool for these works.

.. [Chaves2015] Luciano J. Chaves, Vítor M. Eichemberger, Islene C. Garcia, and Edmundo R. M. Madeira.
   `"Integrating OpenFlow to LTE: some issues toward Software-Defined Mobile Networks" <https://doi.org/10.1109/NTMS.2015.7266498>`_.
   In: 7th IFIP International Conference on New Technologies, Mobility and Security (NTMS), 2015.

.. [Chaves2016a] Luciano J. Chaves, Islene C. Garcia, and Edmundo R. M. Madeira.
   `"OFSwitch13: Enhancing ns-3 with OpenFlow 1.3 support" <http://dx.doi.org/10.1145/2915371.2915381>`_.
   In: 8th Workshop on ns-3 (WNS3), 2016.

.. [Chaves2016b] Luciano J. Chaves, Islene C. Garcia, and Edmundo R. M. Madeira.
   `"OpenFlow-based Mechanisms for QoS in LTE Backhaul Networks" <https://doi.org/10.1109/ISCC.2016.7543905>`_.
   In: 21st IEEE Symposium on Computers and Communications (ISCC), 2016.

.. [Chaves2017] Luciano J. Chaves, Islene C. Garcia, and Edmundo R. M. Madeira.
   `"An adaptive mechanism for LTE P-GW virtualization using SDN and NFV" <https://doi.org/10.23919/CNSM.2017.8256000>`_.
   In: 13th International Conference on Network and Service Management (CNSM), 2017.

.. [Fernandes2020] Eder L. Fernandes, Elisa Rojas, Joaquin Alvarez-Horcajo, Zoltan L. Kis, Davide Sanvito, Nicola Bonelli, Carmelo Cascone, and Christian E. Rothenberg.
   `"The Road to BOFUSS: The Basic OpenFlow User-space Software Switch" <https://doi.org/10.1016/j.jnca.2020.102685>`_.
   Journal of Network and Computer Applications, 165:102685, 2020.
