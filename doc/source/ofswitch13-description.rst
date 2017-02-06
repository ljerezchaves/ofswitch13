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

The OpenFlow 1.3 module for |ns3|, aka ``OFSwitch13`` module, was designed to
enhance the `ns-3 Network Simulator <http://www.nsnam.org>`_ with
Software-Defined Networking (SDN) technology support. Despite the fact that the
|ns3| already has a module that supports simulations with OpenFlow switches,
it is possible to note that the available implementation provides a very
outdated OpenFlow protocol (version 0.8.9, from 2008). Many new major features
were introduced up to the latest version and we want to have them available for
use.

The ``OFSwitch13`` module provides support for OpenFlow protocol version 1.3,
bringing both a switch device and a controller application interface to the
|ns3| simulator, as depicted in Figure :ref:`fig-ofswitch13-module`, from
[Chaves2016]_. With this module, it is possible to interconnect |ns3| nodes to
send and receive traffic using the existing ``CsmaNetDevice`` or
``VirtualNetDevice``. To orchestrate the network, the controller application
interface can be extended to implement any desired control logic. The
communication between the controller and the switch is realized over standard
|ns3| protocol stack, devices and channels. The module also relies on the
external external `OpenFlow 1.3 Software Switch for ns-3
<https://github.com/ljerezchaves/ofsoftswitch13>`_ compiled as a library,
a.k.a. ``ofsoftswitch13`` library, that provides the switch datapath
implementation, the code for converting OpenFlow messages to and from wire
format, and the ``dpctl`` utility tool for configuring the switch from the
command line. The source code for the ``OFSwitch13`` module lives in the
directory ``src/ofswitch13``.

.. _fig-ofswitch13-module:

.. figure:: figures/ofswitch13-module.*
   :align: center

   The ``OFSwitch13`` module overview

Design
======

OpenFlow 1.3 Switch Device
##########################

The OpenFlow 1.3 switch device, namely ``OFSwitch13Device``, can be used to
interconnect |ns3| nodes using the existing network devices and channels.
Figure :ref:`fig-ofswitch13-netdevice` shows the internal switch device
structure. It takes a collection of ``OFSwtich13Port`` acting as input/output
ports, each one associated with a |ns3| underlying ``NetDevice``. In most
cases, the ``CsmaNetDevice`` is used to build the ports, which will act like
physical ports. However, it is possible to use a ``VirtualNetDevice`` to
implement logical ports. The switch device acts as the intermediary between the
ports, receiving a packet from one port and forwarding it to another. The
OpenFlow switch datapath implementation (flow tables, group table, and meter
table) is provided by the ``ofsoftswitch13`` library. For this reason, packets
entering the switch are sent to the library for OpenFlow pipeline processing
before being forwarded to the correct output port(s). OpenFlow messages
received from the controller are also sent to the library for datapath
configuration.

.. _fig-ofswitch13-netdevice:

.. figure:: figures/ofswitch13-switch.*
   :align: center

   The ``OFSwitch13Device`` internal structure

A packet enters the switch device through a new OpenFlow receive callback in
the ``NetDevice`` that is invoked for packets successfully received by the
device. This is a promiscuous receive callback, but in contrast to a
promiscuous protocol handler, the packet sent to this callback includes all
the headers, which are necessary by OpenFlow pipeline processing. This is the
only required modification to the |ns3| source code for ``OFSwitch13`` usage.

To model OpenFlow hardware operations, the module considers the concept of
*virtual TCAM* (Ternary Content-Addressable Memory) to estimate the average
flow table search time. This search time is used to postpone the pipeline
processing at the library. To provide a more realistic delay, the module
considers that real OpenFlow implementations use sophisticated search
algorithms for packet classification and matching. As most of these algorithms
are based on binary search trees, the following equation is used to estimate
the delay:

.. math::
  K * log_2 (n)

where *K* is the ``OFSwitch13Device::TcamDelay`` attribute set to the time for
a TCAM operation in a NetFPGA hardware, and *n* is the current number of
entries in the flow tables.

Packets coming back from the library for output action are sent to the
specialized ``OFSwitch13Queue`` provided by the module. An OpenFlow switch
provides limited QoS support by means of a simple queuing mechanism, where one
or more queues can attach to a port and be used to map flow entries on it.
Flow entries mapped to a specific queue will be treated according to that
queue's configuration. The ``OFSwitch13Queue`` class implements the common
queue interface, extending the ``Queue`` class to allow compatibility with
the ``CsmaNetDevice`` used within ``OFSwitch13Port`` objects (in the case of
``VirtualNetDevice`` the queue will not be used). In this way, it is possible
to replace the standard ``CsmaNetDevice::TxQueue`` attribute by this modified
``OFSwitch13Queue`` object. Figure :ref:`fig-ofswitch13-queue` shows its
internal structure. It can hold a collection of other queues, each one
identified by a unique ID. Packets sent to the OpenFlow queue for transmission
by the ``CsmaNetDevice`` are expected to carry the ``QueueTag``, which is
used to identify the internal queue that will hold the packet. Then, the output
scheduling algorithm decides from which queue to get packets during dequeue
procedures. Currently, only a priority scheduling algorithm is available for
use (with lowest priority id set to 0). By default, the maximum number of
queues allowed per port (8) are created at constructor, and can not be removed.
These queues are of the type ``DropTailQueue``, operating in packet mode with
maximum number of packets set to 1000.

.. _fig-ofswitch13-queue:

.. figure:: figures/ofswitch13-queue.*
  :align: center

  The ``OFSwitch13Queue`` internal structure

OpenFlow 1.3 Controller Application Interface
#############################################

The OpenFlow 1.3 controller application interface, namely
``OFSwitch13Controller``, provides the basic functionalities for controller
implementation. It can handle a collection of OpenFlow switches, as illustrated
in Figure :ref:`fig-ofswitch13-controller`. For constructing OpenFlow
configuration messages and sending them to the switches, the controller
interface relies on the ``dpctl`` utility provided by the ``ofsoftswitch13``
library. With a simple command-line syntax, this utility can be used to add
flows to the pipeline, query for switch features and status, and change other
configurations.

.. _fig-ofswitch13-controller:

.. figure:: figures/ofswitch13-controller.*
  :align: center

  The ``OFSwitch13Controller`` internal structure

For OpenFlow messages coming from the switches, the controller interface
provides a collection of internal handlers to deal with the different types of
messages. Some handlers can not be modified by derived class, as they must
behave as already implemented. Other handlers can be overridden to implement
the desired control logic.

The ``OFSwitch13`` module brings the ``OFSwitch13LearningController`` class
that implements the controller interface to work as a "learning bridge
controller" (see 802.1D). This learning controller instructs the OpenFlow
switches to forward incoming unicast frames from one port to the single correct
output port whenever possible (similar to the ``ns3::BridgeNetDevice``).

OpenFlow channel
################

The OpenFlow channel is the interface that connects each switch to an OpenFlow
controller. Through this interface, the controller configures and manages the
switch, receives events from the switch, and sends packets out the switch. In
the ``OFSwitch13`` module, the controller interface can manage the switch
devices remotely over a separate dedicated network (out-of-band controller
connection). It is possible to use standard |ns3| protocol stack, channels and
devices to create the OpenFlow channel connections using a single shared
channel or individual links between the controller interface and each switch
device. This model provides realistic control plane connections, including
communication delay and, optionally, error models. It also simplifies the
OpenFlow protocol analysis, as the |ns3| tracing subsystem can be used for
outputting PCAP files to be read by third-party software.

Considering that the OpenFlow messages traversing the OpenFlow channel follow
the standard wire format, it is also possible to use the |ns3| ``TapBridge``
module to integrate an external OpenFlow controller, running on the local
machine, to the simulated environment.

Library integration
###################

This module was designed to work together with the ``ofsoftswitch13``
user-space software switch implementation. The `original implementation
<https://github.com/CPqD/ofsoftswitch13>`_ was forked and slightly modified,
resulting in the `OpenFlow 1.3 Software Switch for ns-3
<https://github.com/ljerezchaves/ofsoftswitch13>`_ library. The code does not
modify the original switch datapath implementation, which is currently
maintained in the original repository and regularly synced to the modified
one. The ``ns3lib`` branch includes some callbacks, compiler directives and
minor changes in structure declarations to allow the integration between the
module and the |ns3|.

Figure :ref:`fig-ofswitch13-library`, adapted from [Fernandes2014]_, shows the
library architecture and highlights the |ns3| integration points. The library
provides the complete OpenFlow switch datapath implementation, including input
and output ports, the flow-table pipeline for packet matching, the group table,
and the meter table. It also provides the ``OFLib`` library that is used for
converting internal messages to and from OpenFlow 1.3 wire format, and the
``dpctl`` utility for converting text commands into internal messages. The
``NetBee`` library is used for packet decoding and parsing, based on the
*NetPDL* XML-based language for packet header description [Risso2006]_.

.. _fig-ofswitch13-library:

.. figure:: figures/ofswitch13-library.*
   :align: center

   |ns3| integration to the OpenFlow 1.3 software switch architecture

For proper |ns3| integration, the switch ports were set aside, and the library
was modified to receive and send packets directly to the |ns3| environment. To
accomplish this task, all library functions related to sending and receiving
packets over ports were annotated as *weak symbols*, allowing the module to
override them at link time. This same strategy was used for overriding
time-related functions, ensuring time consistency between the library and the
simulator. The integration also relies on callbacks, which are used by the
library to notify the module about internal packet events, like packets dropped
by meter bands, packet content modifications by pipeline instructions, packets
cloned by group actions, and buffered packets sent to the controller. As this
integration involves callbacks and overridden functions, and considering that
the library code is written in C, the module uses a global map to save pointers
to all ``OFSwitch13Devices`` objects in the simulation, allowing faster
object retrieve by datapath IP.

One potential performance drawback is the conversion between the |ns3| packet
representation and the serialized packet buffer used by the library. This is
even more critical for empty packets, as |ns3| provides optimized internal
representation for them. To improve the performance, when a packet is sent to
the library for pipeline processing, the module keeps track of its original
|ns3| packet using the ``PipelinePacket`` structure. For packets processed by
the pipeline without content changes, the switch device forwards the original
|ns3| packet to the specified output port. In the face of content changes, the
switch device creates a new |ns3| packet with the modified content (eventually
copying all packet and byte tags from the original packet to the new one). This
approach is more expensive than the previous one but is far more simple
than identifying which changes were performed in the packet by the library to
modify the original |ns3| packets. *Note that in the case of byte tags, the
tags in the new packet will cover the entire packet, regardless of the byte
range in the original packet.*

Scope and Limitations
=====================

This module is intended for simulating OpenFlow networks, considering the main
features available in OpenFlow version 1.3. The module provides a complete
OpenFlow switch device, and the OpenFlow controller interface. The switch is
fully functional, while the controller interface is intended to allow users to
write more sophisticated controllers to exploit the real benefits offered by
SDN paradigm. However, some features are not yet supported:

* **Auxiliary connections**: Only a single connection between each switch and
  controller is available. According to the OpenFlow specifications, auxiliary
  connections could be created by the switch and are helpful to improve the
  switch processing performance and exploit the parallelism of most switch
  implementations.

* **OpenFlow channel encryption**: The switch and controller may communicate
  through a TLS connection to provide authentication and encryption of the
  connection. However, as there is no straightforward TLS support on *ns-3*,
  the OpenFlow channel is implemented over a plain TCP connection, without
  encryption.

* **In-band control**: The OpenFlow controller manages the switches remotely
  over a separate dedicated network (out-of-band controller connection), as the
  switch port representing the switch's local networking stack and its
  management stack is not implemented.

* **Platform support**: This module is currently supported only for GNU/Linux
  platforms, as the code relies on an external library linked to the simulator
  that *must* be compiled with GCC.

|ns3| OpenFlow comparison
=========================

Note that the ``OFSwitch13`` is not an extension of the available |ns3|
OpenFlow module. They share some design principles, like the use of an external
software library linked to the simulator, the virtual TCAM, and the collection
of ``CsmaNetDevices`` to work as OpenFlow ports. However, this is a complete
new code, and can be used to simulate a larger number of scenarios in
comparison to the available implementation.

One difference between the |ns3| OpenFlow model and the ``OFSwitch13`` is the
introduction of the OpenFlow channel, using |ns3| devices and channels to
provide the control connection between the controller and the switches. It
allows the user to collect PCAP traces for this control channel, simplifying
the analysis of OpenFlow messages. It is also possible the use of the |ns3|
``TapBridge`` module to integrate a local external OpenFlow 1.3 controller to
the simulated environment.

In respect to the controller, this module provides a more flexible interface.
Instead of dealing with the internal library structures, the user can use
simplified ``dpctl`` commands to build OpenFlow messages and send them to the
switches. Only for processing OpenFlow messages received by the controller
from the switches that will be necessary to handle internal library structures
and functions to extract the desired information.

In respect to the OpenFlow protocol implementation, the ``OFSwitch13`` module
brings a number of improved features from version 1.3 in comparison to the
available |ns3| model (version 0.8.9). Some of the most important features
are:

* **Multiple tables**: Prior versions of the OpenFlow specification did expose
  to the controller the abstraction of a single table. OpenFlow 1.1 introduces
  a more flexible pipeline with multiple tables. Packets are processed through
  the pipeline, they are matched and processed in the first table, and may be
  matched and processed in other subsequent tables.

* **Groups**: The new group abstraction enables OpenFlow to represent a set of
  ports as a single entity for forwarding packets. Different types of groups
  are provided to represent different abstractions such as multicasting or
  multipathing. Each group is composed of a set group buckets, each group
  bucket contains the set of actions to be applied before forwarding to the
  port. Groups buckets can also forward to other groups.

* **Logical ports**: Prior versions of the OpenFlow specification assumed that
  all the ports of the OpenFlow switch were physical ports. This version of the
  specification adds support for logical ports, which can represent complex
  forwarding abstractions such as tunnels. In the ``OFSwitch13`` module,
  logical ports are implemented with the help of ``VirtualNetDevice`` withing
  the ``OFSwitch13Port``, where the user can configure callbacks to handle
  packets in a proper way.

* **Extensible match support**: Prior versions of the OpenFlow specification
  used a static fixed length structure to specify ``ofp_match``, which prevents
  flexible expression of matches and prevents inclusion of new match fields.
  The ``ofp_match`` has been changed to a TLV structure, called OpenFlow
  Extensible Match (OXM), which dramatically increases flexibility.

* **IPv6 support**: Basic support for IPv6 match and header rewrite has been
  added, via the OXM match support.

* **Per flow meters**: Per-flow meters can be attached to flow entries and can
  measure and control the rate of packets. One of the main applications of
  per-flow meters is to rate limit packets sent to the controller.

For |ns3| OpenFlow users who want to port existing code to this new module,
please, check the :ref:`port-coding` section for detailed instructions.

|ns3| code compatibility
========================

The only required modification to the |ns3| source code for ``OFSwitch13``
integration is the inclusion of the new OpenFlow receive callback in the
``CsmaNetDevice`` and ``VirtualNetDevice``. The module brings the patch for
including this receive callback into |ns3| source code, available under
``src/ofswitch13/utils`` directory.  Note the existence of a *src* patch for
the receive callbacks inclusion, and an optional *doc* patch that can be used
for including the ``OFSwitch13`` when compiling Doxygen and Sphinx
documentation. For older versions, users can apply the *src* patch and, if
necessary, manually resolve the conflicts.

Current ``OFSwitch13`` stable version have been tested with |ns3| versions 3.26
and greater. For older |ns3| releases, it is possible to use ``OFSwitch13``
versions 2.0.x. It is strongly recommended to use the latest module version for
better results.

References
==========

#. The reference [Fernandes2014]_ (in Portuguese) describes the details on the
   ``ofsoftswitch13`` software switch implementation.

#. The reference [Chaves2016]_ presents the ``OFSwitch13`` module, including
   details about module design and implementation. A case study scenario is
   also used to illustrate some of the available OpenFlow 1.3 module
   features.

#. The reference [Chaves2015]_ is related to the integration between OpenFlow
   and LTE technologies. The |ns3| simulator, enhanced with the ``OFSwitch13``
   module, is used as the performance evaluation tool. This is the first
   published work including simulation results obtained with the ``OFSwitch13``
   module.

.. [Fernandes2014] Eder. L. Fernandes, and Christian E. Rothenberg. `"OpenFlow 1.3 Software Switch"
   <https://dl.dropboxusercontent.com/u/15183439/pubs/sbrc14-ferramentas-ofsoftswitch13.pdf>`_.
   In: Salão de Ferramentas do XXXII Simpósio Brasileiro de Redes de Computadores (SBRC), 2014.

.. [Risso2006] Fulvio Risso and Mario Baldi. `"Netpdl: An extensible xml-based language
   for packet header description" <http://dx.doi.org/10.1016/j.comnet.2005.05.029>`_.
   Computer Networks, 50(5):688–706, 2006.

.. [Qi2010] Yaxuan Qi, Jeffrey Fong, Weirong Jiang, Bo Xu, Jun Li, and Viktor Prasanna.
   `"Multi-dimensional Packet Classification on FPGA: 100 Gbps and Beyond"
   <http://dx.doi.org/10.1109/FPT.2010.5681492>`_.
   In: IEEE International Conference on Field-Programmable Technology (FPT), 2010.

.. [Chaves2016] Luciano J. Chaves, Islene C. Garcia, and Edmundo R. M. Madeira.
   `"OFSwitch13: Enhancing ns-3 with OpenFlow 1.3 support"
   <http://www.lrc.ic.unicamp.br/~luciano/publications/wns316.pdf>`_.
   To appear in: 8th Workshop on ns-3 (WNS3), 2016.

.. [Chaves2015] Luciano J. Chaves, Vítor M. Eichemberger, Islene C. Garcia, and Edmundo R. M. Madeira.
   `"Integrating OpenFlow to LTE: some issues toward Software-Defined Mobile Networks"
   <http://ieeexplore.ieee.org/xpl/articleDetails.jsp?reload=true&arnumber=7266498>`_.
   In: 7th IFIP International Conference on New Technologies, Mobility and Security (NTMS), 2015.
