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
|ns3| already has a module that supports simulations with OpenFlow switches, it
is possible to note that the available implementation provides a very outdated
OpenFlow protocol (version 0.8.9, from 2008). Many new major features were
introduced up to the latest version and we want to have them available for use.
Thus, the available OpenFlow module does not seem an attractive option when it
comes to cutting-edge research.

To overcome these shortcomings, the ``OFSwitch13`` module interconnects the
|ns3| simulator to the external `OpenFlow 1.3 Software Switch for ns-3
<https://github.com/ljerezchaves/ofsoftswitch13>`_  library, aka
``ofsoftswitch13`` library, to create both an OpenFlow 1.3 switch device and an
OpenFlow 1.3 controller interface. The ``ofsoftswitch13`` library provides an
OpenFlow 1.3 compatible user-space software switch implementation, the code for
converting to and from OpenFlow 1.3 wire format, and the ``dpctl`` tool for
configuring the switch from the console.

With this module it is possible to interconnect simulated |ns3| nodes to send
and receive traffic using the existing |ns3| CSMA devices and channels. To
orchestrate the network, the OpenFlow controller interface provides a
straightforward way to send OpenFlow messages to the switches, using ``dpctl``
command strings with a simple syntax. The controller can be extended to
implement any desired feature, such as those necessary to control a complex
SDN-based network.

The source code for the ``OFSwitch13`` module lives in the directory
``src/ofswitch13``.

Design
======

Figure :ref:`fig-ofswitch13-module` shows the module overview, which brings
both an OpenFlow 1.3 switch device and an OpenFlow 1.3 controller interface.

.. _fig-ofswitch13-module:

.. figure:: figures/ofswitch13-module.*
   :align: center

   Overview of the ``OFSwitch13`` module

* The **OpenFlow 1.3 Controller interface**, namely ``OFSwitch13Controller``,
  can handle a collection of OpenFlow switches. It provides a simplified
  mechanism for |ns3| uses to configure OpenFlow switches using ``dpctl``
  commands over the ``DpctlCommand()`` function. These commands are converted
  to OpenFlow messages by the ``ofsoftswitch13`` library and are sent to the
  switches over the OpenFlow channel(s). This ``OFSwitch13Controller`` *must be
  extended* by |ns3| uses to implement the desired control logic. The module
  also brings an ``OFSwitch13LearningController`` that implements the logic for
  a "learning bridge" algorithm (see 802.1D), instructing OpenFlow switches to
  forward incoming unicast frames from one port to the single correct output
  port whenever possible (similar to the ``ns3::BridgeNetDevice``).

* The **OpenFlow 1.3 Switch device**, namely ``OFSwitch13NetDevice``, can be
  used to interconnect |ns3| nodes over standard devices and channels. The
  ``OFSwitch13NetDevice`` takes a collection of OpenFlow ports, namely
  ``OFSwtich13Port``, which are used to interconnect the
  ``OFSwitch13NetDevice`` to the |ns3| underlying ``CsmaNetDevice``, as
  indicated in Figure :ref:`fig-ofswitch13-netdevice`. The
  ``OFSwitch13NetDevice`` acts as the intermediary between the ports, receiving
  a packet from one port and forwarding it to another. Input packets are sent
  to the ``ofsoftswitch13`` library for internal OpenFlow pipeline processing
  before being forwarded to the correct output port(s). OpenFlow messages
  received from the ``OFSwitch13Controller`` are also sent to the library for
  internal datapath configuration.

  This module depends on a new ``OpenFlowRx`` trace source in the
  ``CsmaNetDevice``. This trace source is fired for packets successfully
  received by the ``CsmaNetDevice`` immediately before being forwarded up to
  higher layers. This is a promiscuous trace, but in contrast to a promiscuous
  protocol handler, the packet sent to this trace source also includes the
  Ethernet header, which is necessary by OpenFlow pipeline processing. This new
  trace source is the only required modification to the |ns3| source code for
  ``OFSwitch13`` usage.

.. _fig-ofswitch13-netdevice:

.. figure:: figures/ofswitch13-netdevice.*
   :align: center

   The ``OFSwitch13NetDevice`` port collection

Library integration
###################

This module was designed to work together with the ``ofsoftswitch13``
user-space software switch implementation. The `original implementation
<https://github.com/CPqD/ofsoftswitch13>`_ was forked and slightly modified,
resulting in the `OpenFlow 1.3 Software Switch for ns-3
<https://github.com/ljerezchaves/ofsoftswitch13>`_ library. The code does not
modify the original switch datapath implementation, which is currently
maintained in the original repository and regularly synced to the modified one.
The ``ns3lib`` branch includes some callbacks, compiler directives and minor
changes in structure declarations to allow integration with the ``OFSwitch13``
module for the |ns3|.

Figure :ref:`fig-ofsoftswitch13-library`, adapted from [Fernandes2014]_, shows
the library architecture and highlights the |ns3| integration points. The
library provides the complete OpenFlow switch datapath, including the
input/output ports, the ``NetBee`` parser and link that uses the *NetPDL*
xml-based language for packet header description [Risso2006]_, the flow-table
pipeline for matching, the group table, and the meter table. On the controller
side, the ``dpctl`` utility is also available for converting text commands to
OpenFlow messages. The library also provides the ``OFLib``, used for
converting OpenFlow messages to and from OpenFlow 1.3 wire format.

.. _fig-ofsoftswitch13-library:

.. figure:: figures/ofsoftswitch13-library.*
   :align: center

   |ns3| integration to the OpenFlow 1.3 software switch architecture

For proper |ns3| integration, the ``ofsoftswitch13`` ports and the control
channel port were set aside, and the code was modified to receive and send
packets directly to the |ns3| environment. To this, the ``ofsoftswitch13``
functions related to sending and receiving packets were marked as *weak*, so
this module can override them in order to integrate the library with the
simulated environment. This same *weak* strategy is used for overriding
time-related functions, ensuring time consistency between the library and the
simulator.

The module relies heavily on callbacks, which are used by the library to notify
the simulator about internal events like packet drop by meter band, packet
modifications by pipeline instructions, packet cloned by group actions, and
buffered packets sent to controller. As this integration involves callbacks and
overridden functions, and considering that the library code is written in C,
the module uses a global map to save pointers to all ``OFSwitch13NetDevices``
objects in the simulation, allowing faster object retrieve by datapath id.

Packet conversion
#################

One of the major performance drawbacks of this module is the packet conversion
between the internal ``ns3::Packet`` representation and the serialized packet
representation in the library (see ``ns3::OFSwitch13Interface`` class for
conversion functions). This becomes even worse when the packet content is
empty, as |ns3| provides optimized internal representation of empty packets.

To improve the performance, when a packet is sent to the OpenFlow pipeline for
library processing, the module keep track of its original ``ns3::Packet`` using
the ``PipelinePacket`` structure. When the packet is processed by the pipeline
with no content changes, the module forwards the original ``ns3::Packet`` to
the specified output port. When the packet content is changed in the pipeline,
the module creates a new ``ns3::Packet`` with the modified content and copy all
packet and byte tags from the original packet to the new one. This approach is
more expensive than the previous one, but is far more simple than identifying
which changes were performed in the packet by the library to modify the
original ``ns3::Packet``. *Note that in the case of byte tags, the tags in the
new packet will cover the entire packet, regardless of the byte range in
original packet.*

Multiple output queues
######################

An OpenFlow switch provides limited Quality-of-Service support through a simple
queuing mechanism. One or more queues can attach to a port and be used to map
flow entries on it. Flow entries mapped to a specific queue will be treated
according to that queue's configuration (e.g. min rate). Note that queue
configuration takes place outside the OpenFlow protocol.

The ``OFSwitch13Queue`` class implements a common queue interface, extending
the ``ns3::Queue`` class to allow compatibility with the ``CsmaNetDevice`` used
in ``OFSwitch13Port`` objects. In this way, it is possible to replace the
standard ``CsmaNetDevice::TxQueue`` attribute by this modified
``OFSwitch13Queue`` object. Internally, the ``OFSwitch13Queue`` can hold a
collection of ``ns3::Queue`` objects, identified by an unique id. Packets sent
to the ``OFSwitch13Queue`` are expected to carry the ``ns3::QueueTag``, which
is used to identify which internal queue will hold the packet. The internal
scheduling algorithms decides from which queue get the packets during dequeue
procedures (currently, only a priority queue scheduling is available).  Figure
:ref:`fig-ofswitch13-queue` shows this architecture. A default internal
``DropTailQueue`` object with id 0 is created at constructor, and can not be
removed.

.. _fig-ofswitch13-queue:

.. figure:: figures/ofswitch13-queue.*
  :align: center

  The ``OFSwitch13Queue`` internal structure

Virtual TCAM
############

This module uses the concept of Virtual TCAM (Ternary Content-Addressable
Memory) flow table to model OpenFlow hardware. To provide a more realistic
switch model, specially with respect to flow table search time, this module
considers that in real OpenFlow implementations, packet classification can use
sophisticated search algorithms, such as the HyperSplit [Qi2010]_. As most of
theses algorithms classifies the packet based on binary search trees, this
module estimates the pipeline average time to:

.. math::
  K * log_2 (n)

where *K* is the ``ns3::OFSwitch13NetDevice::TCAMDelay`` attribute set to the
time for a TCAM operation in a NetFPGA hardware, and *n* is the current number
of entries in the flow tables.

OpenFlow channel
################

The OpenFlow channel is the interface that connects each OpenFlow switch to an
OpenFlow controller. Through this interface, the controller configures and
manages the switch, receives events from the switch, and sends packets out the
switch. In this module, the OpenFlow controller manages the OpenFlow switches
remotely over a separate dedicated network (out-of-band controller connection).

|ns3| users can create an OpenFlow channel using a single shared channel,
interconnecting the controller to all switches. It is also possible to create
individual connections between the controller and each switch, using dedicated
links. Using standard |ns3| channels and devices, it is possible to provide
realistic connections with delay and error models.

Scope and Limitations
=====================

This module is intended for simulating OpenFlow networks, considering the main
features available in OpenFlow version 1.3. The module provides a complete
OpenFlow switch device, and a simple OpenFlow learning controller. The switch
is fully functional, while the learning controller is intended to allow basic
usage and examples. However, users can write more sophisticated controllers,
exploiting the real benefits offered by SDN paradigm.

Some OpenFlow 1.3 features are not yet supported by this module:

* **Auxiliary connections**: In the current implementation, only a single
  (main) connection between the switch and the controller is available.
  According to the OpenFlow specifications, auxiliary connections can created
  by the OpenFlow switch and are helpful to improve the switch processing
  performance and exploit the parallelism of most switch implementations.

* **Multiple controllers**: In the current implementation, each switch can only
  be managed by a single controller.  According to the OpenFlow specifications,
  having multiple controllers improves reliability, as the switch can continue
  to operate in OpenFlow mode if one controller or controller connection fails.

* **OpenFlow channel encryption**: The default security mechanism of the
  OpenFlow protocol is TLS (Transport Layer Security). The switch and
  controller may communicate through a TLS connection to provide authentication
  and encryption of the connection. However, as there is no straightforward TSL
  support on |ns3|, the OpenFlow channel is implemented over a plain TCP
  connection, without encryption.

* **In-band control**:  In the current implementation, the OpenFlow controller
  manages the OpenFlow switches remotely over a separate dedicated network
  (out-of-band controller connection), as the LOCAL switch port, representing
  the switch’s local networking stack and its management stack, is not
  implemented.

References
==========

#. The reference [Fernandes2014]_ (in portuguese) describes the details on the
   ``ofsoftswitch13`` software switch implementation.

#. The reference [Chaves2015]_  is related to the integration between OpenFlow
   and LTE technologies. The |ns3| simulator, enhanced with the ``OFSwitch13``
   module, is used as the performance evaluation tool. This is the first
   published work including simulation results obtained with the ``OFSwitch13``
   module.

.. [Fernandes2014]  Eder. L. Fernandes, and Christian E. Rothenberg. `"OpenFlow 1.3 Software Switch"
   <https://dl.dropboxusercontent.com/u/15183439/pubs/sbrc14-ferramentas-ofsoftswitch13.pdf>`_.
   In: Salão de Ferramentas do XXXII Simpósio Brasileiro de Redes de Computadores (SBRC), 2014.

.. [Risso2006] Fulvio Risso and Mario Baldi. `"Netpdl: An extensible xml-based language
   for packet header description" <http://dx.doi.org/10.1016/j.comnet.2005.05.029>`_.
   Computer Networks, 50(5):688–706, 2006.

.. [Qi2010] Yaxuan Qi, Jeffrey Fong, Weirong Jiang, Bo Xu, Jun Li, and Viktor Prasanna.
   `"Multi-dimensional Packet Classification on FPGA: 100 Gbps and Beyond"
   <http://dx.doi.org/10.1109/FPT.2010.5681492>`_.
   In: IEEE International Conference on Field-Programmable Technology (FPT), 2010.

.. [Chaves2015] Luciano J. Chaves, Vítor M. Eichemberger, Islene C. Garcia, and Edmundo R. M. Madeira.
   `"Integrating OpenFlow to LTE: some issues toward Software-Defined Mobile Networks"
   <http://ieeexplore.ieee.org/xpl/articleDetails.jsp?reload=true&arnumber=7266498>`_.
   In: 7th IFIP International Conference on New Technologies, Mobility and Security (NTMS), 2015.

