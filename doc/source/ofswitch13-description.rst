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
  port whenever possible (see ``ns3::BridgeNetDevice``). 

* The **OpenFlow 1.3 Switch device**, namely ``OFSwitch13NetDevice``, can be
  used to interconnect |ns3| nodes over standard devices and channels. The
  ``OFSwitch13NetDevice`` takes a collection of OpenFlow Ports
  (``OFSwtich13Port``), which are used to interconnect the
  ``OFSwitch13NetDevice`` to the |ns3| underlying ``CsmaNetDevice``, as
  indicated in the :ref:`fig-ofswitch13-netdevice`. The ``OFSwitch13NetDevice``
  acts as the intermediary between the ports, receiving a packet from one port
  and forwarding it to another. Input packets are sent to the
  ``ofsoftswitch13`` library for internal OpenFlow pipeline processing before
  being forwarded to the correct output port(s). OpenFlow messages received
  from the ``OFSwitch13Controller`` are also sent to the library for internal
  pipeline configuration. 

.. _fig-ofswitch13-netdevice:

.. figure:: figures/ofswitch13-netdevice.*
   :align: center

   The ``OFSwitch13NetDevice`` structure

Library integration
###################
This module was designed to work together with the CPqD ofsoftswitch13
user-space software switch implementation, originally available at
https://github.com/CPqD/ofsoftswitch13. This user-space switch is based on the
Ericsson TrafficLab 1.1 softswitch implementation, with changes in the
forwarding plane to support OpenFlow 1.3.

In fact, this module provides an interface for interconnecting the |ns3|
OFSwitch13NetDevice to the ofsoftswitch13 datapath. Also, it interconnects the
OFSwitch13Controller to the dpctl utility, in order to simplify the process of
sending OpenFlow messages to the switch. To this end, the ofsoftswitch13
project must be compiled as a static library and get proper linked with |ns3|
simulator.

.. _fig-ofsoftswitch13-library:

.. figure:: figures/ofsoftswitch13-library.*
   :align: center

   The |ns3| integration to the OpenFlow 1.3 software switch architecture




Following the same strategy on the |ns3| ``OpenFlow module``, ...

Virtual Flow Table, TCAM: Typical OF-enabled switches are implemented on a
hardware TCAM. The OFSID we turn into a library includes a modelled software
TCAM, that produces the same results as a hardware TCAM. We include an
attribute FlowTableLookupDelay, which allows a simple delay of using the TCAM
to be modelled. We don’t endeavor to make this delay more complicated, based on
the tasks we are running on the TCAM, that is a possible future improvement.
The OpenFlowSwitch network device is aimed to model an OpenFlow switch, with a
TCAM and a connection to a controller program. With some tweaking, it can model
every switch type, per OpenFlow’s extensibility. It outsources the complexity
of the switch ports to NetDevices of the user’s choosing. It should be noted
that these NetDevices must behave like practical switch ports, i.e. a Mac
Address is assigned, and nothing more. It also must support a SendFrom function
so that the OpenFlowSwitch can forward across that port.



Structure to save packet metadata while it is under OpenFlow pipeline.

This structure keeps track of packets under OpenFlow pipeline, including the ID for each packet copy (notified by the clone callback). Note that only one packet can be in pipeline at a time, but the packet can have multiple internal copies (which one will receive an unique packet ID), and can also be saved into buffer for later usage.


OpenFlow channel
################

The OpenFlow channel is the interface that connects each OpenFlow switch to an
OpenFlow controller. Through this interface, the controller configures and
manages the switch, receives events from the switch, and sends packets out the
switch. In this module, the OpenFlow controller manages the OpenFlow switches
remotely over a separate dedicated network (out-of-band controller connection).

The ``OFSwitch13Helper`` can create an OpenFlow channel using a single shared
``CsmaChannel``, interconnecting the controller to all switches. It is also
possible to create individual connections between the controller and each
switch, using either CSMA or point-to-point links. Using standard |ns3|
channels and devices, it is possible to provide realistic connections with
delay and error models.

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
``OFSwitch13Queue`` object, as indicated in the
:ref:`fig-ofswitch13-netdevice`. Internally, the ``OFSwitch13Queue`` can hold a
collection of ``ns3::Queue`` objects, identified by an unique id. Packets sent
to the ``OFSwitch13Queue`` are expected to carry the ``ns3::QueueTag``, which
is used to identify which internal queue will hold the packet. The internal
scheduling algorithms decides from which queue get the packets during dequeue
procedures (currently, only a priority queue scheduling is available). A
default internal ``DropTailQueue`` object with id 0 is created at constructor,
and can not be removed.


Scope and Limitations
=====================

What can the model do?  What can it not do?  Please use this section to
describe the scope and limitations of the model.

problem with byte tags.

problem packet print?


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
   published work including simulationm results obtained with the
   ``OFSwitch13`` module.

.. [Fernandes2014]  Eder. L. Fernandes, Christian E. Rothenberg. `"OpenFlow 1.3 Software Switch"
   <https://dl.dropboxusercontent.com/u/15183439/pubs/sbrc14-ferramentas-ofsoftswitch13.pdf>`_.
   In: Salão de Ferramentas do XXXII Simpósio Brasileiro de Redes de Computadores, 2014.

.. [Chaves2015] Luciano J. Chaves, Vítor M. Eichemberger, Islene C. Garcia, and Edmundo R. M. Madeira. 
   `"Integrating OpenFlow to LTE: some issues toward Software-Defined Mobile Networks" 
   <http://ieeexplore.ieee.org/xpl/articleDetails.jsp?reload=true&arnumber=7266498>`_. 
   In: 7th IFIP International Conference on New Technologies, Mobility and Security, 2015.




