Module Description
******************

Overview
========

The OpenFlow 1.3 module for *ns-3*, aka ``OFSwitch13`` module, was designed to
enhance the `ns-3 Network Simulator <http://www.nsnam.org>`_ with
Software-Defined Networking (SDN) technology support. Despite the fact that the
*ns-3* already has a module that supports simulations with OpenFlow switches,
it is possible to note that the available implementation provides a very
outdated OpenFlow protocol (version 0.8.9, from 2008). Many new major features
were introduced up to the latest version and we want to have them available for
use. Thus, the available OpenFlow module does not seem an attractive option
when it comes to cutting-edge research.

To overcome these shortcomings, the ``OFSwitch13`` module interconnects the
*ns-3* simulator to the external `OpenFlow 1.3 Software Switch for ns-3
<https://github.com/ljerezchaves/ofsoftswitch13>`_  library, aka
``ofsoftswitch13`` library, to create both an OpenFlow 1.3 switch device and an
OpenFlow 1.3 controller interface. The ``ofsoftswitch13`` library provides an
OpenFlow 1.3 compatible user-space software switch implementation, the code for
converting to and from OpenFlow 1.3 wire format, and the ``dpctl`` tool for
configuring the switch from the console.

With this module it is possible to interconnect simulated *ns-3* nodes to send
and receive traffic using the existing *ns-3* CSMA devices and channels. To
orchestrate the network, the OpenFlow controller interface provides a
straightforward way to send OpenFlow messages to the switches, using ``dpctl``
command strings with a simple syntax. The controller can be extended to
implement any desired feature, such as those necessary to control a complex
SDN-based network.


Design
======

Briefly describe the software design of the model and how it fits into 
the existing *ns-3* architecture. 

.. figure:: figures/module.*
   :align: center

   Overview of the OFSwitch13 modele



This module was designed to work together with the CPqD ofsoftswitch13 user-space software switch implementation, originally available at https://github.com/CPqD/ofsoftswitch13. This user-space switch is based on the Ericsson TrafficLab 1.1 softswitch implementation, with changes in the forwarding plane to support OpenFlow 1.3.

In fact, this module provides an interface for interconnecting the ns-3 OFSwitch13NetDevice to the ofsoftswitch13 datapath. Also, it interconnects the OFSwitch13Controller to the dpctl utility, in order to simplify the process of sending OpenFlow messages to the switch. To this end, the ofsoftswitch13 project must be compiled as a static library and get proper linked with ns-3 simulator.



Scope and Limitations
=====================

What can the model do?  What can it not do?  Please use this section to
describe the scope and limitations of the model.

References
==========

.. [ofSwitch13] E. L. Fernandes, C. E. Rothenberg, OpenFlow 1.3 Software Switch. https://dl.dropboxusercontent.com/u/15183439/pubs/sbrc14-ferramentas-ofsoftswitch13.pdf

*OBS:* This article is only available in portuguese, and it describes the external openflow library (wich were used as reference to implement the openflow) without any relation with the integration between this library (the ns-3 *ofSwitch13* module) and the ns-3 simulator.

