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

The OpenFlow 1.3 module for |ns3|, aka ``OFSwitch13`` module, was designed to enhance the `ns-3 Network Simulator <http://www.nsnam.org>`_ with Software-Defined Networking (SDN) technology support. Despite the fact that the |ns3| already has a module that supports simulations with OpenFlow switches, it is possible to note that the available implementation provides a very outdated OpenFlow protocol (version 0.8.9, from 2008). Many new major features were introduced up to the latest version and we want to have them available for use. Thus, the available OpenFlow module does not seem an attractive option when it comes to cutting-edge research.

To overcome these shortcomings, the ``OFSwitch13`` module interconnects the |ns3| simulator to the external `OpenFlow 1.3 Software Switch for ns-3 <https://github.com/ljerezchaves/ofsoftswitch13>`_  library, aka ``ofsoftswitch13`` library, to create both an OpenFlow 1.3 switch device and an OpenFlow 1.3 controller interface. The ``ofsoftswitch13`` library provides an OpenFlow 1.3 compatible user-space software switch implementation, the code for converting to and from OpenFlow 1.3 wire format, and the ``dpctl`` tool for configuring the switch from the console.

With this module it is possible to interconnect simulated |ns3| nodes to send and receive traffic using the existing |ns3| CSMA devices and channels. To orchestrate the network, the OpenFlow controller interface provides a straightforward way to send OpenFlow messages to the switches, using ``dpctl`` command strings with a simple syntax. The controller can be extended to implement any desired feature, such as those necessary to control a complex SDN-based network.


Design
======

Briefly describe the software design of the model and how it fits into 
the existing |ns3| architecture. 

.. figure:: figures/module.*
   :align: center

   Overview of the OFSwitch13 modele



This module was designed to work together with the CPqD ofsoftswitch13 user-space software switch implementation, originally available at https://github.com/CPqD/ofsoftswitch13. This user-space switch is based on the Ericsson TrafficLab 1.1 softswitch implementation, with changes in the forwarding plane to support OpenFlow 1.3.

In fact, this module provides an interface for interconnecting the |ns3| OFSwitch13NetDevice to the ofsoftswitch13 datapath. Also, it interconnects the OFSwitch13Controller to the dpctl utility, in order to simplify the process of sending OpenFlow messages to the switch. To this end, the ofsoftswitch13 project must be compiled as a static library and get proper linked with |ns3| simulator.



Scope and Limitations
=====================

What can the model do?  What can it not do?  Please use this section to
describe the scope and limitations of the model.

Some OpenFlow 1.3 main features are not yet supported by this module:

* Auxiliary connections
* Multiple controllers

problem with byte tags.

problem packet

References
==========

  #. The reference [Fernandes2014]_ (in portuguese) describes the details on the ``ofsoftswitch13`` software switch implementation. 

  #. The reference [Chaves2015]_  is related to the integration between OpenFlow and LTE technologies. The |ns3| simulator, enhanced with the ``OFSwitch13`` module, is used as the performance evaluation tool. This is the first published work including simulationm results obtained with the ``OFSwitch13`` module.

.. [Fernandes2014]  Eder. L. Fernandes, Christian E. Rothenberg. `"OpenFlow 1.3 Software Switch" <https://dl.dropboxusercontent.com/u/15183439/pubs/sbrc14-ferramentas-ofsoftswitch13.pdf>`_. In: Salão de Ferramentas do XXXII Simpósio Brasileiro de Redes de Computadores, 2014.

.. [Chaves2015] Luciano J. Chaves, Vítor M. Eichemberger, Islene C. Garcia, and Edmundo R. M. Madeira. `"Integrating OpenFlow to LTE: some issues toward Software-Defined Mobile Networks" <http://ieeexplore.ieee.org/xpl/articleDetails.jsp?reload=true&arnumber=7266498>`_. In: 7th IFIP International Conference on New Technologies, Mobility and Security, 2015.




