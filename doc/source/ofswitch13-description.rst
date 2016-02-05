Model Description
*****************


Overview
========


OpenFlow 1.3 module for ns-3 simulator

This module can enhance the ns-3 network simulator with OpenFlow 1.3 capabilities. It provides OpenFlow compatibles switch and controller, allowing the user to simulate software defined networks.


This module was designed to work together with the CPqD ofsoftswitch13 user-space software switch implementation, originally available at https://github.com/CPqD/ofsoftswitch13. This user-space switch is based on the Ericsson TrafficLab 1.1 softswitch implementation, with changes in the forwarding plane to support OpenFlow 1.3.

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

.. [ofSwitch13] E. L. Fernandes, C. E. Rothenberg, OpenFlow 1.3 Software Switch. https://dl.dropboxusercontent.com/u/15183439/pubs/sbrc14-ferramentas-ofsoftswitch13.pdf

*OBS:* This article is only available in portuguese, and it describes the external openflow library (wich were used as reference to implement the openflow) without any relation with the integration between this library (the ns-3 *ofSwitch13* module) and the ns-3 simulator.

