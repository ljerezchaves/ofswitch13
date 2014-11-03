# OpenFlow 1.3 module for ns-3 simulator #

This module can enhance the ns-3 network simulator with OpenFlow 1.3 capabilities. It provides  OpenFlow compatibles switch and controller, allowing the user to simulate software defined networks.

### CPqD ofsoftswitch13 ###

This module was designed to work together with the CPqD ofsoftswitch13 user-space software switch implementation, originally available at https://github.com/CPqD/ofsoftswitch13. This user-space switch is based on the Ericsson TrafficLab 1.1 softswitch implementation, with changes in the forwarding plane to support OpenFlow 1.3. 

In fact, this module provides an interface for interconnecting the ns-3 OFSwitch13NetDevice to the ofsoftswitch13 datapath. Also, it interconnects the OFSwitch13Controller to the dpctl utility, in order to simplify the process of sending OpenFlow messages to the switch. To this end, the ofsoftswitch13 project must be compiled as a static library and get proper linked with ns-3 simulator. 

### Installation ###

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

### Documentation and examples ###
You can find some examples on how using this module inside examples folder. The code is commented following the ns3 doxygen style, and you can compile the documentation using ./waf doxygen. The manual will be update soon!

### Important considerations ###

Some OpenFlow 1.3 main features are not yet supported by this module:

* Auxiliary connections
* Multiple controllers
* Queues at output ports