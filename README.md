# OpenFlow 1.3 module for ns-3 #
This is the `OFSwitch13` module, which enhances the [ns-3 Network Simulator][ns-3] with [OpenFlow 1.3][ofp13] capabilities, allowing ns-3 users to simulate Software-Defined Networks (SDN). 
In fact, this module implements the interface for interconnecting the ns-3 simulator to the [OpenFlow 1.3 Software Switch for ns-3][ofs13] (`ofsoftswitch13`) library. It is the library that, in fact, provides the switch implementation, the library for converting to/from OpenFlow 1.3 wire format, and the `dpctl` tool for configuring the switch from the console.

Please, visit the `OFSwitch13` [project homepage][project] for detailed information on the module design, documentation, and *how to get started* tutorials.

# Contribute #
Please, contribute to this project submitting your bug reports to our [issue tracker][issues]. For fixes and suggestions, consider creating a pull request.

# License #
The `OFSwitch13` module is free software, licensed under the [GNU GPLv2 license][gpl], and is publicly available for research, development, and use.

# Acknowledgments #
Thanks to the main contributors:

* Luciano Jerez Chaves
* Vítor Marge Eichemberger
* Islene Calciolari Garcia
* *"Your name here"*

# Contact #
Luciano Jerez Chaves (luciano at lrc dot ic dot unicamp dot br)

[ns-3]: https://www.nsnam.org
[ofp13]: https://www.opennetworking.org/sdn-resources/technical-library
[ofs13]: https://github.com/ljerezchaves/ofsoftswitch13
[project]: http://www.lrc.ic.unicamp.br/ofswitch13/
[wiki]: https://bitbucket.org/ljerezchaves/ofswitch13-module/wiki/Home
[ofs13vm]: http://www.lrc.ic.unicamp.br/~luciano/files/ns3-ofswitch13.ova
[issues]: https://bitbucket.org/ljerezchaves/ofswitch13-module/issues?status=new&status=open
[gpl]: http://www.gnu.org/copyleft/gpl.html
[manual]: http://www.lrc.ic.unicamp.br/ofswitch13/