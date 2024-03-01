# OpenFlow 1.3 module for ns-3

The `OFSwitch13` module enhances the [ns-3 Network Simulator][ns-3] with Software-Defined Networking (SDN) capabilities.
`OFSwitch13` supports [OpenFlow protocol version 1.3][ofp13], bringing a switch device and a controller application interface to the ns-3 simulator.
With `OFSwitch13`, it is possible to interconnect ns-3 nodes to send and receive traffic using the existing CSMA and virtual network devices.
Extending the controller application interface allows users to implement any desired control logic to orchestrate the network.
The communication between the controller and the switches happens over standard ns-3 protocol stack, devices, and channels.
The `OFSwitch13` module relies on the external [`BOFUSS` library][bofuss] that provides the switch datapath implementation and the support for OpenFlow messages in wire format.

Please visit the [OFSwitch13 project homepage][project] and refer to the documentation for details about the module design, installation, and usage.

## License

The `OFSwitch13` module is a free software licensed under the [GNU GPLv2 license][gpl].

## Contribute

The `OFSwitch13` module is currently maintained by Luciano Jerez Chaves.
It also received contributions from Vítor Marge Eichemberger, Islene Calciolari Garcia, and Arthur Boechat Mazzi.
We thank Eder Leão Fernandes for helping with the `BOFUSS` library integration.

Please contribute to this project by submitting your bug reports to the [issue tracker][issues]. For fixes and improvements, consider creating a pull request.

## Contact

Feel free to subscribe to the [mailing list at Google Groups][group] and provide feedback, give suggestions, interact with other users, or say hello!

[ns-3]: https://www.nsnam.org
[ofp13]: https://www.opennetworking.org/sdn-resources/technical-library
[bofuss]: https://github.com/ljerezchaves/ofsoftswitch13
[project]: http://www.lrc.ic.unicamp.br/ofswitch13/
[issues]: https://github.com/ljerezchaves/ofswitch13-module/issues
[gpl]: http://www.gnu.org/copyleft/gpl.html
[group]: https://groups.google.com/forum/#!forum/ofswitch13-users
