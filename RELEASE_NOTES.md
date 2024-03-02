# Release notes

This file contains OFSwitch13 release notes (most recent releases first).

## [Release 5.2.3](https://github.com/ljerezchaves/ofswitch13/releases/tag/5.2.3)

**Release date:** Mar 02, 2024.  
**Works with:** ns-3.38, ns-3.39, and ns-3.40.

- Configuring `OFSwitch13PriorityQueue::QueueFactory` with `DropTailQueue<Packet>` queues by default.
- Renaming `OFSwitch13Helper::ChannelType` enumeration values to match coding style.
- Enabling checksum computations in `OFSwitch13Helper::CreateOpenFlowChannel()` methods.
- This release automatically handles the integration between OFSwitch13 module and BOFUSS library v5.2.x.

## [Release 5.2.2](https://github.com/ljerezchaves/ofswitch13/releases/tag/5.2.2)

**Release date:** Sep 01, 2023.  
**Works with:** ns-3.38 and ns-3.39.

- Removing `examples/ofswitch13-qos-controller` dependency from the NetAnim module.
- Updating buffer timeout operation with millisecond resolution support.
- Updating the maximum size of the parent `OFSwitch13Queue` class with the sum of the maximum size of all internal queues (the operation mode of all internal queues must be the same).
- This release automatically handles the integration between OFSwitch13 module and BOFUSS library v5.2.x.

## [Release 5.2.1](https://github.com/ljerezchaves/ofswitch13/releases/tag/5.2.1)

**Release date:** Mar 31, 2023.  
**Works with:** ns-3.38.

- Replacing `V4PingHelper` by `PingHelper` in examples.
- This release automatically handles the integration between OFSwitch13 module and BOFUSS library v5.2.x.

## [Release 5.2.0](https://github.com/ljerezchaves/ofswitch13/releases/tag/5.2.0)

**Release date:** Mar 31, 2023.  
**Works with:** ns-3.36 and ns-3.37.

- Replacing the outdated ofsoftswitch13 name by BOFUSS in the project (source code and documentation).
- Refactoring the BOFUSS ns3lib branch to simplify library compilation.
- Updating `CMakeLists.txt` to automatically download, configure and build the BOFUSS library.
- Updating the module documentation to reflect the changes in building process.
- This release automatically handles the integration between OFSwitch13 module and BOFUSS library v5.2.x.

## [Release 5.1.0](https://github.com/ljerezchaves/ofswitch13/releases/tag/5.1.0)

**Release date:** Dec 10, 2022.  
**Works with:** ns-3.36 and ns-3.37.

- Updating the build system to work with CMake introduced by ns-3.36.
- Updating the source code formatting to match ns-3.37 coding style.
- Updating the module documentation, removing outdated figures.
- New CSMA full-duplex patch for improved channel operation.
- Fixing errors when compiling the project with gcc 11.3.0 in Ubuntu 22.04.1.
- This release requires manual integration between OFSwitch13 module and BOFUSS library v5.1.x.

## [Release 5.0.1](https://github.com/ljerezchaves/ofswitch13/releases/tag/5.0.1)

**Release date:** Dec 20, 2021.  
**Works with:** ns-3.31, ns-3.32, ns-3.33, ns-3.34, and ns-3.35.

- Updating the `OFSwitch13Queue` class to match the changes introduced in the Queue API by ns-3.31.
- Removing DL library dependency to prevent issues with boost library.
- This release requires manual integration between OFSwitch13 module and BOFUSS library v5.0.x.

## [Release 5.0.0](https://github.com/ljerezchaves/ofswitch13/releases/tag/5.0.0)

**Release date:** Dec 19, 2021.  
**Works with:** ns-3.30.

**BE AWARE THAT** this release brings incompatible API changes.

- Refactoring the `OFSwitch13Controller::Dpctl*()` methods:
  - The `OFSwitch13Controller::DpctlExecute()` method has no more overloaded definitions. The target switch (first parameter) must be the switch's datapath IP. Previous signature using the `Ptr<const RemoteSwitch>` pointer was removed. Users can fix compilation errors by just using `RemoteSwitch::GetDpId()` method when invoking `OFSwitch13Controller::DpctlExecute()`.
  - The `OFSwitch13Controller::DpctlSchedule()` method was deprecated in favor of `OFSwitch13Controller::DpctlExecute()`. When the switch is not connected to the controller, the `OFSwitch13Controller::DpctlExecute()` method will automatically schedule the command for execution just after the handshake procedure. This is particularly useful for executing commands when creating the topology, before invoking `Simulator::Run()`.
- New `OFSwitch13Device::TableDrop` trace source to notify unmatched packets dropped by flow tables without table-miss entries.
- New `TabDrps` column in the `OFSwitch13StatsCalculator` output file.
- Updating the `OFSwitch13Queue` class to match the changes introduced in the Queue API by ns-3.30.
- Updating the `ofswitch13-external-controller` example with a custom topology configuration (this example was tested with the Ryu controller).
- Fixing incorrect Ethernet 802.3 packet header parsing.
- Fixing errors when compiling the project with gcc 9.3.0 in Ubuntu 20.04.
- This release requires manual integration between OFSwitch13 module and BOFUSS library v5.0.x.

## [Release 4.0.0](https://github.com/ljerezchaves/ofswitch13/releases/tag/4.0.0)

**Release date:** Apr 02, 2019.  
**Works with:** ns-3.28 and ns-3.29.

**BE AWARE THAT** this release brings incompatible API changes.

- Refactoring the OFSwitch13 queue API:
  - The `OFSwitch13Queue` class implements the queue interface, extending the `Queue<Packet>` class to allow compatibility with the `CsmaNetDevice` used by `OFSwitch13Port`. Internally, it holds a collection of N (possibly different) queues, identified by IDs ranging from 0 to N-1. The `OFSwitch13Queue::Enqueue()` method uses the `QueueTag` to identify which internal queue will hold the packet.
  - Specialized `OFSwitch13Queue` subclasses can perform different output scheduling algorithms by implementing the virtual `OFSwitch13Queue::Peek()`, `OFSwitch13Queue::Dequeue()`, and `OFSwitch13Queue::Remove()` methods. The last two methods must call the `OFSwitch13Queue::NotifyDequeue()` and `OFSwitch13Queue::NotifyRemoved()`, respectively, to update statistics and keep consistency with the base class.
  - The `OFSwitch13Port::QueueFactory` attribute can be used to configure OpenFlow port queue at construction time.
  - The new `OFSwitch13PriorityQueue` class implements the specialized priority queuing discipline for a collection of N priority queues, identified by IDs ranging from 0 to N-1 with decreasing priority (queue ID 0 has the highest priority). The output scheduling algorithm ensures that higher-priority queues are always served first. The `OFSwitch13PriorityQueue::QueueFactory` and `OFSwitch13PriorityQueue::NumQueues` attributes can be used to configure the type and the number of internal priority queues.
- Refactoring the `OFSwitch13Device` class:
  - Adjusting `OFSwitch13Device::PipelineTables`, `OFSwitch13Device::FlowTableSize`, `OFSwitch13Device::GroupTableSize`, and `OFSwitch13Device::MeterTableSize` attributes at any time.
  - New `OFSwitch13Device::GetDpId()` method as an alias for the `OFSwitch13Device::GetDatapathId()` method.
  - New `OFSwitch13Device::GetDatapathStruct()` and `OFSwitch13Port::GetPortStruct()` methods returning pointers to the BOFUSS library internal structures.
  - New `OFSwitch13Device::GetDatapathTimeout()`, `OFSwitch13Device::GetFlowTableUsage()`, `OFSwitch13Device::GetGroupTableUsage()`, `OFSwitch13Device::GetMeterTableUsage()`, `OFSwitch13Device::GetNControllers()`, `OFSwitch13Device::GetBufferEntries()`, `OFSwitch13Device::GetBufferUsage()`, and `OFSwitch13Device::GetBufferSize()` methods for datapath statistics.
  - Renaming `OFSwitch13Device::PipelineCapacity` attribute to `OFSwitch13Device::CpuCapacity`,
  - Renaming `OFSwitch13Device::PipelineLoad` traced value to `OFSwitch13Device::CpuLoad`,
  - Renaming `OFSwitch13Device::LoadDrop` trace source to `OFSwitch13Device::OverloadDrop`.
  - Renaming `OFSwitch13Device::GetOFSwitch13Port()` method to `OFSwitch13Device::GetSwitchPort()`.
  - Renaming `OFSwitch13Device::GetPipelineLoad()` method to `OFSwitch13Device::GetCpuLoad()`.
  - Renaming `OFSwitch13Device::GetPipelineCapacity()` method to `OFSwitch13Device::GetCpuCapacity()`.
  - Renaming `OFSwitch13Device::GetFlowEntries()` method to `OFSwitch13Device::GetFlowTableEntries()`
  - Renaming `OFSwitch13Device::GetGroupEntries()` method to `OFSwitch13Device::GetGroupTableEntries()`.
  - Renaming `OFSwitch13Device::GetMeterEntries()` method to `OFSwitch13Device::GetMeterTableEntries()`.
- Refactoring the `OFSwitch13StatsCalculator` class:
  - New `OFSwitch13StatsCalculator::FlowTableDetails` attribute to dump individual flow table statistics.
  - Renaming `OFSwitch13StatsCalculator::GetEwmaPipelineLoad()` method to `OFSwitch13StatsCalculator::GetEwmaCpuLoad()`.
  - Renaming `OFSwitch13StatsCalculator::GetAvgPipelineUsage()` method to `OFSwitch13StatsCalculator::GetAvgCpuUsage()`.
  - Renaming column names in first row, removing any special character from them.
- Overriding the `OFSwitch13Helper::InstallSwitch()` method:
  - When the first parameter is a node container, the method returns an OpenFlow device container.
  - When the first parameter is a node pointer, the method returns the OpenFlow device pointer (there's the optional second parameter of a device container that will be configured as switch ports).
- New `OFSwitch13Port::GetPortDevice()`, `OFSwitch13Port::GetPortQueue()` and `OFSwitch13Port::GetSwitchDevice()` methods.
- Increasing the maximum number of OpenFlow switch ports to 4096 (see DP_MAX_PORTS at BOFUSS library)
- Increasing the maximum number of output queues on ports to 32 (see NETDEV_MAX_QUEUES at BOFUSS library)
- Removing the BOFUSS library dependency on the NetBee library.
- Improving the BOFUSS library performance and fixing memory leak errors.
- This release requires manual integration between OFSwitch13 module and BOFUSS library v4.0.x.

## [Release 3.3.0](https://github.com/ljerezchaves/ofswitch13/releases/tag/3.3.0)

**Release date:** Sep 29, 2018.  
**Works with:** ns-3.28 and ns-3.29.

- Fixing incorrect bitwise comparison in port configuration.
- Fixing incorrect ns-3 version comparison that was preventing module configuration in ns-3.28.1
- New `OFSwitch13Device::PipelineTables` attribute to define the number of flow tables in the pipeline.
- Adjusting `OFSwitch13Device::PipelineTables`, `OFSwitch13Device::FlowTableSize`, `OFSwitch13Device::GroupTableSize`, and `OFSwitch13Device::MeterTableSize` attributes at construction time only.
- Renaming the `OFSwitch13Device::GetFlowEntries()` method to `OFSwitch13Device::GetSumFlowEntries()`.
- Renaming the `OFSwitch13StatsCalculator::GetEwmaFlowEntries()` method to `OFSwitch13StatsCalculator::GetEwmaSumFlowEntries()`.
- This release requires manual integration between OFSwitch13 module and BOFUSS library v3.3.x.

## [Release 3.2.2](https://github.com/ljerezchaves/ofswitch13/releases/tag/3.2.2)

**Release date:** Jul 05, 2018.  
**Works with:** ns-3.28.

- Fixing errors when compiling the project with gcc 7.3.0 in Ubuntu 18.04.
- Replacing Mercurial by Git as version control system.
- Configuring the BOFUSS library as a git submodule that automatically handle version compatibility.
- This release requires manual integration between OFSwitch13 module and BOFUSS library v3.2.x.

## [Release 3.2.1](https://github.com/ljerezchaves/ofswitch13/releases/tag/3.2.1)

**Release date:** May 22, 2018.  
**Works with:** ns-3.28.

- Updating `OFSwitch13Queue` and `OFSwitch13InternalHelper` classes to avoid using deprecated ns-3 queue API when setting queue size and queue mode.
- This release requires manual integration between OFSwitch13 module and BOFUSS library v3.2.x.

## [Release 3.2.0](https://github.com/ljerezchaves/ofswitch13/releases/tag/3.2.0)

**Release date:** May 22, 2018.  
**Works with:** ns-3.27.

- Updating `OFSwitch13Queue` class to match the changes introduced in the Queue API by ns-3.27 (special thanks to Stefano Avallone for providing the necessary patches).
- This release requires manual integration between OFSwitch13 module and BOFUSS library v3.2.x.

## [Release 3.1.1](https://github.com/ljerezchaves/ofswitch13/releases/tag/3.1.1)

**Release date:** May 12, 2018.  
**Works with:** ns-3.26.

- New packet counter in `OFSwitch13StatsCalculator` class to measure the pipeline load.
- New `OFSwitch13Queue::QueueFactory` attribute for the object factory used to create internal OpenFlow queues on device ports.
- Fixing errors when handling packet tags and refilling meter tokens.
- This release requires manual integration between OFSwitch13 module and BOFUSS library v3.1.x.

## [Release 3.1.0](https://github.com/ljerezchaves/ofswitch13/releases/tag/3.1.0)

**Release date:** May 29, 2017.  
**Works with:** ns-3.26.

- New `OFSwitch13Device::PipelineCapacity` attribute to limit the traffic throughput to a specific data rate.
- New `OFSwitch13Device::FlowTableSize`, `OFSwitch13Device::GroupTableSize`, and `OFSwitch13Device::MeterTableSize` attributes to define the maximum number of entries in pipeline tables.
- New `OFSwitch13Queue::NumQueues` attribute to define the number of output queues available for use.
- New `OFSwitch13SocketHandler` class to assist switches and controllers dealing with TCP sockets used by the OpenFlow channels.
- Including the meter ID parameter on the `OFSwitch13Device::MeterDrop` trace source.
- Including new trace sources in `OFSwitch13Device` for monitoring datapath performance.
- Refactoring the `OFSwitch13StatsCalculator` to dump statistics in a clear way.
- Improving the `ofswitch13-logical-port` example with a stateless tunnel application.
- Updating the default `OFSwitch13Device::TcamDelay` attribute value to better reflect real hardware operation.
- This release requires manual integration between OFSwitch13 module and BOFUSS library v3.1.x.

## [Release 3.0.0](https://github.com/ljerezchaves/ofswitch13/releases/tag/3.0.0)

**Release date:** Feb 10, 2017.  
**Works with:** ns-3.26.

**BE AWARE THAT** this release brings incompatible API changes.

- Start using the [semantic versioning](http://semver.org) on this project.
- Updating the `OFSwitch13Queue` class to match the changes introduced in the Queue API by ns-3.26.
- Supporting multiple controllers in the same OpenFlow network domain.
- Supporting `VirtualNetDevice` as logical OpenFlow port.
- Renaming examples files with prefix `ofswitch13-`.
- New `ofswitch13-logical-port` example.
- Removing the need of registering the switch at the controller before starting the connection.
- Removing the `OFSwitch13Device::ControllerAddr` attribute (the controller address must be indicated by the helper as a parameter to the `OFSwitch13Device::StartControllerConnection()` method).
- New `OFSwitch13StatsCalculator` class for switch performance monitoring.
- Implementing a simplified OpenFlow version-negotiation in OpenFlow device.
- New `SocketReader` class for safely reading OpenFlow messages from TCP sockets.
- New `RemoteController` and `RemoteSwitch` classes to handle several remote connections.
- Refactoring the `OFSwitch13Controller` class:
  - Splitting the `DpctlCommand()` method into `DpctlExecute()` and `DpctlSchedule()`.
  - Removing the dependence from the `OFSwitch13Device` class.
  - Renaming the `ConnectionStarted()` method to `HandshakeSuccessful()`.
  - Implementing the handshake procedure.
  - Implementing the barrier reply, hello and features reply handlers.
  - Using constant pointers to `RemoteSwitch` objects.
- Refactoring the `OFSwitch13Helper` class:
  - Using the `OFSwitch13Helper` as a base class and implementing extended helpers for configuring an OpenFlow network domain with internal controller applications (`OFSwitch13InternalHelper`) or an external controller (`OFSwitch13ExternalHelper`).
  - Removing the need of installing the controller before configuring the switches.
  - Introducing the `CreateOpenFlowChannels()` method to effectively connect switches to controllers after installing switches and controllers into respective nodes (the use of this function is mandatory).
- This release requires manual integration between OFSwitch13 module and BOFUSS library v3.0.x.

## [Release 2.0.3](https://github.com/ljerezchaves/ofswitch13/releases/tag/2.0.3)

**Release date:** Sep 12, 2016.  
**Works with:** ns-3.22, ns-3.23, ns-3.24.1, and ns-3.25.

- Fixing a wrong variable type on priority output queue selection.
- This release requires manual integration between OFSwitch13 module and BOFUSS library v2.0.x.

## [Release 2.0.2](https://github.com/ljerezchaves/ofswitch13/releases/tag/2.0.2)

**Release date:** Apr 11, 2016.  
**Works with:** ns-3.22, ns-3.23, ns-3.24.1, and ns-3.25.

- Renaming `OFSwitch13NetDevice` to `OFSwitch13Device`, as the OpenFlow device is not a network device anymore.
- New `OFSwitch13DeviceContainer` for handling OpenFlow devices.
- New `CsmaNetDevice` OpenFlow receive callback that forwards packets with all headers from the underlying CSMA port to the OpenFlow device.
- New `qos-controller` example.
- Creating 8 priority queues for each `OFSwitch13Queue`.
- Updating the documentation with detailed module design and `qos-controller` example description.
- This release requires manual integration between OFSwitch13 module and BOFUSS library v2.0.x.

## [Release 2.0.1](https://github.com/ljerezchaves/ofswitch13/releases/tag/2.0.1)

**Release date:** Feb 16, 2016.  
**Works with:** ns-3.22, ns-3.23 and ns-3.24.1.

- Improving documentation with highlights for the differences between the OFSwitch13 module and the existing ns-3 OpenFlow module.
- Patches for integrating OFSwitch13 with ns-3 versions 3.22, 3.23 and 3.24.1.
- This release requires manual integration between OFSwitch13 module and BOFUSS library v2.0.x.

## [Release 2.0.0](https://github.com/ljerezchaves/ofswitch13/releases/tag/2.0.0)

**Release date:** Feb 15, 2016.  
**Works with:** ns-3.22, ns-3.23, and ns-3.24.1.

- The first public release of the OFSwitch13 module, including source code and documentation.
- This release requires manual integration between OFSwitch13 module and BOFUSS library v2.0.x.
