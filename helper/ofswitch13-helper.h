/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2015 University of Campinas (Unicamp)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Luciano Chaves <luciano@lrc.ic.unicamp.br>
 */

#ifndef OFSWITCH13_HELPER_H
#define OFSWITCH13_HELPER_H

#include <ns3/ofswitch13-interface.h>
#include <ns3/ofswitch13-controller.h>
#include <ns3/ofswitch13-device.h>
#include <ns3/ofswitch13-device-container.h>
#include <ns3/application-container.h>
#include <ns3/ipv4-interface-container.h>
#include <ns3/internet-stack-helper.h>
#include <ns3/ipv4-address-helper.h>
#include <ns3/node-container.h>
#include <ns3/object-factory.h>
#include <ns3/csma-helper.h>
#include <ns3/point-to-point-helper.h>
#include <ns3/inet-socket-address.h>
#include <ns3/simple-ref-count.h>
#include <ns3/names.h>
#include <string>

namespace ns3 {

class Node;
class AttributeValue;
class OFSwitch13Controller;
class OFSwitch13LearningController;

/**
 * \ingroup ofswitch13
 *
 * This is a base class that must be extended to create and configure an
 * OpenFlow 1.3 network domain composed of one or more OpenFlow switches
 * connected to single or multiple OpenFlow controllers.
 *
 * By default, the connections between switches and controllers are created
 * using a single shared out-of-band CSMA channel, with IP addresses assigned
 * using a /24 network mask. Users can modify this configuration by changing
 * the ChannelType attribute at instantiation time. Dedicated out-of-band
 * connections over CSMA or Point-to-Point channels are also available, using a
 * /30 network mask for IP allocation.
 *
 * Please note that this base helper class was designed to configure a single
 * OpenFlow network domain. All switches will be connected to all controllers
 * on the same domain. If you want to configure separated OpenFlow domains on
 * your network topology (with their individual switches and controllers) so
 * you may need to use a different instance of the derived helper class for
 * each domain. In this case, don't forget to use the SetAddressBase ()
 * method to change the IP network address of the other helper instances, in
 * order to avoid IP conflicts.
 */
class OFSwitch13Helper : public Object
{
public:
  /**
   * OpenFlow channel type, used to create the connections.
   * between controllers and switches.
   */
  enum ChannelType
  {
    SINGLECSMA = 0,       //!< Uses a single shared CSMA channel.
    DEDICATEDCSMA = 1,    //!< Uses individual CSMA channels.
    DEDICATEDP2P = 2      //!< Uses individual P2P channels.
  };

  OFSwitch13Helper ();          //!< Default constructor.
  virtual ~OFSwitch13Helper (); //!< Dummy destructor, see DoDispose.

  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);

  /**
   * Set an attribute on each OpenFlow device created by this helper.
   *
   * \param n1 the name of the attribute to set.
   * \param v1 the value of the attribute to set.
   */
  void SetDeviceAttribute (std::string n1, const AttributeValue &v1);

  /**
   * Set the OpenFlow channel type used to create the connections between
   * switches and controllers.
   *
   * \param type The ChannelType to use.
   */
  virtual void SetChannelType (ChannelType type);

  /**
   * Set the OpenFlow channel data rate used to create the connections between
   * switches and controllers.
   *
   * \param rate The channel data rate to use.
   */
  virtual void SetChannelDataRate (DataRate rate);

  /**
   * Enable pacp traces at OpenFlow channel between controller and switches.
   *
   * \attention Call this method only after configuring the OpenFlow channels.
   *
   * \param prefix Filename prefix to use for pcap files.
   * \param promiscuous If true, enable promisc trace.
   */
  void EnableOpenFlowPcap (std::string prefix = "ofchannel",
                           bool promiscuous = true);

  /**
   * Enable ASCII traces at OpenFlow channel between controller and switches.
   *
   * \attention Call this method only after configuring the OpenFlow channels.
   *
   * \param prefix Filename prefix to use for ascii files.
   */
  void EnableOpenFlowAscii (std::string prefix = "ofchannel");

  /**
   * Enable OpenFlow datapath statistics at OpenFlow switch devices configured
   * by this helper. This method will create an OFSwitch13StatsCalculator for
   * each switch device, dumping statistcs to output files.
   *
   * \attention Call this method only after configuring the OpenFlow channels.
   *
   * \param prefix Filename prefix to use for stats files.
   * \param useNodeNames Use node names instead of datapath id.
   */
  void EnableDatapathStats (std::string prefix = "datapath",
                            bool useNodeNames = false);

  /**
   * This method creates an OpenFlow device and aggregates it to the switch
   * node. It also attaches the given devices as physical ports on the switch.
   * If no devices are given, the switch will be configured without ports. In
   * this case, don't forget to add ports to it later, or it will do nothing.
   *
   * \param swNode The switch node where to install the OpenFlow device.
   * \param ports Container of devices to be added as physical switch ports.
   * \return The OpenFlow device created.
   */
  Ptr<OFSwitch13Device> InstallSwitch (Ptr<Node> swNode,
                                       NetDeviceContainer &swPorts);

  /**
   * This method creates an OpenFlow device and aggregates it to the switch
   * node. The switch configured by this method will have no switch ports.
   * Don't forget to add ports do it later, or it will do nothing.
   *
   * \param swNode The switch node where to install the OpenFlow device.
   * \return The OpenFlow device created.
   */
  Ptr<OFSwitch13Device> InstallSwitch (Ptr<Node> swNode);

  /**
   * This method creates and aggregates an OpenFlow device to each switch node
   * in the container. Switches configured by this method will have no switch
   * ports. Don't forget to add ports do them later, or they will do nothing.
   *
   * \param swNodes The switch nodes where to install the OpenFlow devices.
   * \return A container holding all the OpenFlow devices created.
   */
  OFSwitch13DeviceContainer InstallSwitch (NodeContainer &swNodes);

  /**
   * This virtual method must interconnect all switches to all controllers
   * installed by this helper and starts the individual OpenFlow channel
   * connections.
   * \attention After calling this method, it will not be allowed to install
   *            more switches or controller using this helper.
   */
  virtual void CreateOpenFlowChannels (void) = 0;

  /**
   * Set the IP network base address, used to assign IP addresses to switches
   * and controllers during the CreateOpenFlowChannels () procedure.
   *
   * \param network The Ipv4Address containing the initial network number to
   *        use during allocation.
   * \param mask The Ipv4Mask containing one bits in each bit position of the
            network number.
   * \param base An optional Ipv4Address containing the initial address used
   *        for IP address allocation.
   */
  static void SetAddressBase (Ipv4Address network, Ipv4Mask mask,
                              Ipv4Address base = "0.0.0.1");

  /**
   * Enable OpenFlow datapath logs at all OpenFlow switch devices on the
   * simulation. This method will enable vlog system at debug level on the
   * ofsoftswitch13 library, dumping messages to output file.
   *
   * \param prefix Filename prefix to use for log file.
   * \param explicitFilename Treat the prefix as an explicit filename if true.
   */
  static void EnableDatapathLogs (std::string prefix = "",
                                  bool explicitFilename = false);

protected:
  /** Destructor implementation. */
  virtual void DoDispose ();

  ChannelType               m_channelType;      //!< OF channel type.
  DataRate                  m_channelDataRate;  //!< OF channel data rate.
  ObjectFactory             m_devFactory;       //!< OF device factory.
  bool                      m_blocked;          //!< Block this helper.

  NetDeviceContainer        m_controlDevs;      //!< OF channel ctrl devices.
  OFSwitch13DeviceContainer m_openFlowDevs;     //!< OF switch devices.
  NodeContainer             m_switchNodes;      //!< OF switch nodes.

  InternetStackHelper       m_internet;         //!< Helper for TCP/IP stack.
  CsmaHelper                m_csmaHelper;       //!< Helper for CSMA links.
  PointToPointHelper        m_p2pHelper;        //!< Helper for P2P links.

  static Ipv4AddressHelper  m_ipv4helper;       //!< Helper for IP address.
};

} // namespace ns3
#endif /* OFSWITCH1_CONTROLLER_HELPER_H */

