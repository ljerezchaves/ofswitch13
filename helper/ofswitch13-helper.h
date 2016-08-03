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

#include "ns3/ofswitch13-interface.h"
#include "ns3/ofswitch13-controller.h"
#include "ns3/ofswitch13-device.h"
#include "ns3/ofswitch13-device-container.h"
#include "ns3/ipv4-interface-container.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/node-container.h"
#include "ns3/object-factory.h"
#include "ns3/csma-helper.h"
#include "ns3/point-to-point-helper.h"
#include "ns3/inet-socket-address.h"
#include "ns3/simple-ref-count.h"
#include "ns3/names.h"
#include <string>

namespace ns3 {

class Node;
class AttributeValue;
class OFSwitch13Controller;

// FIXME: This helper must support the use of multiple controllers.
/**
 * \ingroup ofswitch13
 *
 * \brief Helper to create and configure an OpenFlow 1.3 network with a single
 * controller and multiple switches. This helper can be configure to create a
 * single shared csma with the controller and all switches, or using dedicated
 * links (csma or point-to-point) between each switch and the controller.
 *
 * \attention This helper extends the Object class, and should be created with
 * the CreateObject method.
 */
class OFSwitch13Helper : public Object
{
public:
  /**
   * OpenFlow channel type, used to create the connections between the
   * controller and switches.
   */
  enum ChannelType
  {
    SINGLECSMA = 0,       //!< Uses a single shared csma channel
    DEDICATEDCSMA = 1,    //!< Uses individual csma channels
    DEDICATEDP2P = 2      //!< Uses individual p2p channels
  };

  OFSwitch13Helper ();          //!< Default constructor
  virtual ~OFSwitch13Helper (); //!< Dummy destructor, see DoDipose

  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);

  /** Destructor implementation */
  virtual void DoDispose ();

  /**
   * Set an attribute on each ns3::OFSwitch13Device created by this helper.
   *
   * \param n1 the name of the attribute to set
   * \param v1 the value of the attribute to set
   */
  void SetDeviceAttribute (std::string n1, const AttributeValue &v1);

  /**
   * Set the ChannelType strategy used to create the controller
   * channel between the switches and the controller.
   *
   * \param type The SetOpenflowChannelType to use.
   */
  void SetChannelType (ChannelType type);

  /**
   * Set the OpenFlow controller channel data rate, used to connect the
   * controller to the switches.
   *
   * \param datarate The DataRate to use.
   */
  void SetChannelDataRate (DataRate datarate);

  /**
   * Enable log traces at the OpenFlow switches
   *
   * \param level The log level
   */
  void EnableDatapathLogs (std::string level = "all");

  /**
   * Set the base network number, network mask and base address.
   *
   * \param network The Ipv4Address containing the initial network number to
   * use during allocation.
   * \param mask The Ipv4Mask containing one bits in each bit position of the
   * network number.
   * \param base An optional Ipv4Address containing the initial address used
   * for IP address allocation.
   */
  void SetAddressBase (Ipv4Address network, Ipv4Mask mask,
                       Ipv4Address base = "0.0.0.1");

  /**
   * This method creates and aggregate a ns3::OFSwitch13Device at each node in
   * swNodes container. It also installs the TCP/IP stack into each node, and
   * connects them to the controller. Finally, if the controller has been
   * already set, it starts the switch <--> controller connection.
   *
   * \attention Switches configured by this methods have no switch ports. Don't
   * forget to add ports do them later, or they will do nothing.
   *
   * \param swNodes The nodes to install the device in
   * \returns A container holding the OFSwitch13Device devices.
   */
  OFSwitch13DeviceContainer InstallSwitchesWithoutPorts (
    NodeContainer swNodes);

  /**
   * This method creates a new ns3::OFSwitch13LearningController application
   * and install it into cNode. It also installs the TCP/IP stack into cNode.
   * Finally, it starts the switch <--> controller connection for all previous
   * registered switches.
   *
   * \param cNode The node to configure as controller
   * \returns The OFSwitch13LearningController application created (installed
   * into cNode)
   */
  Ptr<OFSwitch13Controller> InstallDefaultController (Ptr<Node> cNode);

  /**
   * This method creates a ns3::OFSwitch13Device, aggregates it to the
   * swNode, and attaches the given NetDevices as ports of the switch. It also
   * installs the TCP/IP stack into swNode, and connects it to the controller.
   * Finally, if the controller has been already set, start the switch <-->
   * controller connection.
   *
   * \param swNode The node to install the device in
   * \param ports Container of NetDevices to add as switch ports
   * \returns A container holding the OFSwitch13Device devices.
   */
  OFSwitch13DeviceContainer InstallSwitch (
    Ptr<Node> swNode, NetDeviceContainer ports);

  /**
   * This method installs the given ns3::OFSwitch13Controller application into
   * cNode. It also installs the TCP/IP stack into cNode. Finally, it starts
   * the switch <--> controller connection for all previous registered
   * switches.
   *
   * \param cNode The node to configure as controller
   * \param controller The controller application to install into cNode
   * \returns The controller application (same as input)
   */
  Ptr<OFSwitch13Controller> InstallControllerApp (
    Ptr<Node> cNode, Ptr<OFSwitch13Controller> controller);

  /**
   * This method prepares the cNode so it can connect to an external OpenFlow
   * controller over TapBridge. It also installs the TCP/IP stack into cNode,
   * and connects it to the csma network. Finally, start the switch <-->
   * controller connection for all already registered switches.
   *
   * \attention It is expected that this method is used togheter with TabBridge
   *            to provide an external OpenFlow controller.
   *
   * \param cNode The node to install the controller
   * \returns The CsmaNetDevice to bind to TapBridge
   */
  Ptr<NetDevice> InstallExternalController (Ptr<Node> cNode);

  /**
   * Enable pacp traces at OpenFlow channel between controller and switches.
   *
   * \param prefix Filename prefix to use for pcap files.
   */
  void EnableOpenFlowPcap (std::string prefix = "ofchannel");

  /**
   * Enable ascii traces at OpenFlow channel between controller and switches.
   *
   * \param prefix Filename prefix to use for ascii files.
   */
  void EnableOpenFlowAscii (std::string prefix = "ofchannel");

protected:
  ObjectFactory             m_devFactory;       //!< OpenFlow device factory
  OFSwitch13DeviceContainer m_devices;          //!< OpenFlow devices
  NetDeviceContainer        m_ctrlDevs;         //!< Controller devices
  InternetStackHelper       m_internet;         //!< Helper for TCP/IP
  Ipv4AddressHelper         m_ipv4helper;       //!< Helper for IP address
  CsmaHelper                m_csmaHelper;       //!< Helper for csma connection
  PointToPointHelper        m_p2pHelper;        //!< Helper for p2p connection
  Ptr<CsmaChannel>          m_csmaChannel;      //!< Common controller channel

  // FIXME: We must be able to install and configure more than a single
  // controller on the network, so we need a collection of controllers here
  Ptr<Node>                 m_ctrlNode;         //!< Controller node
  Ptr<OFSwitch13Controller> m_ctrlApp;          //!< Controller application
  Address                   m_ctrlAddr;         //!< Controller address

  uint16_t                  m_ctrlPort;         //!< Controller port
  ChannelType               m_channelType;      //!< Channel type
  DataRate                  m_channelDataRate;  //!< Channel link data rate
};

} // namespace ns3
#endif /* OFSWITCH1_CONTROLLER_HELPER_H */

