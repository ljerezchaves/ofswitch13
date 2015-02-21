/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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
#include "ns3/ofswitch13-net-device.h"
#include "ns3/net-device-container.h"
#include "ns3/ipv4-interface-container.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/node-container.h"
#include "ns3/object-factory.h"
#include "ns3/csma-helper.h"
#include "ns3/inet-socket-address.h"
#include "ns3/simple-ref-count.h"
#include <string>

namespace ns3 {

class Node;
class AttributeValue;
class OFSwitch13Controller;

/**
 * \ingroup ofswitch13
 *
 * \brief Create and configure an OpenFlow 1.3 network with a single controller
 * and multiple switches.
 */
//class OFSwitch13Helper : public SimpleRefCount<OFSwitch13Helper>
class OFSwitch13Helper
{
public:
  OFSwitch13Helper ();
  virtual ~OFSwitch13Helper ();

  /**
   * Set an attribute on each ns3::OFSwitch13NetDevice created by
   * OFSwitch13Helper::InstallSwitch
   *
   * \param n1 the name of the attribute to set
   * \param v1 the value of the attribute to set
   */
  void SetDeviceAttribute (std::string n1, const AttributeValue &v1);

  /**
   * Set the base network number, network mask and base address.
   *
   * \param network The Ipv4Address containing the initial network number to
   * use during allocation. The bits outside the network mask are not used.
   * \param mask The Ipv4Mask containing one bits in each bit position of the
   * network number.
   * \param base An optional Ipv4Address containing the initial address used
   * for IP address allocation. Will be combined (ORed) with the network number
   * to generate the first IP address. Defaults to 0.0.0.1.
   */
  void SetAddressBase (Ipv4Address network, Ipv4Mask mask, 
      Ipv4Address base = "0.0.0.1");

  /**
   * This method creates a ns3::OFSwitch13NetDevice with the attributes
   * configured by OFSwitch13Helper::SetDeviceAttribute, adds the device to the
   * swNode, and attaches the given NetDevices as ports of the switch. It also
   * installs the TCP/IP stack into swNode, and connect it to the csma
   * gigabit network using IPv4 network 10.100.150.0/24. Finally, if the
   * controller has been already set, start the switch <--> controller
   * connection.
   *
   * \param swNode The node to install the device in
   * \param ports Container of NetDevices to add as switch ports
   * \returns A container holding the OFSwitch13NetDevice net device.
   */
  NetDeviceContainer 
  InstallSwitch (Ptr<Node> swNode, NetDeviceContainer ports);

  /**
   * This method creates and install a ns3::OFSwitch13NetDevice with the
   * attributes configured by OFSwitch13Helper::SetDeviceAttribute for each
   * node in swNodes container.  It also installs the TCP/IP stack into each
   * node, and connect them to the csma gigabit network using IPv4 network
   * 10.100.150.0/24. Finally, if the controller has been already set, start
   * the switch <--> controller connection.
   *
   * \attention Switches configured by this methods have no switch ports. Don't
   * forget to add ports do them later, or they will do nothing.
   *
   * \param swNode The node to install the device in
   * \param ports Container of NetDevices to add as switch ports
   * \returns A container holding the OFSwitch13NetDevice net device.
   */
  NetDeviceContainer InstallSwitchesWithoutPorts (NodeContainer swNodes);

  /**
   * This method creates a new ns3::OFSwitch13LearningController application
   * and install it into cNode. It also installs the TCP/IP stack into cNode,
   * and connects it to the csma gigabit network, using IPv4 network
   * 10.100.150.0/24. Finally, start the switch <--> controller connection
   * for all already registered switches.
   *
   * \param cNode The node to configure as controller
   * \returns The OFSwitch13LearningController application created (installed
   * into cNode)
   */
  Ptr<OFSwitch13Controller> InstallControllerApp (Ptr<Node> cNode);

  /**
   * This method installs the given ns3::OFSwitch13Controller application into
   * cNode. It also installs the TCP/IP stack into cNode, and connects it to
   * the csma gigabit network, using IPv4 network 10.100.150.0/24. Finally,
   * start the switch <--> controller connection for all already registered
   * switches.
   *
   * \param cNode The node to configure as controller
   * \param controller The controller application to install into cNode
   * \returns The controller application (same as input)
   */
  Ptr<OFSwitch13Controller> 
  InstallControllerApp (Ptr<Node> cNode, Ptr<OFSwitch13Controller> controller);

  /**
   * This method prepares the cNode so it can connect to an external OpenFlow
   * controller over TapBridge. It also installs the TCP/IP stack into cNode,
   * and connects it to the csma gigabit network, using IPv4 network
   * 10.100.150.0/24. Finally, start the switch <--> controller connection for
   * all already registered switches.
   *
   * \attention It is expected that this method is used togheter with TabBridge
   *            to provide an external OpenFlow controller.
   *
   * \param cNode The node to install the controller
   * \returns The CsmaNetDevice to bind to TapBridge
   */
  Ptr<NetDevice> InstallExternalController (Ptr<Node> cNode);

  /**
   * Enable pacp traces at the OpenFlow channel between controller and switches
   */
  void EnableOpenFlowPcap (std::string prefix = "openflow-channel");

  /**
   * Enable log traces at the OpenFlow switches
   */
  void EnableDatapathLogs (std::string level = "all");

private:
  ObjectFactory             m_ndevFactory;  //!< OpenFlow NetDevice factory

  NetDeviceContainer        m_devices;      //!< OFSwitch13NetDevices
  InternetStackHelper       m_internet;     //!< Helper for installing TCP/IP
  Ipv4AddressHelper         m_ipv4helper;   //!< Helper for assigning IP
  CsmaHelper                m_csmaHelper;   //!< Helper for connecting controller to switches

  Ptr<CsmaChannel>          m_csmaChannel;  //!< Channel connecting switches to controller
  Ptr<Node>                 m_ctrlNode;     //!< Controller Node
  Ptr<OFSwitch13Controller> m_ctrlApp;      //!< Controller App
  Ptr<NetDevice>            m_ctrlDev;      //!< Controller CsmaNetDevice (switch connection)
  Address                   m_ctrlAddr;     //!< Controller Addr

  /** Structure to store switch information */
  typedef std::vector<SwitchInfo> SwitchInfoVector_t;  
  SwitchInfoVector_t        m_unregSw;      //!< OpenFlow switches not registered to controller yet
};

} // namespace ns3
#endif /* OFSWITCH1_CONTROLLER_HELPER_H */

