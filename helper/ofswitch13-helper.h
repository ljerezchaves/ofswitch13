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
#include "ns3/ofswitch13-net-device.h"
#include "ns3/net-device-container.h"
#include "ns3/node-container.h"
#include "ns3/object-factory.h"
#include "ns3/csma-helper.h"
#include <string>

namespace ns3 {

class Node;
class AttributeValue;
class OFSwitch13Controller;

/**
 * \ingroup ofswitch13
 * \brief 
 */
class OFSwitch13Helper
{
public:
  OFSwitch13Helper ();

  /**
   * Set an attribute for the ns3::OFSwitch13Controller created by
   * OFSwitch13Helper::InstallController
   *
   * \param n1 the name of the attribute to set
   * \param v1 the value of the attribute to set
   */
  void 
  SetControllerAttribute (std::string n1, const AttributeValue &v1);

  /**
   * Set an attribute on each ns3::OFSwitch13NetDevice created by
   * OFSwitch13SwitchHelper::Install
   *
   * \param n1 the name of the attribute to set
   * \param v1 the value of the attribute to set
   */
  void SetDeviceAttribute (std::string n1, const AttributeValue &v1);

  /**
   * This method creates an ns3::OFSwitch13Controller application with the
   * attributes configured by OFSwitch13Helper::SetControllerAttribute and add
   * it to the cNode. Also, this method installs the TCP/IP stack both into
   * cNode and all swNodes, and connect them with an csma gigabit link, using
   * IPv4 network 10.100.150.0/24. Finally, it register the controller at each
   * switch. 
   *
   * \attention This method should be invoked afert all InstallSwitch
   *
   * \param cNode The node to install the controller
   * \returns The controller application
   */
  Ptr<OFSwitch13Controller> InstallController (Ptr<Node> cNode);

  /**
   * This method creates an ns3::OFSwitch13NetDevice with the attributes
   * configured by OFSwitch13Helper::SetDeviceAttribute, adds the device
   * to the swNode, and attaches the given NetDevices as ports of the
   * switch.
   *
   * \param swNode The node to install the device in
   * \param devs Container of NetDevices to add as switch ports
   * \returns A container holding the added net device.
   */
  NetDeviceContainer
  InstallSwitch (Ptr<Node> swNode, NetDeviceContainer devs);

  /**
   * Enable openflow pacp traces between controller and switches
   */
  void EnableOpenFlowPcap ();

private:
  ObjectFactory m_controllerFactory;    //!< Controller factory
  ObjectFactory m_deviceFactory;        //!< Device factory

  Ptr<Node> m_controller;               //!< Controller Node
  Ptr<OFSwitch13Controller> m_app;      //!< Controller App
  Ptr<NetDevice> m_controllerPort;      //!< Controller csma device connected to switches

  CsmaHelper m_csmaHelper;              //!< Helper to create the connection between controller and switches

  NodeContainer m_switches;             //!< Switches

  std::vector<Ptr<OFSwitch13NetDevice> > m_devices; //!< OFSwitch13NetDevices
};

} // namespace ns3
#endif /* OFSWITCH1_CONTROLLER_HELPER_H */

