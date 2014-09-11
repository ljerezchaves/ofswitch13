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
#include "ns3/ipv4-interface-container.h"
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
class OFSwitch13Helper : public SimpleRefCount<OFSwitch13Helper>
{
public:
  OFSwitch13Helper ();
  virtual ~OFSwitch13Helper ();

  /**
   * Set an attribute for the ns3::OFSwitch13Controller created by
   * OFSwitch13Helper::InstallController
   *
   * \param n1 the name of the attribute to set
   * \param v1 the value of the attribute to set
   */
  void SetControllerAttribute (std::string n1, const AttributeValue &v1);

  /**
   * Set an attribute on each ns3::OFSwitch13NetDevice created by
   * OFSwitch13Helper::InstallSwitch
   *
   * \param n1 the name of the attribute to set
   * \param v1 the value of the attribute to set
   */
  void SetDeviceAttribute (std::string n1, const AttributeValue &v1);

  /**
   * This method creates an ns3::OFSwitch13NetDevice with the attributes
   * configured by OFSwitch13Helper::SetDeviceAttribute, adds the device
   * to the swNode, and attaches the given NetDevices as ports of the
   * switch.
   *
   * \param swNode The node to install the device in
   * \param ports Container of NetDevices to add as switch ports
   * \returns A container holding the OFSwitch13NetDevice net device.
   */
  NetDeviceContainer InstallSwitch (Ptr<Node> swNode, NetDeviceContainer ports);
  
  /**
   * This method creates an ns3::OFSwitch13Controller application with the
   * attributes configured by OFSwitch13Helper::SetControllerAttribute and add
   * it to cNode. It also installs the TCP/IP stack both into
   * cNode and all switches, and connect them with a csma gigabit link, using
   * IPv4 network 10.100.150.0/24. Finally, it register the controller at each
   * switch. 
   *
   * \attention This method should be invoked after InstallSwitch
   *
   * \param cNode The node to install the controller
   * \returns The controller application
   */
  Ptr<OFSwitch13Controller> InstallController (Ptr<Node> cNode);

  /**
   * Enable pacp traces at the OpenFlow channel between controller and switches
   */
  void EnableOpenFlowPcap ();
   
  /**
   * \name Get items methods
   * \param idx The index at the container
   * \return the objects in the container at a specific index.
   */
  //\{
  Ipv4Address GetSwitchAddress (uint32_t idx);
  Ptr<OFSwitch13NetDevice> GetSwitchDevice (uint32_t idx);
  Ptr<Node> GetSwitchNode (uint32_t idx);
  //\}

  /**
   * \name GetIndex methods
   * Iterate over the containers looking for the specifc index matching the
   * parameter. This index can be used to access other containers.
   * \return The index in the containers
   */
  //\{
  uint32_t GetContainerIndex (Ipv4Address addr);
  uint32_t GetContainerIndex (Ptr<Node> node);
  uint32_t GetContainerIndex (Ptr<OFSwitch13NetDevice> dev);
  //\}

private:
  ObjectFactory             m_ctrlFactory;  //!< Controller factory
  ObjectFactory             m_ndevFactory;  //!< Device factory
  CsmaHelper                m_csmaHelper;   //!< Helper for connecting controller to switches

  Ptr<Node>                 m_ctrlNode; //!< Controller Node
  Ptr<OFSwitch13Controller> m_ctrlApp;  //!< Controller App
  Ptr<NetDevice>            m_ctrlDev;  //!< Controller CsmaNetDevice (switch connection)
  Address                   m_ctrlAddr; //!< Controller Addr 

  /**
   * Containers used to store switche nodes, OFSwitch13NetDevice devices, and
   * Ipv4Address. They use a relative position to associate these three objetcs
   * to the same switch.
   */
  //\{
  NodeContainer             m_switches; //!< Switch nodes
  NetDeviceContainer        m_devices;  //!< OFSwitch13NetDevices
  Ipv4InterfaceContainer    m_address;  //!< Switch address
  //\}
};

} // namespace ns3
#endif /* OFSWITCH1_CONTROLLER_HELPER_H */

