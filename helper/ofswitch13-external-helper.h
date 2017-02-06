/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017 University of Campinas (Unicamp)
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

#ifndef OFSWITCH13_EXTERNAL_HELPER_H
#define OFSWITCH13_EXTERNAL_HELPER_H

#include <ns3/ofswitch13-helper.h>

namespace ns3 {

class Node;
class AttributeValue;
class OFSwitch13Controller;
class OFSwitch13LearningController;

/**
 * \ingroup ofswitch13
 *
 * This helper extends the base class and can be instantiated to create and
 * configure an OpenFlow 1.3 network domain composed of one or more OpenFlow
 * switches connected to a single external real OpenFlow controller. It brings
 * methods for configuring the controller node for TapBridge usage and creating
 * the OpenFlow channels.
 */
class OFSwitch13ExternalHelper : public OFSwitch13Helper
{
public:
  OFSwitch13ExternalHelper ();          //!< Default constructor.
  virtual ~OFSwitch13ExternalHelper (); //!< Dummy destructor, see DoDispose.

  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);

  // Inherited from OFSwitch13Helper.
  void SetChannelType (ChannelType type);
  void SetChannelDataRate (DataRate rate);
  void CreateOpenFlowChannels (void);

  /**
   * This method prepares the controller node so it can be used to connect
   * internal simulated switches to an external OpenFlow controller running on
   * the local machine over a TapBridge device. It installs the TCP/IP stack
   * into controller node, attach it to the common CSMA channel and configure
   * IP address for it.
   *
   * \param cNode The node to configure as the controller.
   * \return The network device to bind to the TapBridge.
   */
  Ptr<NetDevice> InstallExternalController (Ptr<Node> cNode);

protected:
  /** Destructor implementation. */
  virtual void DoDispose ();

private:
  Ptr<CsmaChannel>          m_csmaChannel;      //!< Common CSMA channel.
  Ptr<Node>                 m_controlNode;      //!< OF controller node.
  uint16_t                  m_controlPort;      //!< OF controller TCP port.
  Ipv4Address               m_controlAddr;      //!< OF IP controller addr.
};

} // namespace ns3
#endif /* OFSWITCH13_EXTERNAL_HELPER_H */

