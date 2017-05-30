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

#ifndef OFSWITCH13_INTERNAL_HELPER_H
#define OFSWITCH13_INTERNAL_HELPER_H

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
 * switches connected to a single or multiple internal simulated OpenFlow
 * controllers. It brings methods for installing the controller and creating
 * the OpenFlow channels.
 */
class OFSwitch13InternalHelper : public OFSwitch13Helper
{
public:
  OFSwitch13InternalHelper ();          //!< Default constructor.
  virtual ~OFSwitch13InternalHelper (); //!< Dummy destructor, see DoDispose.

  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);

  // Inherited from OFSwitch13Helper.
  void CreateOpenFlowChannels (void);

  /**
   * This method installs the given controller application into the given
   * controller node. If no application is given, a new (default) learning
   * controller application is created and installed into controller node.
   *
   * \param cNode The node to configure as controller.
   * \param controller The controller application to install into cNode
   * \return The installed controller application.
   */
  Ptr<OFSwitch13Controller> InstallController (
    Ptr<Node> cNode, Ptr<OFSwitch13Controller> controller =
      CreateObject<OFSwitch13LearningController> ());

protected:
  /** Destructor implementation. */
  virtual void DoDispose ();

private:
  /**
   * Create an individual connection between the switch and the controller
   * node, using the already configured channel type.
   *
   * \param ctrl The controller node.
   * \param swtch The switch node.
   * \return The devices created on both nodes.
   */
  NetDeviceContainer Connect (Ptr<Node> ctrl, Ptr<Node> swtch);

  ApplicationContainer      m_controlApps;      //!< OF controller apps.
  NodeContainer             m_controlNodes;     //!< OF controller nodes.
};

} // namespace ns3
#endif /* OFSWITCH13_INTERNAL_HELPER_H */

