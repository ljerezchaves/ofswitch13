/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2016 University of Campinas (Unicamp)
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

#ifndef LOGICAL_PORT_TUNNEL_H
#define LOGICAL_PORT_TUNNEL_H

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/ofswitch13-module.h"

using namespace ns3;

/**
 * This controller is responsible for installing the forwarding rules on the
 * switches. For packets entering the switches coming from the hosts, the
 * controller sets the tunnel id and send packets to logical port, where they
 * will be encapsulated withing GTP-U/UDP/IP protocols.
 * port.
 */
class TunnelController : public OFSwitch13Controller
{
public:
  TunnelController ();           //!< Default constructor
  virtual ~TunnelController ();  //!< Dummy destructor, see DoDipose

protected:
  // Inherited from OFSwitch13Controller
  void HandshakeSuccessful (Ptr<const RemoteSwitch> swtch);
};


/**
 * This handler is responsible for implementing the logical port operations. It
 * provides the two callback implementations used by the logical switch port.
 * This handler is intended to demonstrate how a logical ports can be used to
 * encapsulate and de-encapsulated packets withing GTP tunnels. This
 * implementation is complete stateless, and only add or remove protocols
 * headers over packets leaving or entering the switch.
 */
class TunnelHandler
{
public:
  TunnelHandler ();   //!< Default constructor
  ~TunnelHandler ();  //!< Dummy destructor

  /**
   * Receive logical port callback implementation. Remove the GTP-U/UDP/IP
   * headers from the packet and return the GTP-U TEID id.
   * \param dpId The datapath id.
   * \param portNo The physical port number.
   * \param packet The received packet.
   * \return The GTP teid value from the header.
   * port.
   */
  uint64_t Receive (uint64_t dpId, uint32_t portNo, Ptr<Packet> packet);

  /**
   * Send logical port callback implementation. Add the GTP-U/UDP/IP
   * headers to the packet, using the tunnelId as GTP-U TEID value.
   * \param dpId The datapath id.
   * \param portNo The physical port number.
   * \param packet The packet to send.
   * \param tunnelId The GTP teid value to use during encapsulation.
   */
  void Send (uint64_t dpId, uint32_t portNo, Ptr<Packet> packet,
             uint64_t tunnelId);
};

#endif /* LOGICAL_PORT_TUNNEL_H */
