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

#ifndef TUNNEL_USER_APP_H
#define TUNNEL_USER_APP_H

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/virtual-net-device-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/ofswitch13-module.h"

namespace ns3 {

/**
 * This handler is responsible for implementing the logical port operations. It
 * provides the two callback implementations used by the logical switch port.
 * This handler is intended to demonstrate how a logical ports can be used to
 * encapsulate and de-encapsulated packets withing GTP tunnels. This
 * implementation is complete stateless, and only add or remove protocols
 * headers over packets leaving or entering the switch.
 */
class TunnelUserApp : public Application
{
public:
  TunnelUserApp ();           //!< Default constructor
  virtual ~TunnelUserApp ();  //!< Dummy destructor

  /**
   * Complete constructor
   * \param logicalPort The OpenFlow logical port device.
   * \param ipHostAddr The IP addr of the host dev connected to this switch.
   * \param macHostAddr The MAC addr of the host dev connected to this switch.
   * \param macPortAddr The MAC addr of the port on this switch connected to
   *                    the host device.
   * \param ipTunnelAddr The IPv4 address of the other tunnel endpoint.
   */
  TunnelUserApp (Ptr<VirtualNetDevice> logicalPort, Ipv4Address ipHostAddr,
                 Address macHostAddr, Address macPortAddr,
                 Ipv4Address ipTunnelAddr);

  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);

  /**
   * Method to be assigned to the send callback of the VirtualNetDevice
   * implementing the OpenFlow logical port. It is called when the switch sends
   * a packet out over the logical port and must forward the packet to the
   * tunnel socket.
   * \param packet The packet received from the logical port.
   * \param source Ethernet source address.
   * \param dst Ethernet destination address.
   * \param protocolNumber The type of payload contained in this packet.
   */
  bool RecvFromLogicalPort (Ptr<Packet> packet, const Address& source,
                            const Address& dest, uint16_t protocolNumber);

  /**
   * Method to be assigned to the receive callback of the tunnel socket. It is
   * called when the tunnel socket receives a packet, and must forward the
   * packet to the logical port.
   * \param socket Pointer to the tunnel socket.
   */
  void RecvFromTunnelSocket (Ptr<Socket> socket);

protected:
  /** Destructor implementation */
  virtual void DoDispose ();

  // Inherited from Application
  virtual void StartApplication (void);

private:
  /**
   * Adds the necessary Ethernet headers and trailers to a packet of data.
   * \param packet Packet to which header should be added.
   * \param source MAC source address from which packet should be sent.
   * \param dest MAC destination address to which packet should be sent.
   * \param protocolNumber The type of payload contained in this packet.
   */
  void AddHeader (Ptr<Packet> packet, Mac48Address source, Mac48Address dest,
                  uint16_t protocolNumber);

  Ptr<Socket>           m_tunnelSocket;   //!< UDP tunnel socket.
  Ptr<VirtualNetDevice> m_logicalPort;    //!< OpenFlow logical port device.
  Ipv4Address           m_ipTunnelAddr;   //!< IP of the other tunnel endpoint.
  Ipv4Address           m_ipHostAddr;     //!< IP of the host device
  Mac48Address          m_macHostAddr;    //!< Host device MAC.
  Mac48Address          m_macPortAddr;    //!< Port connected to the host MAC..
};

} // namespace ns3
#endif /* TUNNEL_USER_APP_H */
