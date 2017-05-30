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

#ifndef GTP_TUNNEL_APP_H
#define GTP_TUNNEL_APP_H

#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/internet-module.h>
#include <ns3/applications-module.h>
#include <ns3/virtual-net-device-module.h>
#include <ns3/csma-module.h>

namespace ns3 {

/**
 * This GTP tunnel application is responsible for implementing the logical port
 * operations to encapsulate and de-encapsulated packets withing GTP tunnel. It
 * provides the callback implementations that are used by the logical switch
 * port and UDP socket. This application is stateless: it only adds/removes
 * protocols headers over packets leaving/entering the OpenFlow switch based on
 * information that is carried by packet tags.
 *
 * When sending a packet to the GTP tunnel, this application expects that the
 * packet carries the TunnelId tag set with the destination address in the 32
 * MSB and the TEID in the 32 LSB of packet tag. When a packet is received from
 * the GTP tunnel, this application attachs the TunnelId tag only with the GTP
 * TEID value.
 */
class GtpTunnelApp : public Application
{
public:
  /**
   * Complete constructor.
   * \param logicalPort The OpenFlow logical port device.
   * \param physicalDev The physical network device on node.
   */
  GtpTunnelApp (Ptr<VirtualNetDevice> logicalPort,
                Ptr<CsmaNetDevice> physicalDev);
  virtual ~GtpTunnelApp ();  //!< Dummy destructor, see DoDispose.

  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);

  /**
   * Method to be assigned to the send callback of the VirtualNetDevice
   * implementing the OpenFlow logical port. It is called when the OpenFlow
   * switch sends a packet out over the logical port. The logical port
   * callbacks here, and we must encapsulate the packet withing GTP and forward
   * it to the UDP tunnel socket.
   * \param packet The packet received from the logical port.
   * \param source Ethernet source address.
   * \param dest Ethernet destination address.
   * \param protocolNo The type of payload contained in this packet.
   * \return Whether the operation succeeded.
   */
  bool RecvFromLogicalPort (Ptr<Packet> packet, const Address& source,
                            const Address& dest, uint16_t protocolNo);

  /**
   * Method to be assigned to the receive callback of the UDP tunnel socket. It
   * is called when the tunnel socket receives a packet, and must forward the
   * packet to the logical port.
   * \param socket Pointer to the tunnel socket.
   */
  void RecvFromTunnelSocket (Ptr<Socket> socket);

protected:
  /** Destructor implementation. */
  virtual void DoDispose ();

  // Inherited from Application.
  virtual void StartApplication (void);

private:
  /**
   * Adds the necessary Ethernet headers and trailers to a packet of data.
   * \param packet Packet to which header should be added.
   * \param source MAC source address from which packet should be sent.
   * \param dest MAC destination address to which packet should be sent.
   * \param protocolNo The type of payload contained in this packet.
   */
  void AddHeader (Ptr<Packet> packet, Mac48Address source = Mac48Address (),
                  Mac48Address dest = Mac48Address (),
                  uint16_t protocolNo = Ipv4L3Protocol::PROT_NUMBER);

  Ptr<Socket>           m_tunnelSocket;   //!< UDP tunnel socket.
  Ptr<VirtualNetDevice> m_logicalPort;    //!< OpenFlow logical port device.
  Ptr<CsmaNetDevice>    m_physicalDev;    //!< Node physical network device.
  const uint16_t        m_port = 2152;    //!< GTP tunnel port.
};

} // namespace ns3
#endif /* GTP_TUNNEL_APP_H */
