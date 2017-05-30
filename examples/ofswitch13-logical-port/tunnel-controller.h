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

#ifndef TUNNEL_CONTROLLER_H
#define TUNNEL_CONTROLLER_H

#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/internet-module.h>
#include <ns3/applications-module.h>
#include <ns3/ofswitch13-module.h>
#include <ns3/virtual-net-device-module.h>

namespace ns3 {

/**
 * This controller is responsible for installing the forwarding rules on the
 * switches. For packets entering the switches coming from the hosts, the
 * controller sets the tunnel id and send packets to the logical port, where
 * they will be encapsulated withing GTP-U/UDP/IP protocols. For packets
 * entering the switches coming from the logical port, the controller forwards
 * the packets to the host.
 */
class TunnelController : public OFSwitch13Controller
{
public:
  TunnelController ();           //!< Default constructor.
  virtual ~TunnelController ();  //!< Dummy destructor, see DoDispose.

  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);

  /**
   * Save the pair IP / MAC address in ARP table.
   * \param ipAddr The IPv4 address.
   * \param macAddr The MAC address.
   */
  void SaveArpEntry (Ipv4Address ipAddr, Mac48Address macAddr);

  /**
   * Save the pair datapath ID + port no / IP address in tunnel endpoint table.
   * \param dpId The datapath ID.
   * \param portNo The port number.
   * \param ipAddr The IPv4 address of tunnel endpoint.
   */
  void SaveTunnelEndpoint (uint64_t dpId, uint32_t portNo, Ipv4Address ipAddr);

protected:
  /** Destructor implementation */
  virtual void DoDispose ();

  // Inherited from OFSwitch13Controller
  void HandshakeSuccessful (Ptr<const RemoteSwitch> swtch);

  /**
   * Handle a packet in message sent by the switch to this controller.
   * \note Inherited from OFSwitch13Controller.
   * \param msg The OpenFlow received message.
   * \param swtch The remote switch metadata.
   * \param xid The transaction id from the request message.
   * \return 0 if everything's ok, otherwise an error number.
   */
  virtual ofl_err HandlePacketIn (
    struct ofl_msg_packet_in *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

private:
  /**
   * Perform ARP resolution.
   * \param ip The Ipv4Address to search.
   * \return The MAC address for this ip.
   */
  Mac48Address GetArpEntry (Ipv4Address ip);

  /**
   * Perform tunnel endpoint resolution.
   * \param dpId The datapath ID.
   * \param portNo The port number.
   * \return The IPv4 address of tunnel endpoint.
   */
  Ipv4Address GetTunnelEndpoint (uint64_t dpId, uint32_t portNo);

  /**
   * Handle packet-in messages sent from switch with ARP message.
   * \param msg The packet-in message.
   * \param swtch The switch information.
   * \param xid Transaction id.
   * \return 0 if everything's ok, otherwise an error number.
   */
  ofl_err HandleArpPacketIn (
    struct ofl_msg_packet_in *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

  /**
   * Extract an IPv4 address from packet match.
   * \param oxm_of The OXM_IF_* IPv4 field.
   * \param match The ofl_match structure pointer.
   * \return The IPv4 address.
   */
  Ipv4Address ExtractIpv4Address (uint32_t oxm_of, struct ofl_match* match);

  /**
   * Create a Packet with an ARP reply, encapsulated inside of an Ethernet
   * frame (with header and trailer.
   * \param srcMac Source MAC address.
   * \param srcIp Source IP address.
   * \param dstMac Destination MAC address.
   * \param dstIp Destination IP address.
   * \return The ns3 Ptr<Packet> with the ARP reply.
   */
  Ptr<Packet> CreateArpReply (Mac48Address srcMac, Ipv4Address srcIp,
                              Mac48Address dstMac, Ipv4Address dstIp);

  /** A pair identifying OpenFlow datapath id and port number. */
  typedef std::pair<uint64_t, uint32_t> DpPortPair_t;

  /** Map saving <DpPortPair_t / IPv4 address> */
  typedef std::map<DpPortPair_t, Ipv4Address> DpPortIpMap_t;

  /** Map saving <IPv4 address / MAC address> */
  typedef std::map<Ipv4Address, Mac48Address> IpMacMap_t;

  IpMacMap_t      m_arpTable;       //!< ARP resolution table.
  DpPortIpMap_t   m_endpointTable;  //!< Tunnel endpoint resolution table.
};

} // namespace ns3
#endif /* TUNNEL_CONTROLLER_H */
