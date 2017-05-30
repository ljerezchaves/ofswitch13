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
 * Author:  Luciano Chaves <luciano@lrc.ic.unicamp.br>
 */

#ifndef QOS_CONTROLLER_H
#define QOS_CONTROLLER_H

#include <ns3/ofswitch13-module.h>

using namespace ns3;

/**
 * \brief An border OpenFlow 1.3 controller
 */
class QosController : public OFSwitch13Controller
{
public:
  QosController ();          //!< Default constructor.
  virtual ~QosController (); //!< Dummy destructor.

  /** Destructor implementation */
  virtual void DoDispose ();

  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);

  /**
   * Handle a packet in message sent by the switch to this controller.
   * \note Inherited from OFSwitch13Controller.
   * \param msg The OpenFlow received message.
   * \param swtch The remote switch metadata.
   * \param xid The transaction id from the request message.
   * \return 0 if everything's ok, otherwise an error number.
   */
  ofl_err HandlePacketIn (
    struct ofl_msg_packet_in *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

protected:
  // Inherited from OFSwitch13Controller
  void HandshakeSuccessful (Ptr<const RemoteSwitch> swtch);

private:
  /**
   * Configure the border switch.
   * \param swtch The switch information.
   */
  void ConfigureBorderSwitch (Ptr<const RemoteSwitch> swtch);

  /**
   * Configure the aggregation switch.
   * \param swtch The switch information.
   */
  void ConfigureAggregationSwitch (Ptr<const RemoteSwitch> swtch);

  /**
   * Handle ARP request messages.
   * \param msg The packet-in message.
   * \param swtch The switch information.
   * \param xid Transaction id.
   * \return 0 if everything's ok, otherwise an error number.
   */
  ofl_err HandleArpPacketIn (
    struct ofl_msg_packet_in *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

  /**
   * Handle TCP connection request
   * \param msg The packet-in message.
   * \param swtch The switch information.
   * \param xid Transaction id.
   * \return 0 if everything's ok, otherwise an error number.
   */
  ofl_err HandleConnectionRequest (
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
   * Create an ARP request packet, encapsulated inside of an Ethernet frame.
   * \param srcMac Source MAC address.
   * \param srcIp Source IP address.
   * \param dstIp Destination IP address.
   * \return The ns3 Ptr<Packet> with the ARP request.
   */
  Ptr<Packet> CreateArpRequest (Mac48Address srcMac, Ipv4Address srcIp,
                                Ipv4Address dstIp);

  /**
   * Create an ARP reply packet, encapsulated inside of an Ethernet frame.
   * \param srcMac Source MAC address.
   * \param srcIp Source IP address.
   * \param dstMac Destination MAC address.
   * \param dstIp Destination IP address.
   * \return The ns3 Ptr<Packet> with the ARP reply.
   */
  Ptr<Packet> CreateArpReply (Mac48Address srcMac, Ipv4Address srcIp,
                              Mac48Address dstMac, Ipv4Address dstIp);

  /**
   * Save the pair IP / MAC address in ARP table.
   * \param ipAddr The IPv4 address.
   * \param macAddr The MAC address.
   */
  void SaveArpEntry (Ipv4Address ipAddr, Mac48Address macAddr);

  /**
   * Perform an ARP resolution
   * \param ip The Ipv4Address to search.
   * \return The MAC address for this ip.
   */
  Mac48Address GetArpEntry (Ipv4Address ip);

  Address   m_serverIpAddress;    //!< Virtual server IP address
  uint16_t  m_serverTcpPort;      //!< Virtual server TCP port
  Address   m_serverMacAddress;   //!< Border switch MAC address
  bool      m_meterEnable;        //!< Enable per-flow mettering
  DataRate  m_meterRate;          //!< Per-flow meter rate
  bool      m_linkAggregation;    //!< Enable link aggregation

  /** Map saving <IPv4 address / MAC address> */
  typedef std::map<Ipv4Address, Mac48Address> IpMacMap_t;
  IpMacMap_t m_arpTable;          //!< ARP resolution table.
};

#endif /* QOS_CONTROLLER_H */
