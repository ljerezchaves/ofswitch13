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

#ifndef OFSWITCH13_LEARNING_CONTROLLER_H
#define OFSWITCH13_LEARNING_CONTROLLER_H

#include "ofswitch13-interface.h"
#include "ofswitch13-net-device.h"
#include "ofswitch13-controller.h"
#include <ns3/arp-header.h>
#include <ns3/ethernet-header.h>
#include <ns3/ethernet-trailer.h>
#include <ns3/arp-l3-protocol.h>

namespace ns3 {

/**
 * \ingroup ofswitch13
 * \brief An Learning OpenFlow 1.3 controller (works as L2 switch)
 */
class OFSwitch13LearningController : public OFSwitch13Controller
{
public:
  OFSwitch13LearningController ();          //!< Default constructor
  virtual ~OFSwitch13LearningController (); //!< Dummy destructor, see DoDispose.

  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);

  /** Destructor implementation */
  virtual void DoDispose ();

  /**
   * Handle packet-in messages sent from switch to this controller. Look for L2
   * switching information, update the structures and send a packet-out back.
   *
   * \param msg The packet-in message.
   * \param swtch The switch information.
   * \param xid Transaction id.
   * \return 0 if everything's ok, otherwise an error number.
   */
  ofl_err HandlePacketIn (ofl_msg_packet_in *msg, SwitchInfo swtch, uint32_t xid);

  /**
   * Handle flow removed messages sent from switch to this controller. Look for L2
   * switching information and removes associated entry.
   *
   * \param msg The flow removed message.
   * \param swtch The switch information.
   * \param xid Transaction id.
   * \return 0 if everything's ok, otherwise an error number.
   */
  ofl_err HandleFlowRemoved (ofl_msg_flow_removed *msg, SwitchInfo swtch, uint32_t xid);
  
  /**
   * Notify this controller of a new eNB IP device connected to the OpenFlow
   * network over some switch port. This function will save the IP address /
   * MAC address from this IP device for further ARP resolution. 
   * \attention This dev is not the one added as port to switch. Instead, this
   * is the 'other' end of this connection, associated with a eNB or SgwPgw
   * node.
   * \param dev The device connected to the OpenFlow network.
   * \param ip The IPv4 address assigned to this device.
   * \param switchIdx The switch index this device is attached to.
   */
  virtual void 
  NotifyNewIpDevice (Ptr<NetDevice> dev, Ipv4Address ip); //ref//

protected:
  // Inherited from OFSwitch13Controller
  void ConnectionStarted (SwitchInfo swtch);
  
  /**
   * Extract an IPv4 address from packet match.
   * \param oxm_of The OXM_IF_* IPv4 field.
   * \param match The ofl_match structure pointer.
   * \return The IPv4 address.
   */
  Ipv4Address ExtractIpv4Address (uint32_t oxm_of, ofl_match* match); //ref//

private:
  /**
   * Handle packet-in messages sent from switch with arp message.
   * \param msg The packet-in message.
   * \param swtch The switch information.
   * \param xid Transaction id.
   * \return 0 if everything's ok, otherwise an error number.
   */
  ofl_err HandleArpPacketIn (ofl_msg_packet_in *msg, SwitchInfo swtch, 
                             uint32_t xid);

  /**
   * Perform an ARP resolution
   * \param ip The Ipv4Address to search.
   * \return The MAC address for this ip.
   */
  Mac48Address ArpLookup (Ipv4Address ip);

  /**
   * Create a Packet with an ARP reply, encapsulated inside of an Ethernet
   * frame (with header and trailer.
   * \param srcMac Source MAC address.
   * \param srcIP Source IP address.
   * \param dstMac Destination MAC address.
   * \param dstMac Destination IP address.
   * \return The ns3 Ptr<Packet> with the ARP reply.
   */
  Ptr<Packet> CreateArpReply (Mac48Address srcMac, Ipv4Address srcIp, 
                              Mac48Address dstMac, Ipv4Address dstIp);  

  /** Map saving <IPv4 address / MAC address> */
  typedef std::map<Ipv4Address, Mac48Address> IpMacMap_t;

  /** Map saving <IPv4 address / Switch index > */
  typedef std::map<Ipv4Address, uint16_t> IpSwitchMap_t;

  IpMacMap_t        m_arpTable;         //!< ARP resolution table.

  /**
   * \name L2 switching structures
   */
  //\{
  typedef std::map<Mac48Address, uint32_t> L2Table_t;     //!< L2SwitchingTable: map MacAddress to port
  typedef std::map<uint64_t, L2Table_t>    DatapathMap_t; //!< Map datapathID to L2SwitchingTable
  DatapathMap_t                            m_learnedInfo; //!< Switching information for all dapataths
  //\}
};

} // namespace ns3
#endif /* OFSWITCH13_LEARNING_CONTROLLER_H */
