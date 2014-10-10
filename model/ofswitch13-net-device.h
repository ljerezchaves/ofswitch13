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

#ifndef OFSWITCH13_NET_DEVICE_H
#define OFSWITCH13_NET_DEVICE_H

#include <errno.h>

#include "ns3/object.h"
#include "ns3/net-device.h"
#include "ns3/mac48-address.h"
#include "ns3/bridge-channel.h"
#include "ns3/csma-net-device.h"
#include "ns3/node.h"
#include "ns3/packet.h"
#include "ns3/socket.h"
#include "ns3/simple-ref-count.h"

#include "ofswitch13-interface.h"

namespace ns3 {

/**
 * \ingroup ofswitch13
 * A OpenFlow switch port metadata, saving the port number, the pointer to ns3
 * NetDevice and the pointer to ofsoftswitch internal sw_port structure.
 * \see ofsoftswitch13 udatapath/dp_ports.h
 */
class OfPort : public SimpleRefCount<OfPort>
{
  friend class OFSwitch13NetDevice;

public:
  /**
   * Create and populate port information.
   * \param dp The datapath.
   * \param dev The swith port ns3::NetDevice.
   */
  OfPort (datapath *dp, Ptr<NetDevice> dev);

  /** Default destructor */
  ~OfPort ();

private:
  /**
   * Create the bitmaps of OFPPF_* that describe port features, based on
   * ns3::NetDevice.
   * \return Port features bitmap.
   */
  uint32_t PortGetFeatures ();

  uint32_t portNo;       //!< Port number
  Ptr<NetDevice> netdev; //!< Pointer to ns3::NetDevice
  sw_port *swPort;       //!< Pointer to datapath sw_port
};

/** Structure to store port information. */
typedef std::vector<Ptr<OfPort> > Ports_t;

/**
 * \ingroup ofswitch13
 *
 * A NetDevice that switches multiple LAN segments via OpenFlow protocol.
 * The OFSwitch13NetDevice object aggregates multiple netdevices as ports
 * and acts like a switch. It implements OpenFlow datapath compatibility,
 * according to the OpenFlow Switch Specification v1.3.
 *
 * \attention Each NetDevice used as port must only be assigned a Mac Address.
 * adding an Ipv4 or Ipv6 layer to it will cause an error. It also must support
 * a SendFrom call.
 */
class OFSwitch13NetDevice : public NetDevice
{
public:
  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);

  /**
   * Default constructor. Initialize structures.
   * \see ofsoftswitch dp_new () at udatapath/datapath.c
   */
  OFSwitch13NetDevice ();

  /**
   * Dummy destructor, see DoDispose.
   */
  virtual ~OFSwitch13NetDevice ();

  /**
    * Add a 'port' to the switch device. This method adds a new switch
    * port to a OFSwitch13NetDevice, so that the new switch port NetDevice
    * becomes part of the switch and L2 frames start being forwarded to/from
    * this NetDevice.
    * \attention The current implementation only supports CsmaNetDevices using
    * DIX encapsulation. Also, the csmaNetDevice that is being added as switch
    * port must _not_ have an IP address.
    * \param portDevice The NetDevice port to add.
    * \return 0 if everything's ok, otherwise an error number.
    */
  int AddSwitchPort (Ptr<NetDevice> portDevice);

  /**
   * Send a message to the controller. This method is the key to communicating
   * with the controller, it does the actual sending. The other send methods
   * call this one when they are ready to send the packet.
   * \internal This method is public as the 'C' dp_send_message overriding
   * function use this 'C++' member function to send their messages.
   * \see send_openflow_buffer () at udatapath/datapath.c.
   * \param msg The OFLib message to send.
   * \param sender When replying to controller, the sender (controller)
   * information, incluind xid.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int SendToController (ofl_msg_header *msg, const sender *sender = NULL);

  /**
   * Send a message over a specific switch port. Check port configuration,
   * create the ns3 packet, remove the ethernet header and trailer from packet
   * (which will be included again by CsmaNetDevice), send the packet over the
   * proper netdevice, and update port statistics.
   * \param buffer The internal packet buffer to send.
   * \param portNo The port number.
   * \param queueNo The queue number.
   * \return True if success, false otherwise.
   */
  bool SendToSwitchPort (ofpbuf *buffer, uint32_t portNo, uint32_t queueNo);

  /**
   * \return Number of switch ports attached to this switch.
   */
  uint32_t GetNSwitchPorts (void) const;

  /**
   * \return The datapath ID.
   */
  uint64_t GetDatapathId (void) const;

  /**
   * \return The next (in sequence) transaction ID for this switch.
   */
  uint32_t GetNextXid ();

  /**
   * Starts the TCP connection between switch and controller.
   */
  void StartControllerConnection ();

  // Inherited from NetDevice base class
  virtual void SetIfIndex (const uint32_t index);
  virtual uint32_t GetIfIndex (void) const;
  virtual Ptr<Channel> GetChannel (void) const;
  virtual void SetAddress (Address address);
  virtual Address GetAddress (void) const;
  virtual bool SetMtu (const uint16_t mtu);
  virtual uint16_t GetMtu (void) const;
  virtual bool IsLinkUp (void) const;
  virtual void AddLinkChangeCallback (Callback<void> callback);
  virtual bool IsBroadcast (void) const;
  virtual Address GetBroadcast (void) const;
  virtual bool IsMulticast (void) const;
  virtual Address GetMulticast (Ipv4Address multicastGroup) const;
  virtual Address GetMulticast (Ipv6Address addr) const;
  virtual bool IsPointToPoint (void) const;
  virtual bool IsBridge (void) const;
  virtual bool Send (Ptr<Packet> packet, const Address& dest, uint16_t protocolNumber);
  virtual bool SendFrom (Ptr<Packet> packet, const Address& source, const Address& dest,
                         uint16_t protocolNumber);
  virtual Ptr<Node> GetNode (void) const;
  virtual void SetNode (Ptr<Node> node);
  virtual bool NeedsArp (void) const;
  virtual void SetReceiveCallback (NetDevice::ReceiveCallback cb);
  virtual void SetPromiscReceiveCallback (NetDevice::PromiscReceiveCallback cb);
  virtual bool SupportsSendFrom () const;

private:
  virtual void DoDispose (void);

  ///\name Datapath methods
  //\{
  /**
   * Creates a new datapath.
   * \return The created datapath.
   */
  datapath* DatapathNew ();

  /**
   * Check if any flow in any table is timed out and update port status. This
   * method reschedules itself at every m_timout interval, to constantly check
   * the pipeline for timed out flow entries and update port status.
   * \see ofsoftswitch13 function pipeline_timeout () at udatapath/pipeline.c
   * \param dp The datapath.
   */
  void DatapathTimeout (datapath* dp);

  /**
   * Send an echo request message to controller. This method reschedules itself
   * at every m_echo interval, to constantly check the connection between
   * switch and controller.
   */
  void DatapathSendEchoRequest ();
  //\}

  ///\name Port methods
  //\{
  /**
   * Search the switch ports looking for a specific device.
   * \param dev The Ptr<CsmaNetDevice> pointer to device.
   * \return A pointer to the corresponding OfPort.
   */
  Ptr<OfPort> PortGetOfPort (Ptr<NetDevice> dev);

  /**
   * Search the switch ports looking for a specific port number.
   * \param no The port number (starting at 1).
   * \return A pointer to the corresponding OfPort.
   */
  Ptr<OfPort> PortGetOfPort (uint32_t no);

  /**
   * Called when a packet is received on one of the switch's ports. This method
   * will send the packet to the openflow pipeline.
   * \see ofsoftswitch13 function dp_ports_run () at udatapath/dp_ports.c
   * \param netdev The port the packet was received on.
   * \param packet The Packet itself.
   * \param protocol The protocol defining the Packet.
   * \param src The source address of the Packet.
   * \param dst The destination address of the Packet.
   * \param packetType Type of the packet.
   */
  void ReceiveFromSwitchPort (Ptr<NetDevice> netdev, Ptr<const Packet> packet,
                              uint16_t protocol, const Address& src,
                              const Address& dst, PacketType packetType);

  /**
   * Add an Ethernet header and trailer to the packet. This is an workaround
   * to facilitate the creation of the openflow buffer. When the packet gets
   * inside the switch, the Ethernet header has already been removed by
   * CsmaNetDevice::Receive () method on the NetDevice port. So, we are going
   * to include it again to properly buffer the packet. We will remove this
   * header and trailer latter.
   * \attention This method only works for DIX encapsulation mode.
   * \see CsmaNetDevice::AddHeader ().
   * \param packet The packet (will be modified).
   * \param source The L2 source address.
   * \param dest The L2 destination address.
   * \param protocolNumber The L3 protocol defining the packet.
   */
  void AddEthernetHeader (Ptr<Packet> packet, Mac48Address source,
                          Mac48Address dest, uint16_t protocolNumber);
  //\}

  /**
   * \name Socket callbacks
   * Handlers used as socket callbacks to TCP communication between this
   * switch and the controller.
   * \param socket The TCP socket.
   */
  //\{
  /**
   * Receive a openflow packet from controller.
   * \see remote_rconn_run () at udatapath/datapath.c.
   */
  void SocketCtrlRead       (Ptr<Socket> socket);
  void SocketCtrlSucceeded  (Ptr<Socket> socket);   //!< TCP request accepted
  void SocketCtrlFailed     (Ptr<Socket> socket);   //!< TCP request refused
  //\}

  /// NetDevice callbacks
  NetDevice::ReceiveCallback        m_rxCallback;        //!< Receive callback
  NetDevice::PromiscReceiveCallback m_promiscRxCallback; //!< Promiscuous receive callback

  static uint64_t     m_globalDpId;       //!< Global counter of datapath IDs

  uint64_t            m_dpId;             //!< This datapath id
  uint32_t            m_xid;              //!< Transaction idx sequence
  Mac48Address        m_address;          //!< Address of this device
  Ptr<BridgeChannel>  m_channel;          //!< Port channels into the Switch Channel
  Ptr<Node>           m_node;             //!< Node this device is installed on
  Ptr<Socket>         m_ctrlSocket;       //!< Tcp Socket to controller
  Address             m_ctrlAddr;         //!< Controller Address
  uint32_t            m_ifIndex;          //!< Interface Index
  uint16_t            m_mtu;              //!< Maximum Transmission Unit
  Time                m_echo;             //!< Echo request interval
  Time                m_timeout;          //!< Datapath Timeout
  Time                m_lookupDelay;      //!< Flow Table Lookup Delay [overhead].
  datapath*           m_datapath;         //!< The OpenFlow datapath
  Ports_t             m_ports;            //!< Metadata for switch ports

}; // Class OFSwitch13NetDevice
} // namespace ns3
#endif /* OFSWITCH13_NET_DEVICE_H */
