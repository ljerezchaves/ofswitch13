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
class OFPort : public SimpleRefCount<OFPort>
{
  friend class OFSwitch13NetDevice;

public:
  /**
   * Create and populate a new datapath port.
   * \see ofsoftswitch new_port () at udatapath/dp_ports.c
   * \param dp The datapath.
   * \param dev The swith port ns3::NetDevice.
   */
  OFPort (datapath *dp, Ptr<NetDevice> dev);

  /** Default destructor */
  ~OFPort ();

private:
  /**
   * Create the bitmaps of OFPPF_* describing port features, based on
   * ns3::NetDevice.
   * \see ofsoftswitch netdev_get_features () at lib/netdev.c
   * \return Port features bitmap.
   */
  uint32_t PortGetFeatures ();

  /**
   * Update the port state field based on netdevice status.
   * \return true if the state of the port has changed, false otherwise.
   */
  bool PortUpdateState ();

  uint32_t       m_portNo; //!< Port number
  Ptr<NetDevice> m_netdev; //!< Pointer to ns3::NetDevice
  sw_port*       m_swPort; //!< Pointer to datapath sw_port
};

/** Structure to map port number to port information. */
typedef std::map<uint32_t, Ptr<OFPort> > PortNoMap_t;

/** Structure to map NetDevice to port information. */
typedef std::map<Ptr<NetDevice>, Ptr<OFPort> > PortDevMap_t;

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
   * TracedCallback signature for Ptr<NetDevice> and Ptr<Packet>, used to link
   * CsmaNetDevice with OpenFlow datapath. 
   */
  typedef void (* TracedCallback) 
    (Ptr<NetDevice>, const Ptr<const Packet> packet);

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
    * \attention The current implementation only supports CsmaNetDevices (as
    * OpenFlow deals with ethernet frames). Also, the port device that is being
    * added as switch port must _not_ have an IP address.
    * \param portDevice The NetDevice port to add.
    * \return 0 in case of errors, otherwise the port number (>= 1).
    */
  uint32_t AddSwitchPort (Ptr<NetDevice> portDevice);

  /**
   * Send a message to the controller node.
   * \internal This method is public as the 'C' send_openflow_buffer_to_remote
   * overriding function use this 'C++' member function to send their msgs.
   * \see send_openflow_buffer_to_remote () at udatapath/datapath.c.
   * \attention Don't use this method to send messages to controller. Use
   * dp_send_message () instead, as it deals with multiple connections and
   * check assync config.
   * \param buffer The message buffer to send.
   * \param remote The controller connection information.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int SendToController (ofpbuf *buffer, remote *remote);

  /**
   * Send a message over a specific switch port. Check port configuration,
   * create the ns3 packet, remove the ethernet header and trailer from packet
   * (which will be included again by CsmaNetDevice), send the packet over the
   * proper netdevice, and update port statistics.
   * \internal This method is public as the 'C' dp_ports_output overriding
   * function use this 'C++' member function to send their messages.
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
   * Set the logging level of ofsoftswitch13 library.
   * \param log String representing library logging level.
   */
  void SetLibLogLevel (std::string log);

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
   * Search the switch ports looking for a specific port number.
   * \param no The port number (starting at 1).
   * \return A pointer to the corresponding OFPort.
   */
  Ptr<OFPort> PortGetOFPort (uint32_t no);

  /**
   * Called when a packet is received on one of the switch's ports. This method
   * will send the packet to the openflow pipeline.
   * \see ofsoftswitch13 function dp_ports_run () at udatapath/dp_ports.c
   * \param netdev The port the packet was received on.
   * \param packet The Packet itself.
   */
  void ReceiveFromSwitchPort (Ptr<NetDevice> netdev, Ptr<const Packet> packet);

  /**
   * Socket callback to receive a openflow packet from controller.
   * \see remote_rconn_run () at udatapath/datapath.c.
   * \param socket The TCP socket.
   */
  void SocketCtrlRead (Ptr<Socket> socket);

  /**
   * Socket callback fired when a TCP connection to controller succeeds fail.
   * \param socket The TCP socket.
   */
  void SocketCtrlSucceeded (Ptr<Socket> socket);

  /**
   * Socket callback fired when a TCP connection fail.
   * \param socket The TCP socket.
   */
  void SocketCtrlFailed (Ptr<Socket> socket);

  uint64_t        m_dpId;         //!< This datapath id
  Ptr<Node>       m_node;         //!< Node this device is installed on
  Ptr<Socket>     m_ctrlSocket;   //!< Tcp Socket to controller
  Address         m_ctrlAddr;     //!< Controller Address
  uint32_t        m_ifIndex;      //!< NetDevice Interface Index
  Time            m_timeout;      //!< Datapath Timeout
  Time            m_lookupDelay;  //!< Flow Table Lookup Delay overhead.
  std::string     m_libLog;       //!< The ofsoftswitch13 library logging levels.
  datapath*       m_datapath;     //!< The OpenFlow datapath
  PortNoMap_t     m_portsByNo;    //!< Switch ports indexed by port number.
  PortDevMap_t    m_portsByDev;   //!< Switch ports indexed by NetDevice.

  static uint64_t m_globalDpId;   //!< Global counter of datapath IDs

}; // Class OFSwitch13NetDevice
} // namespace ns3
#endif /* OFSWITCH13_NET_DEVICE_H */
