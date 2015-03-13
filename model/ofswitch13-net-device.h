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
#include "ns3/traced-callback.h"

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
typedef std::map<Ptr<const NetDevice>, Ptr<OFPort> > PortDevMap_t;

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
   * TracedCallback signature for sending packets from CsmaNetDevice to OpenFlow pipeline.
   * CsmaNetDevice with OpenFlow datapath.
   * \attention The packet can be modified by the OpenFlow pipeline.
   * \param netdev The underlying CsmaNetDevice switch port.
   * \param packet The packet.
   */
  typedef void (*OpenFlowCallback) 
    (Ptr<NetDevice> netdev, Ptr<Packet> packet);

  /**
   * TracedCallback signature for OpenFlow packets input/output at switch ports.
   * \param packet The Packet.
   * \param port The OpenFlow port.
   */
  typedef void (*PacketPortCallback) 
    (Ptr<const OFPort> port, Ptr<const Packet> packet);

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
   * Send a packet to the controller node.
   * \internal This method is public as the 'C' send_openflow_buffer_to_remote
   * overriding function use this 'C++' member function to send their msgs.
   * \see send_openflow_buffer_to_remote () at udatapath/datapath.c.
   * \attention Don't use this method to directly send messages to controller.
   * Use dp_send_message () instead, as it deals with multiple connections and
   * check assync config.
   * \param packet The ns-3 packet to send.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int SendToController (Ptr<Packet> packet);

  /**
   * Send a message over a specific switch port. Check port configuration,
   * create the ns3 packet, remove the ethernet header and trailer from packet
   * (which will be included again by CsmaNetDevice), send the packet over the
   * proper netdevice, and update port statistics.
   * \internal This method is public as the 'C' dp_ports_output overriding
   * function use this 'C++' member function to send their messages.
   * \param pkt The internal packet to send.
   * \param portNo The port number.
   * \param queueNo The queue number.
   * \return True if success, false otherwise.
   */
  bool SendToSwitchPort (struct packet *pkt, uint32_t portNo, uint32_t queueNo);

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
 
  /**
   * Notify this device of a packet destroyed by the OpenFlow pipeline.
   * \param pkt The ofsoftswitch13 packet.
   */
  void NotifyPacketDestroyed (struct packet *pkt);
  
  /**
   * Notify this device of a packet dropped by OpenFlow meter band.
   * \param pkt The ofsoftswitch13 packet.
   */
  void NotifyDroppedPacket (struct packet *pkt);

  /**
   * Notify this device of a packet saved into buffer. This method will get the
   * ns-3 packet in pipeline and save into buffer map.
   * \param packetUid The ns-3 packet uid.
   */
  void SaveBufferPacket (uint64_t packetUid);
  
  /**
   * Notify this device of a packet retrieved from buffer. This method will get
   * the ns-3 packet from buffer map and put it back into pipeline.
   * \param packetUid The ns-3 packet uid.
   */
  void RetrieveBufferPacket (uint64_t packetUid);

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

  /**
   * Copy all packet and byte tags from srcPkt packet to dstPkt packet. 
   * \attention In the case of byte tags, the tags in dstPkt will cover the
   * entire packet, regardless of the byte range in srcPkt.
   * \param srcPkt The source packet.
   * \param dstPkt The destination packet.
   * \return true if everything's ok, false otherwise. 
   */
  static bool CopyTags (Ptr<const Packet> srcPkt, Ptr<const Packet> dstPkt);

  /**
   * \brief ofsoftswitch13 callbacks.
   */
  //\{
  /**
   * Callback fired when a packet is dropped by meter band
   * \param pkt The original internal packet.
   */
  static void MeterDropCallback (struct packet *pkt);

  /**
   * Callback fired when a packet is destroyed.
   * \param pkt The internal packet destroyed.
   */
  static void PacketDestroyCallback (struct packet *pkt);

  /**
   * Callback fired when a packet is saved into buffer.
   * \param pkt The internal packet saved into buffer.
   * \param timeout The timeout for this packet into buffer.
   */
  static void BufferSaveCallback (struct packet *pkt, time_t timeout);

  /**
   * Callback fired when a packet is retrieved from buffer.
   * \param pkt The internal packet retrieved from buffer.
   */
  static void BufferRetrieveCallback (struct packet *pkt);
  //\}

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
   * will schedule the pipeline for this packet.
   * \see ofsoftswitch13 function dp_ports_run () at udatapath/dp_ports.c
   * \param netdev The port the packet was received on.
   * \param packet The Packet itself.
   */
  void ReceiveFromSwitchPort (Ptr<const NetDevice> netdev, Ptr<Packet> packet);

  /**
   * Send the packet to the OpenFlow ofsoftswitch13 pipeline.
   * \param packet The packet.
   * \param inPort The OpenFlow switch input port.
   */
  void SendToPipeline (Ptr<Packet> packet, Ptr<OFPort> inPort);

  /**
   * Socket callback to receive a openflow packet from controller.
   * \see remote_rconn_run () at udatapath/datapath.c.
   * \param socket The TCP socket.
   */
  void ReceiveFromController (Ptr<Socket> socket);

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


  /**
   * The trace source fired when a packet arrives at a switch port, before
   * being sent to OpenFlow pipeline.
   */
  TracedCallback<Ptr<const Packet>, Ptr<const OFPort> > m_swPortRxTrace; 

  /**
   * The trace source fired when the OpenFlow pipeline sent a packets over a
   * switch port.
   */
  TracedCallback<Ptr<const Packet>, Ptr<const OFPort> > m_swPortTxTrace; 
  
  /**
   * The trace source fired when the OpenFlow pipeline drops a packet due to
   * meter band.
   */
  TracedCallback<Ptr<const Packet> > m_meterDropTrace; 
  

  /** Structure to save packets, indexed by its uid. */
  typedef std::map<uint64_t, Ptr<Packet> > UidPacketMap_t;

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
  Ptr<Packet>     m_pktPipeline;  //!< Packet under switch pipeline.
  UidPacketMap_t  m_pktsBuffer;   //!< Packets saved in switch buffer.

  static uint64_t m_globalDpId;   //!< Global counter of datapath IDs

}; // Class OFSwitch13NetDevice
} // namespace ns3
#endif /* OFSWITCH13_NET_DEVICE_H */
