/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2015 University of Campinas (Unicamp)
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

#ifndef OFSWITCH13_NET_DEVICE_H
#define OFSWITCH13_NET_DEVICE_H

#include "ns3/socket.h"
#include "ns3/uinteger.h"
#include "ns3/inet-socket-address.h"
#include "ns3/string.h"
#include "ns3/tcp-header.h"
#include "ofswitch13-interface.h"
#include "ofswitch13-port.h"

namespace ns3 {

class OFSwitch13Port;

/**
 * \ingroup ofswitch13
 *
 * A NetDevice that switches multiple LAN segments via OpenFlow protocol.
 * The OFSwitch13NetDevice object aggregates multiple netdevices as ports
 * and acts like a switch. It implements OpenFlow datapath compatibility,
 * according to the OpenFlow Switch Specification v1.3.
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
   * \attention The current implementation only supports CsmaNetDevices (as
   * OpenFlow deals with ethernet frames). Also, the port device that is being
   * added as switch port must _not_ have an IP address.
   * \param portDevice The NetDevice port to add.
   * \return The OFSwitch13Port created.
   */
  Ptr<OFSwitch13Port> AddSwitchPort (Ptr<NetDevice> portDevice);

  /**
   * Called when a packet is received on one of the switch's ports. This method
   * will schedule the packet for OpenFlow pipeline.
   * \param packet The packet.
   * \param portNo The switch input port number.
   */
  void ReceiveFromSwitchPort (Ptr<Packet> packet, uint32_t portNo);

  /**
   * \return Number of switch ports attached to this switch.
   */
  uint32_t GetNSwitchPorts (void) const;

  /**
   * \return The datapath ID.
   */
  uint64_t GetDatapathId (void) const;

  /**
   * \return The current number of flow entries in all pipeline tables.
   */
  uint32_t GetNumberFlowEntries (void) const;

  /**
   * \param tid Table id.
   * \return The current number of flow entries at a specific table.
   */
  uint32_t GetNumberFlowEntries (size_t tid) const;

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
   * Get a pointer to the collection of output queues at a specific port on
   * this switch.
   * \param portNo The switch output port number.
   * \return The queue pointer.
   */
  Ptr<OFSwitch13Queue> GetOutputQueue (uint32_t portNo);

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
  // Inherited from NetDevice base class

  /**
   * Overriding ofsoftswitch13 send_openflow_buffer_to_remote weak function
   * from udatapath/datapath.c. Sends the given OFLib buffer message to the
   * controller associated with remote connection structure.
   * \internal This function relies on the global map that stores OpenFlow
   * devices to call the method on the correct object.
   * \param buffer The message buffer to send.
   * \param ctrl The controller connection information.
   * \return 0 if everything's ok, error number otherwise.
   */
  static int
  SendOpenflowBufferToRemote (ofpbuf *buffer, remote *ctrl);

  /**
   * Overriding ofsoftswitch13 dp_actions_output_port weak function from
   * udatapath/dp_actions.c. Outputs a datapath packet on switch port. This
   * code is nearly the same on ofsoftswitch, but it gets the openflow device
   * from datapath id and uses member functions to send the packet over ns3
   * structures.
   * \internal This function relies on the global map that stores OpenFlow
   * devices to call the method on the correct object.
   * \param pkt The internal packet to send.
   * \param outPort The output switch port number.
   * \param outQueue The output queue number.
   * \param maxLen Max length of packet to send to controller.
   * \param cookie Packet cookie to send to controller.
   */
  static void
  DpActionsOutputPort (struct packet *pkt, uint32_t outPort,
                       uint32_t outQueue, uint16_t maxLen, uint64_t cookie);

  /**
   * Callback fired when a packet is dropped by meter band
   * \param pkt The original internal packet.
   */
  static void
  MeterDropCallback (struct packet *pkt);

  /**
   * Callback fired when a packet is cloned.
   * \param pkt The internal original packet.
   * \param clone The internal cloned packet.
   */
  static void
  PacketCloneCallback (struct packet *pkt, struct packet *clone);

  /**
   * Callback fired when a packet is destroyed.
   * \param pkt The internal packet destroyed.
   */
  static void
  PacketDestroyCallback (struct packet *pkt);

  /**
   * Callback fired when a packet is saved into buffer.
   * \param pkt The internal packet saved into buffer.
   * \param timeout The timeout for this packet into buffer.
   */
  static void
  BufferSaveCallback (struct packet *pkt, time_t timeout);

  /**
   * Callback fired when a packet is retrieved from buffer.
   * \param pkt The internal packet retrieved from buffer.
   */
  static void
  BufferRetrieveCallback (struct packet *pkt);

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
   * Get the OFSwitch13Port pointer from its number.
   * \param no The port number (starting at 1).
   * \return A pointer to the corresponding OFSwitch13Port.
   */
  Ptr<OFSwitch13Port> GetOFSwitch13Port (uint32_t no);

  /**
   * Send a message over a specific switch port. Check port configuration,
   * get the ns-3 packet and send the packet over the proper OpenFlow port.
   * \see DpActionsOutputPort ().
   * \param pkt The internal packet to send.
   * \param portNo The port number.
   * \param queueNo The queue number.
   * \return True if success, false otherwise.
   */
  bool SendToSwitchPort (struct packet *pkt, uint32_t portNo, uint32_t queueNo);

  /**
   * Send the packet to the OpenFlow ofsoftswitch13 pipeline.
   * \param packet The packet.
   * \param portNo The switch input port number.
   */
  void SendToPipeline (Ptr<Packet> packet, uint32_t portNo);

  /**
   * Send a packet to the controller node.
   * \see SendOpenflowBufferToRemote ().
   * \attention Don't use this method to directly send messages to controller.
   * Use dp_send_message () instead, as it deals with multiple connections and
   * check async config.
   * \param packet The ns-3 packet to send.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int SendToController (Ptr<Packet> packet);

  /**
   * Socket callback to receive a openflow packet from controller.
   * \see remote_rconn_run () at udatapath/datapath.c.
   * \param socket The TCP socket.
   */
  void ReceiveFromController (Ptr<Socket> socket);

  /**
   * Socket callback fired when a TCP connection to controller succeed.
   * \param socket The TCP socket.
   */
  void SocketCtrlSucceeded (Ptr<Socket> socket);

  /**
   * Socket callback fired when a TCP connection to controller fail.
   * \param socket The TCP socket.
   */
  void SocketCtrlFailed (Ptr<Socket> socket);

  /**
   * Notify this device of a packet cloned by the OpenFlow pipeline.
   * \param pkt The original ofsoftswitch13 packet.
   * \param clone The cloned ofsoftswitch13 packet.
   */
  void NotifyPacketCloned (struct packet *pkt, struct packet *cloned);

  /**
   * Notify this device of a packet destroyed by the OpenFlow pipeline.
   * \param pkt The ofsoftswitch13 packet.
   */
  void NotifyPacketDestroyed (struct packet *pkt);

  /**
   * Notify this device of a packet dropped by OpenFlow meter band.
   * \param pkt The ofsoftswitch13 packet.
   */
  void NotifyPacketDropped (struct packet *pkt);

  /**
   * Notify this device of a packet saved into buffer. This method will get the
   * ns-3 packet in pipeline and save into buffer map.
   * \param packetId The ns-3 packet id.
   * \param timeout The buffer timeout.
   */
  void BufferPacketSave (uint64_t packetId, time_t timeout);

  /**
   * Notify this device of a packet retrieved from buffer. This method will get
   * the ns-3 packet from buffer map and put it back into pipeline.
   * \param packetId The ns-3 packet id.
   */
  void BufferPacketRetrieve (uint64_t packetId);

  /**
   * Delete the ns-3 packet from buffer map.
   * \param packetId The ns-3 packet id.
   */
  void BufferPacketDelete (uint64_t packetId);

  /**
   * Increase the global packet ID counter and return a new packet ID. This ID
   * is different from the internal ns3::Packet::GetUid (), as we need an
   * unique value even for fragmented or brodcast packets. Its usage is
   * restricted to this NetDevice.
   * \return New unique ID for this packet.
   */
  static uint64_t GetNewPacketId ();

  /**
   * Copy all tags (packet and byte) from srcPkt packet to dstPkt packet.
   * \attention In the case of byte tags, the tags in dstPkt will cover the
   * entire packet, regardless of the byte range in srcPkt.
   * \param srcPkt The source packet.
   * \param dstPkt The destination packet.
   * \return true if everything's ok, false otherwise.
   */
  static bool CopyTags (Ptr<const Packet> srcPkt, Ptr<const Packet> dstPkt);

  /**
   * Insert a new OpenFlow device in global map. Called by device constructor.
   * \param id The datapath id.
   * \param dev The Ptr<OFSwitch13NetDevice> pointer.
   */
  static void RegisterDatapath (uint64_t id, Ptr<OFSwitch13NetDevice> dev);

  /**
   * Remove an existing OpenFlow device from global map. Called by DoDispose.
   * \param id The datapath id.
   */
  static void UnregisterDatapath (uint64_t id);

  /**
   * Retrieve and existing OpenFlow device object by its datapath id
   * \param id The datapath id.
   * \return The OpenFlow OFSwitch13NetDevice pointer.
   */
  static Ptr<OFSwitch13NetDevice> GetDatapathDevice (uint64_t id);

  /** Trace source fired when the OpenFlow meter band drops a packet */
  TracedCallback<Ptr<const Packet> > m_meterDropTrace;

  /**
   * \ingroup ofswitch13
   * Structure to save packet metadata while it is under OpenFlow pipeline.
   * This structure keeps track of packets under OpenFlow pipeline, including
   * the ID for each packet copy (notified by the clone callback). Note that
   * only one packet can be in pipeline at a time, but the packet can have
   * multiple internal copies (which one will receive an unique packet ID), and
   * can also be saved into buffer for later usage.
   */
  struct PipelinePacket
  {
    /** Default (empty) constructor. */
    PipelinePacket ();

    /**
     * Save packet metadata.
     * \param id Packet unique ID.
     * \param packet The packet pointer.
     */
    void SetPacket (uint64_t id, Ptr<Packet> packet);

    /** \return The packet pointer. */
    Ptr<Packet> GetPacket (void) const;

    /** Invalidate packet metatada.*/
    void Invalidate (void);

    /** \return true when valid packet metadata. */
    bool IsValid (void) const;

    /** Notify a new copy for this packet, with a new unique ID. */
    void NewCopy (uint64_t id);

    /**
     * Delete an existing copy for this packet.
     * \return false when the packet metadata becomes invalid.
     */
    bool DelCopy (uint64_t id);

    /** \return true when the id is associated with this packet */
    bool HasId (uint64_t id);

  private:
    bool                  m_valid;  //!< Valid flag.
    Ptr<Packet>           m_packet; //!< Packet pointer.
    std::vector<uint64_t> m_ids;    //!< Internal list of IDs for this packet.
  };

  /** Structure to map port number to port information. */
  typedef std::map<uint32_t, Ptr<OFSwitch13Port> > PortNoMap_t;

  /** Structure to map datapath id to OpenFlow device. */
  typedef std::map<uint64_t, Ptr<OFSwitch13NetDevice> > DpIdDevMap_t;

  /** Structure to save packets, indexed by its id. */
  typedef std::map<uint64_t, Ptr<Packet> > IdPacketMap_t;

  uint64_t        m_dpId;         //!< This datapath id
  Ptr<Node>       m_node;         //!< Node this device is installed on
  Ptr<Socket>     m_ctrlSocket;   //!< Tcp Socket to controller
  Address         m_ctrlAddr;     //!< Controller Address
  uint32_t        m_ifIndex;      //!< NetDevice Interface Index
  Time            m_timeout;      //!< Datapath Timeout
  Time            m_tcamDelay;    //!< Flow Table TCAM lookup delay.
  Time            m_pipeDelay;    //!< Flow Table average delay.
  std::string     m_libLog;       //!< The ofsoftswitch13 library logging levels.
  datapath*       m_datapath;     //!< The OpenFlow datapath
  PipelinePacket  m_pktPipe;      //!< Packet under switch pipeline.
  PortNoMap_t     m_portsByNo;    //!< Switch ports indexed by port number.
  IdPacketMap_t   m_pktsBuffer;   //!< Packets saved in switch buffer.

  static uint64_t m_globalDpId;   //!< Global counter of datapath IDs
  static uint64_t m_globalPktId;  //!< Global counter for packets IDs

  /**
   * As the integration of ofsoftswitch13 and ns-3 involve overriding some C
   * functions, we are using a global map to store a pointer to all
   * OFSwitch13NetDevices objects in simulation, and allow faster object
   * retrieve by datapath id. In this way, static functions like
   * SendOpenflowBufferToRemote, DpActionsOutputPort, and other callbacks can
   * get the object pointer and call member functions.
   */
  static DpIdDevMap_t m_globalSwitchMap;

}; // Class OFSwitch13NetDevice

} // namespace ns3
#endif /* OFSWITCH13_NET_DEVICE_H */
