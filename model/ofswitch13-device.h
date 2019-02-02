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

#ifndef OFSWITCH13_DEVICE_H
#define OFSWITCH13_DEVICE_H

#include <ns3/socket.h>
#include <ns3/uinteger.h>
#include <ns3/inet-socket-address.h>
#include <ns3/string.h>
#include <ns3/tcp-header.h>
#include <ns3/traced-value.h>
#include "ofswitch13-interface.h"
#include "ofswitch13-socket-handler.h"

namespace ns3 {

class OFSwitch13Port;

/**
 * \ingroup ofswitch13
 *
 * An OpenFlow 1.3 device that switches multiple CSMA segments via OpenFlow
 * protocol. It takes a collection of ports, each one associated with a ns-3
 * underlying CsmaNetDevice. The device acts as the intermediary between the
 * ports, receiving a packet from one port and forwarding it to another.
 *
 * The OpenFlow switch datapath implementation (flow tables, group table, and
 * meter table) is provided by the ofsoftswitch13 library. For this reason,
 * packets entering the switch are sent to the library for OpenFlow pipeline
 * processing before being forwarded to the correct output port(s). OpenFlow
 * messages received from the controller are also sent to the library for
 * datapath configuration.
 */
class OFSwitch13Device : public Object
{
private:
  /**
   * \ingroup ofswitch13
   * Inner class to save information of a remote active controller connected to
   * this OpenFlow switch.
   */
  class RemoteController : public SimpleRefCount<RemoteController>
  {
    friend class OFSwitch13Device;

public:
    /** Default (empty) constructor. */
    RemoteController ();

private:
    Ptr<Socket>                   m_socket;   //!< TCP socket to controller.
    Ptr<OFSwitch13SocketHandler>  m_handler;  //!< Socket handler.
    Address                       m_address;  //!< Controller address.
    struct remote*                m_remote;   //!< Library remote struct.
  }; // Class RemoteController

  /**
   * \ingroup ofswitch13
   * Structure to save packet metadata while it is under OpenFlow pipeline.
   * This structure keeps track of packets under OpenFlow pipeline, including
   * the ID for each packet copy (notified by the clone callback). Note that
   * only one packet can be in pipeline at a time, but the packet can have
   * multiple internal copies (each one will receive an unique packet ID), and
   * can also be saved into buffer for latter usage.
   */
  struct PipelinePacket
  {
public:
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

    /**
     * Check for valid packet metadata.
     * \return true when valid packet metadata.
     */
    bool IsValid (void) const;

    /**
     * Notify a new copy for this packet, with a new unique ID.
     * \param id The ns-3 packet id.
     */
    void NewCopy (uint64_t id);

    /**
     * Delete an existing copy for this packet.
     * \param id The ns-3 packet id.
     * \return false when the packet metadata becomes invalid.
     */
    bool DelCopy (uint64_t id);

    /**
     * Check for packet id in the internal list of IDs for this packet.
     * \param id The ns-3 packet id.
     * \return true when the id is associated with this packet.
     */
    bool HasId (uint64_t id);

private:
    bool                  m_valid;  //!< Valid flag.
    Ptr<Packet>           m_packet; //!< Packet pointer.
    std::list<uint64_t>   m_ids;    //!< Internal list of IDs for this packet.
  }; // Struct PipelinePacket

public:
  OFSwitch13Device ();            //!< Default constructor
  virtual ~OFSwitch13Device ();   //!< Dummy destructor, see DoDispose

  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);

  /**
   * Get the OpenFlow datapath ID.
   * \return The datapath ID.
   */
  uint64_t GetDatapathId (void) const;

  /**
   * Alias for the GetDatapathId () method.
   * \return The datapath ID.
   */
  uint64_t GetDpId (void) const;

  /**
   * \name OpenFLow control channel counter accessors.
   * \return The requested value.
   */
  //\{
  uint64_t GetFlowModCounter      (void) const;
  uint64_t GetGroupModCounter     (void) const;
  uint64_t GetMeterModCounter     (void) const;
  uint64_t GetPacketInCounter     (void) const;
  uint64_t GetPacketOutCounter    (void) const;
  //\}

  /**
   * \name Datapath internal accessors.
   * \param tableId The pipeline flow table ID.
   * \return The requested value.
   */
  //\{
  uint32_t GetBufferEntries       (void) const;
  uint32_t GetBufferSize          (void) const;
  double   GetBufferUsage         (void) const;
  DataRate GetCpuCapacity         (void) const;
  DataRate GetCpuLoad             (void) const;
  double   GetCpuUsage            (void) const;
  Time     GetDatapathTimeout     (void) const;
  uint32_t GetDftFlowTableSize    (void) const;
  uint32_t GetFlowTableEntries    (uint8_t tableId) const;
  uint32_t GetFlowTableSize       (uint8_t tableId) const;
  double   GetFlowTableUsage      (uint8_t tableId) const;
  uint32_t GetGroupTableEntries   (void) const;
  uint32_t GetGroupTableSize      (void) const;
  double   GetGroupTableUsage     (void) const;
  uint32_t GetMeterTableEntries   (void) const;
  uint32_t GetMeterTableSize      (void) const;
  double   GetMeterTableUsage     (void) const;
  uint32_t GetNControllers        (void) const;
  uint32_t GetNPipelineTables     (void) const;
  uint32_t GetNSwitchPorts        (void) const;
  Time     GetPipelineDelay       (void) const;
  uint32_t GetSumFlowEntries      (void) const;
  //\}

  /**
   * Get a pointer to the internal ofsoftswitch13 datapath structure.
   * \return The requested pointer.
   */
  struct datapath* GetDatapathStruct ();

  /**
   * Add a 'port' to the switch device. This method adds a new switch port to a
   * OFSwitch13Device, so that the new switch port NetDevice becomes part of
   * the switch and L2 frames start being forwarded to/from this OpenFlow
   * device. The current implementation only supports CsmaNetDevice (for
   * physical ports) or VirtualNetDevice (for logical ports). Keep in mind that
   * an OpenFlow switch expects to receive packets with Ethernet header from
   * port devices).
   * \param portDevice The NetDevice port to add.
   * \return The OFSwitch13Port created.
   */
  Ptr<OFSwitch13Port> AddSwitchPort (Ptr<NetDevice> portDevice);

  /**
   * Get the OFSwitch13Port pointer from its number.
   * \param no The port number (starting at 1).
   * \return A pointer to the corresponding OFSwitch13Port.
   */
  Ptr<OFSwitch13Port> GetSwitchPort (uint32_t no) const;

  /**
   * Called when a packet is received on one of the switch's ports. This method
   * will schedule the packet for OpenFlow pipeline.
   * \param packet The packet.
   * \param portNo The switch input port number.
   * \param tunnelId The metadata associated with a logical port.
   */
  void ReceiveFromSwitchPort (Ptr<Packet> packet, uint32_t portNo,
                              uint64_t tunnelId = 0);

  /**
   * Starts the TCP connection between this switch and the target controller
   * indicated by the address parameter.
   * \param ctrlAddr The controller address used to open the connection.
   */
  void StartControllerConnection (Address ctrlAddr);

  /**
   * Overriding ofsoftswitch13 send_packet_to_controller weak function
   * from udatapath/pipeline.c. Sends the given packet to controller(s) in a
   * packet_in message.
   * \internal
   * This function relies on the global map that stores OpenFlow devices to
   * call the method on the correct object.
   * \param pl The pipeline structure.
   * \param pkt The internal packet to send.
   * \param tableId ID of the table that was looked up.
   * \param reason Reason packet is being sent (on of OFPR_*).
   */
  static void
  SendPacketToController (struct pipeline *pl, struct packet *pkt,
                          uint8_t tableId, uint8_t reason);

  /**
   * Overriding ofsoftswitch13 send_openflow_buffer_to_remote weak function
   * from udatapath/datapath.c. Sends the given OFLib buffer message to the
   * controller associated with remote connection structure.
   * \internal
   * This function relies on the global map that stores OpenFlow devices to
   * call the method on the correct object.
   * \param buffer The message buffer to send.
   * \param remote The remote controller connection information.
   * \return 0 if everything's ok, otherwise an error number.
   */
  static int
  SendOpenflowBufferToRemote (struct ofpbuf *buffer, struct remote *remote);

  /**
   * Overriding ofsoftswitch13 dp_actions_output_port weak function from
   * udatapath/dp_actions.c. Outputs a datapath packet on switch port. This
   * code is nearly the same on ofsoftswitch, but it gets the openflow device
   * from datapath id and uses member functions to send the packet over ns3
   * structures.
   * \internal
   * This function relies on the global map that stores OpenFlow devices to
   * call the method on the correct object.
   * \param pkt The internal packet to send.
   * \param outPort The output switch port number.
   * \param outQueue The output queue number.
   * \param maxLength Max length of packet to send to controller.
   * \param cookie Packet cookie to send to controller.
   */
  static void
  DpActionsOutputPort (struct packet *pkt, uint32_t outPort, uint32_t outQueue,
                       uint16_t maxLength, uint64_t cookie);

  /**
   * Callback fired when a new meter entry is created at meter table.
   * \param entry The new created meter entry.
   */
  static void
  MeterCreatedCallback (struct meter_entry *entry);

  /**
   * Callback fired when a packet is dropped by meter band.
   * \param pkt The original internal packet.
   * \param entry The meter entry that dropped the packet.
   */
  static void
  MeterDropCallback (struct packet *pkt, struct meter_entry *entry);

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

  /**
   * Retrieve and existing OpenFlow device object by its datapath ID.
   * \param id The datapath ID.
   * \return The OpenFlow OFSwitch13Device pointer.
   */
  static Ptr<OFSwitch13Device> GetDevice (uint64_t id);

  /**
   * TracedCallback signature for packets dropped by meter bands.
   * \param packet The dropped packet.
   * \param meterId The meter entry ID that dropped the packet.
   */
  typedef void (*MeterDropTracedCallback)(
    Ptr<const Packet> packet, uint32_t meterId);

  /**
   * TracedCallback signature for OpenFlow switch device.
   * \param deve The OpenFlow switch device pointer.
   */
  typedef void (*DeviceTracedCallback)(Ptr<const OFSwitch13Device> dev);

protected:
  // Inherited from Object
  virtual void DoDispose (void);

  // Inherited from ObjectBase.
  virtual void NotifyConstructionCompleted (void);

private:
  /**
   * Creates a new datapath.
   * \return The created datapath.
   * \see ofsoftswitch dp_new () at udatapath/datapath.c
   */
  struct datapath* DatapathNew ();

  /**
   * \name Adjust OpenFlow switch table sizes.
   * \param tableId The pipeline flow table ID.
   * \param value The value to set.
   */
  //\{
  void SetFlowTableSize     (uint8_t tableId, uint32_t value);
  void SetDftFlowTableSize  (uint32_t value);
  void SetGroupTableSize    (uint32_t value);
  void SetMeterTableSize    (uint32_t value);
  //\}

  /**
   * Check if any flow in any table is timed out and update port status. This
   * method reschedules itself at every m_timout interval, to constantly check
   * the pipeline for timed out flow entries and update port status.
   * \see ofsoftswitch13 function pipeline_timeout () at udatapath/pipeline.c
   * \param dp The datapath.
   */
  void DatapathTimeout (struct datapath *dp);

  /**
   * Create an OpenFlow packet in message and send the packet to all
   * controllers with open connections.
   * \param pkt The internal packet to send.
   * \param tableId ID of the table that was looked up.
   * \param reason Reason packet is being sent (on of OFPR_*).
   * \param maxLength Max length of packet to send to controller.
   * \param cookie Packet cookie to send to controller.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int SendPacketInMessage (struct packet *pkt, uint8_t tableId,
                           uint8_t reason, uint16_t maxLength,
                           uint64_t cookie = 0);

  /**
   * Send a message over a specific switch port. Check port configuration,
   * get the ns-3 packet and send the packet over the proper OpenFlow port.
   * \see DpActionsOutputPort ().
   * \param pkt The internal packet to send.
   * \param portNo The port number.
   * \param queueNo The queue number.
   * \return True if success, false otherwise.
   */
  bool SendToSwitchPort (struct packet *pkt, uint32_t portNo,
                         uint32_t queueNo = 0);

  /**
   * Send the packet to the OpenFlow ofsoftswitch13 pipeline.
   * \param packet The packet.
   * \param portNo The switch input port number.
   * \param tunnelId The metadata associated with a logical port.
   */
  void SendToPipeline (Ptr<Packet> packet, uint32_t portNo,
                       uint64_t tunnelId = 0);

  /**
   * Send a packet to the controller node.
   * \see SendOpenflowBufferToRemote ().
   * \attention Don't use this method to directly send messages to controller.
   * Use dp_send_message () instead, as it deals with multiple connections and
   * check async config.
   * \param packet The ns-3 packet to send.
   * \param remoteCtrl The remote controller object to send the packet.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int SendToController (Ptr<Packet> packet,
                        Ptr<OFSwitch13Device::RemoteController> remoteCtrl);

  /**
   * Receive an OpenFlow packet from controller.
   * \see remote_rconn_run () at udatapath/datapath.c.
   * \param packet The packet with the OpenFlow message.
   * \param from The packet sender address.
   */
  void ReceiveFromController (Ptr<Packet> packet, Address from);

  /**
   * Create an OpenFlow error message and send it back to the sender
   * controller. This function is used only when an error occurred while
   * processing an OpenFlow message received from the controller.
   * \param error The error code.
   * \param buffer The message buffer that originated the error.
   * \param senderCtrl The origin of a received OpenFlow message.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int ReplyWithErrorMessage (ofl_err error, struct ofpbuf *buffer,
                             struct sender *senderCtrl);

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
   * Notify this device of a new meter entry created at meter table. This is
   * used to update the initial number of tokens for this meter. Doing this, we
   * avoid the problem of discarding the initial packets before the next
   * datapath timeout.
   * \param entry The new created meter entry.
   */
  void NotifyMeterEntryCreated (struct meter_entry *entry);

  /**
   * Notify this device of a packet cloned by the OpenFlow pipeline.
   * \param pkt The original ofsoftswitch13 packet.
   * \param clone The cloned ofsoftswitch13 packet.
   */
  void NotifyPacketCloned (struct packet *pkt, struct packet *clone);

  /**
   * Notify this device of a packet destroyed by the OpenFlow pipeline.
   * \param pkt The ofsoftswitch13 packet.
   */
  void NotifyPacketDestroyed (struct packet *pkt);

  /**
   * Notify this device of a packet dropped by OpenFlow meter band.
   * \param pkt The ofsoftswitch13 packet.
   * \param entry The meter entry that dropped the packet.
   */
  void NotifyPacketDroppedByMeter (struct packet *pkt,
                                   struct meter_entry *entry);

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
   * Get the remote controller for this socket.
   * \param socket The connection socket.
   * \return The remote controller.
   */
  Ptr<OFSwitch13Device::RemoteController>
  GetRemoteController (Ptr<Socket> socket);

  /**
   * Get the remote controller for this address.
   * \param address The socket address.
   * \return The remote controller.
   */
  Ptr<OFSwitch13Device::RemoteController>
  GetRemoteController (Address address);

  /**
   * Get the remote controller for this ofsoftswitch13 remote pointer.
   * \param remote The ofsoftswitch13 remote pointer.
   * \return The remote controller.
   */
  Ptr<OFSwitch13Device::RemoteController>
  GetRemoteController (struct remote *remote);

  /**
   * Increase the global packet ID counter and return a new packet ID. This ID
   * is different from the internal ns3::Packet::GetUid (), as we need an
   * unique value even for fragmented or brodcast packets. Its usage is
   * restricted to this device.
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
   * \param dev The Ptr<OFSwitch13Device> pointer.
   */
  static void RegisterDatapath (uint64_t id, Ptr<OFSwitch13Device> dev);

  /**
   * Remove an existing OpenFlow device from global map. Called by DoDispose.
   * \param id The datapath id.
   */
  static void UnregisterDatapath (uint64_t id);

  /** Structure to save the list of ports in this datapath. */
  typedef std::vector<Ptr<OFSwitch13Port> > PortList_t;

  /** Structure to save the list of active controllers. */
  typedef std::vector<Ptr<OFSwitch13Device::RemoteController> > CtrlList_t;

  /** Structure to map datapath id to OpenFlow device. */
  typedef std::map<uint64_t, Ptr<OFSwitch13Device> > DpIdDevMap_t;

  /** Structure to save packets, indexed by its id. */
  typedef std::map<uint64_t, Ptr<Packet> > IdPacketMap_t;

  /** Trace source fired when a packet in buffer expires. */
  TracedCallback<Ptr<const Packet> > m_bufferExpireTrace;

  /** Trace source fired when a packet is retrieved from buffer. */
  TracedCallback<Ptr<const Packet> > m_bufferRetrieveTrace;

  /** Trace source fired when a packet is saved into buffer. */
  TracedCallback<Ptr<const Packet> > m_bufferSaveTrace;

  /** Trace source fired when the datapath timeout operation is completed. */
  TracedCallback<Ptr<const OFSwitch13Device> > m_datapathTimeoutTrace;

  /** Trace source fired when a packet is dropped due to overloaded switch. */
  TracedCallback<Ptr<const Packet> > m_loadDropTrace;

  /** Trace source fired when a packet is dropped by a meter band. */
  TracedCallback<Ptr<const Packet>, uint32_t> m_meterDropTrace;

  /** Trace source fired when a packet is sent to pipeline. */
  TracedCallback<Ptr<const Packet> > m_pipePacketTrace;

  /** Number of entries in group table. */
  TracedValue<uint32_t> m_groupEntries;

  /** Number of entries in meter table. */
  TracedValue<uint32_t> m_meterEntries;

  /** Sum of entries in all flow tables. */
  TracedValue<uint32_t> m_sumFlowEntries;

  /** Average delay for pipeline packet processing. */
  TracedValue<Time> m_pipeDelay;

  /** Average CPU processing load. */
  TracedValue<DataRate> m_cpuLoad;

  uint64_t          m_dpId;         //!< This datapath id.
  Time              m_timeout;      //!< Datapath timeout interval.
  Time              m_lastTimeout;  //!< Datapath last timeout.
  Time              m_tcamDelay;    //!< Flow Table TCAM lookup delay.
  std::string       m_libLog;       //!< The ofsoftswitch13 library log level.
  struct datapath*  m_datapath;     //!< ofsoftswitch13 datapath structure.
  PortList_t        m_ports;        //!< List of switch ports.
  CtrlList_t        m_controllers;  //!< Collection of active controllers.
  uint32_t          m_flowTabSize;  //!< Flow table maximum entries.
  uint32_t          m_groupTabSize; //!< Group table maximum entries.
  uint32_t          m_meterTabSize; //!< Meter table maximum entries.
  uint32_t          m_numPipeTabs;  //!< Number of pipeline flow tables.
  IdPacketMap_t     m_bufferPkts;   //!< Packets saved in switch buffer.
  uint32_t          m_bufferSize;   //!< Buffer size in terms of packets.
  PipelinePacket    m_pipePkt;      //!< Packet under switch pipeline.
  DataRate          m_cpuCapacity;  //!< CPU processing capacity.
  uint64_t          m_cpuConsumed;  //!< CPU processing tokens consumed.
  uint64_t          m_cpuTokens;    //!< CPU processing tokens available.
  uint64_t          m_cFlowMod;     //!< Pipeline flow mod counter.
  uint64_t          m_cGroupMod;    //!< Pipeline group mod counter.
  uint64_t          m_cMeterMod;    //!< Pipeline meter mod counter.
  uint64_t          m_cPacketIn;    //!< Pipeline packet in counter.
  uint64_t          m_cPacketOut;   //!< Pipeline packet out counter.

  static uint64_t   m_globalDpId;   //!< Global counter for datapath IDs.
  static uint64_t   m_globalPktId;  //!< Global counter for packets IDs.

  /**
   * As the integration of ofsoftswitch13 and ns-3 involve overriding some C
   * functions, we are using a global map to store a pointer to all
   * OFSwitch13Device objects in simulation, and allow faster object retrieve
   * by datapath id. In this way, static functions like
   * SendOpenflowBufferToRemote, DpActionsOutputPort, and other callbacks can
   * get the object pointer and call member functions.
   */
  static DpIdDevMap_t m_globalSwitchMap;

}; // Class OFSwitch13Device

} // namespace ns3
#endif /* OFSWITCH13_DEVICE_H */
