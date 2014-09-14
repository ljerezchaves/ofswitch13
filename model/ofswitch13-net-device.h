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

#include "ns3/object.h"
#include "ns3/net-device.h"
#include "ns3/mac48-address.h"
#include "ns3/bridge-channel.h"
#include "ns3/csma-net-device.h"
#include "ns3/node.h"
#include "ns3/packet.h"

#include "ofswitch13-interface.h"
#include "ofswitch13-controller.h"

namespace ns3 {

class OFSwitch13Controller;

/**
 * \ingroup ofswitch13
 *
 * \brief A NetDevice that switches multiple LAN segments via OpenFlow protocol 
 *
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

//friend class OFSwitch13Controller;

public:
  static TypeId GetTypeId (void);

  OFSwitch13NetDevice ();
  virtual ~OFSwitch13NetDevice ();
  
  /**
   * \name OFSwitch13NetDevice Description Data
   * \brief These four data describe the OFSwitch13NetDevice as if it were
   * a real OpenFlow switch.
   *
   * There is a type of stats request that OpenFlow switches are supposed to
   * handle that returns the description of the OpenFlow switch. Currently
   * manufactured by "The ns-3 team", software description is "Simulated
   * OpenFlow Switch datapath version 1.3", hardware description is "N/A",
   * serial number is 1, and datapath description is "N/A".
   */
  //\{
  static const char * GetManufacturerDescription ();
  static const char * GetHardwareDescription ();
  static const char * GetSoftwareDescription ();
  static const char * GetSerialNumber ();
  static const char * GetDatapathDescrtiption ();
  //\}

 /**
   * \brief Add a 'port' to the switch device
   *
   * This method adds a new switch port to a OFSwitch13NetDevice, so that the
   * new switch port NetDevice becomes part of the switch and L2 frames start
   * being forwarded to/from this NetDevice.
   * 
   * \attention The current implementation only supports CsmaNetDevices using
   * DIX encapsulation.
   *
   * \attention The csmaNetDevice that is being added as switch port must _not_
   * have an IP address.
   *
   * \param switchPort The NetDevice port to add.
   * \return 0 if everything's ok, otherwise an error number.
   * \sa #EXFULL
   */
  int AddSwitchPort (Ptr<NetDevice> switchPort);

  /**
   * \return Number of switch ports attached to this switch.
   */
  uint32_t GetNSwitchPorts (void) const;

  /**
   * \brief Set up the TCP connection between switch and controller.
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
  virtual bool SendFrom (Ptr<Packet> packet, const Address& source, const Address& dest, uint16_t protocolNumber);
  virtual Ptr<Node> GetNode (void) const;
  virtual void SetNode (Ptr<Node> node);
  virtual bool NeedsArp (void) const;
  virtual void SetReceiveCallback (NetDevice::ReceiveCallback cb);
  virtual void SetPromiscReceiveCallback (NetDevice::PromiscReceiveCallback cb);
  virtual bool SupportsSendFrom () const;

private:
  virtual void DoDispose (void);

  ///\name Port methods
  //\{
  /**
   * \brief Search the switch ports looking for a specific device
   *
   * \param sed The Ptr<CsmaNetDevice> pointer to device.
   * \return A pointer to the corresponding ofs::Port.
   */
  ofs::Port* PortGetOfsPort (Ptr<NetDevice> dev);

  /**
   * \brief Search the switch ports looking for a specific port number
   *
   * \param no The port number (starting at 1) 
   * \return A pointer to the corresponding ofs::Port.
   */
  ofs::Port* PortGetOfsPort (uint32_t no);

  /**
   * \internal
   * Update the port status field of the switch port. A non-zero return value
   * indicates some field has changed.
   *
   * \param p Port to update its config and flag fields.
   * \return true 0 if unchanged, any value otherwise.
   */
  int PortUpdateStatus (ofs::Port *p);
  //\}


  ///\name Send/Receive methods
  //\{
  /**
   * \brief Called by the HandleRead when a packet is received from the
   * controller.
   * \see remote_rconn_run () at udatapath/dp_control.c
   * \see handle_control_msg () at udatapath/dp_control.c
   *
   * \param msg The message (ofpbuf) received from the controller.
   * \param length Length of the message.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int ReceiveFromController (ofpbuf* buffer);
 
  /**
   * \brief Send a message to the controller. 
   *
   * This method is the key to communicating with the controller, it does the
   * actual sending. The other Send methods call this one when they are ready
   * to send the packet.
   *
   * \param packet The packet to send
   * \return The number of bytes transmitted
   */
  int SendToController (Ptr<Packet> packet);

  /**
   * Called when a packet is received on one of the switch's ports. This method
   * will send the packet to the openflow pipeline.
   * \see ofsoftswitch13 function dp_ports_run () at udatapath/dp_ports.c 
   *
   * \param netdev The port the packet was received on.
   * \param packet The Packet itself.
   * \param protocol The protocol defining the Packet.
   * \param src The source address of the Packet.
   * \param dst The destination address of the Packet.
   * \param PacketType Type of the packet.
   */
  void ReceiveFromSwitchPort (Ptr<NetDevice> netdev, Ptr<const Packet> packet,
      uint16_t protocol, const Address& src, const Address& dst, PacketType
      packetType);

  /**
   * \brief Send a message over a specific switch port
   *
   * Check port configuration, create the ns3 packet, remove the ethernet
   * header and trailer from packet (which will be included again by
   * CsmaNetDevice), send the packet over the proper netdevice, and update port
   * statistics.
   *
   * \param pkt The internal packet to send
   * \param port The Openflow port structure
   * \return True if success, false otherwise
   */
  bool SendToSwitchPort (struct packet *pkt, ofs::Port *port);
  //\}


  ///\name Pipeline methods
  //\{
  /**
   * Run the packet through the pipeline. Looks up in the pipeline tables for a
   * match.  If it doesn't match, it forwards the packet to the registered
   * controller, if the flag is set.
   * \see ofsoftswitch function process_buffer at udatapath/dp_ports.c
   * \see ofsoftswitch function pipeline_process_packet at udatapath/pipeline.c
   *
   * \param pkt The internal openflow packet.
   */
  void PipelineProcessPacket (struct packet* pkt);

  /**
   * Executes the instructions associated with a flow entry
   * \see ofsoftswitch function execute_entry at udatapath/pipeline.c
   *
   * \param pl The pipelipe
   * \param entry The flow entry to execute
   * \param next_table A pointer to next table (can be modified by entry)
   * \param pkt The packet associated with this flow entry
   */
  void PipelineExecuteEntry (struct pipeline *pl, struct flow_entry *entry, 
      struct flow_table **next_table, struct packet **pkt);

  /**
   * \internal
   * \brief Check if any flow in any table is timed out and update port
   * status.
   * 
   * This method reschedules itself at every m_timout interval, to constantly
   * check the pipeline for timed out flow entries and update port status.
   * \see ofsoftswitch13 function pipeline_timeout () at udatapath/pipeline.c
   */
  void PipelineTimeout ();
  //\}


  ///\name Action methods
  //\{
  /**
   * Executes the list of OFPIT_APPLY_ACTIONS actions on the given packet
   * \see ofsoftswitch dp_execute_action_list at udatapath/dp_actions.c
   *
   * \param pkt The packet associated with this action
   * \param actions_num The number of actions to execute
   * \param actions A pointer to the list of actions
   * \param cookie The cookie that identifies the buffer ??? (not sure)
   */
  void ActionListExecute (struct packet *pkt, size_t actions_num,
    struct ofl_action_header **actions, uint64_t cookie);
 
  /**
   * Executes the set of OFPIT_WRITE_ACTIONS actions on the given packet
   * \see ofsoftswitch action_set_execute at udatapath/action_set.c
   *
   * \param pkt The packet associated with this action set
   * \param set A pointer to the set of actions
   * \param cookie The cookie that identifies the buffer ??? (not sure)
   */
  void ActionSetExecute (struct packet *pkt, struct action_set *set,  
      uint64_t cookie);

  /**
   * Executes a single action on the given packet
   * \see ofsoftswitch dp_execute_action at udatapath/dp_actions.c
   *
   * \param pkt The packet associated with this action
   * \param set A pointer to the action
   */
  void ActionExecute (struct packet *pkt, struct ofl_action_header *action);

  /**
   * Execute the ouput action sending the packet to an output port
   * \see ofsoftswitch dp_actions_output_port at udatapath/dp_actions.c
   *
   * \param pkt The packet associated with this action
   * \param out_port The port number
   * \param out_queue The queue to use (Can I remove this?)
   * \param max_len The size of the packet to send
   * \param cookie The cookie that identifies the buffer ??? (not sure)
   */
  void ActionOutputPort (struct packet *pkt, uint32_t out_port,
    uint32_t out_queue, uint16_t max_len, uint64_t cookie);

  /**
   * \brief Validate actions before applying it
   * \see ofsoftswitch13 dp_actions_validade () at udatapath/dp_actions.c
   *
   * \param num The number of actions
   * \param actions The actions structure
   * \return 0 if sucess or OpenFlow error code
   */
  ofl_err ActionValidate (size_t num, struct ofl_action_header **actions);
  //\}
  
  
  ///\name Flow table methods
  //\{
  /**
   * Creates a new flow table 
   * \see ofsoftswitch13 flow_table_create () at udatapath/flow_table.c
   *
   * \param table_id The table id.
   * \return The pointer to the created table.
   */
  struct flow_table* FlowTableCreate (uint8_t table_id);

  /**
   * Handles a flow_mod message with OFPFC_ADD command. 
   * \attention new entries will be placed behind those with equal priority
   * \see ofsoftswitch13 flow_table_add () at udatapath/flow_table.c
   *
   * \param table The table to add the entry
   * \param mod The ofl_msg_flow_mod message
   * \param check_overlap If true, prevents existing flow entry overlaps with
   *        the match in the flow mod message
   * \param match_kept Used by HandleFlowMod to proper free structs
   * \param insts_kept Used by HandleFlowMod to proper free structs
   * \return 0 if sucess or OpenFlow error code
   */
  ofl_err FlowTableAdd (struct flow_table *table, struct ofl_msg_flow_mod *mod, 
      bool check_overlap, bool *match_kept, bool *insts_kept);

  /**
   * Handles a flow_mod msg with OFPFC_DELETE or OFPFC_DELETE_STRICT command. 
   * \see ofsoftswitch13 flow_table_delete () at udatapath/flow_table.c
   *
   * \param table The table to delete the entry
   * \param mod The ofl_msg_flow_mod message
   * \param strict If true, check for strict match
   * \return 0 if sucess or OpenFlow error code
   */
  ofl_err FlowTableDelete (struct flow_table *table, struct ofl_msg_flow_mod *mod, 
      bool strict); 

  /**
   * Handles a flow_mod msf with OFPFC_MODIFY or OFPFC_MODIFY_STRICT command. 
   * \see ofsoftswitch13 flow_table_delete () at udatapath/flow_table.c
   *
   * \param table The table to modify the entry
   * \param mod The ofl_msg_flow_mod message
   * \param strict If true, check for strict match
   * \return 0 if sucess or OpenFlow error code
   */
  ofl_err FlowTableModify (struct flow_table *table, struct ofl_msg_flow_mod *mod, 
      bool strict, bool *insts_kept);
  //\}


  ///\name Flow entry methods
  //\{
  /**
   * \internal
   * Removes a flow entry with the given reason. A flow removed message is sent
   * if needed. 
   * \param entry The flow entry to remove.
   * \param reason The reason to send to controller.
   * \see ofsoftswitch13 flow_entry_remove () at udatapath/flow_entry.c
   */
  void FlowEntryRemove (struct flow_entry *entry, uint8_t reason);

  /**
   * \internal
   * \brief Destroy a flow entry. 
   * \param entry The flow entry to destroy.
   * \see ofsoftswitch13 flow_entry_destroy () at udatapath/flow_entry.c
   */
  void FlowEntryDestroy (struct flow_entry *entry);
  //\}
  

  /**
   * \brief Add an Ethernet header and trailer to the packet
   *
   * This is an workaround to facilitate the creation of the openflow buffer.
   * When the packet gets inside the switch, the Ethernet header has already
   * been removed by CsmaNetDevice::Receive () method on the NetDevice port.
   * So, we are going to include it again to properly buffer the packet. We
   * will remove this header and trailer latter.
   * \attention This method only works for DIX encapsulation mode.
   * \see CsmaNetDevice::AddHeader ()
   *
   * \param p The packet (will be modified).
   * \param source The L2 source address.
   * \param dest The L2 destination address.
   * \param protocolNumber The L3 protocol defining the packet
   */
  void AddEthernetHeader (Ptr<Packet> p, Mac48Address source, 
      Mac48Address dest, uint16_t protocolNumber);

  /**
   * \brief Create a packet_in to send to controller
   *
   * \param pkt The internal packet to send
   * \param tableId Table id with with entry match
   * \param reason The reason to send this packet to controller
   * \param cookie ??
   * \return The ns3 packet created
   */
  Ptr<Packet> CreatePacketIn (struct packet *pkt, uint8_t tableId,
      ofp_packet_in_reason reason, uint64_t cookie);

  /**
   * \internal
   * \name OpenFlow message handlers
   * Handlers used by ReceiveFromController to proccess each type of OpenFlow
   * message received from the controller.
   *
   * \param msg The OpenFlow message.
   * \param xid The transaction id from the request message.
   * \return 0 if everything's ok, otherwise an error number.
   */
  //\{
  ofl_err HandleMsgFeaturesRequest (struct ofl_msg_header *msg, uint64_t xid);
  ofl_err HandleMsgGetConfigRequest (struct ofl_msg_header *msg, uint64_t xid);
  ofl_err HandleMsgFlowMod (struct ofl_msg_flow_mod *msg);
  ofl_err HandleMsgMultipartRequest (struct ofl_msg_multipart_request_header *msg, uint64_t xid);
  
  ofl_err MultipartMsgDesc (struct ofl_msg_multipart_request_header *msg, uint64_t xid);
  ofl_err MultipartMsgPortDesc (struct ofl_msg_multipart_request_header *msg, uint64_t xid);
  ofl_err MultipartMsgPortStats (struct ofl_msg_multipart_request_port *msg, uint64_t xid);
  ofl_err MultipartMsgTable (struct ofl_msg_multipart_request_header *msg, uint64_t xid);


  //\}

   /**
   * \internal
   * \name Socket callbacks
   * Handlers used as socket callbacks to TCP communication between this
   * switch and the controller.
   * \param socket The TCP socket.
   */
  //\{
  void HandleCtrlRead       (Ptr<Socket> socket);   //!< Receive packet from controller
  void HandleCtrlSucceeded  (Ptr<Socket> socket);   //!< TCP request accepted
  void HandleCtrlFailed     (Ptr<Socket> socket);   //!< TCP request refused
  //\}

  /// NetDevice callbacks
  NetDevice::ReceiveCallback        m_rxCallback;
  NetDevice::PromiscReceiveCallback m_promiscRxCallback;
  
  // Considering the necessary datapath structs from ofsoftswitch13
  typedef std::vector<ofs::Port> Ports_t;
  Ports_t m_ports;                          //!< Switch's ports

  uint32_t              m_xid;              //!< Global transaction idx
  uint64_t              m_id;               //!< Unique identifier for this switch
  Mac48Address          m_address;          //!< Address of this device
  Ptr<BridgeChannel>    m_channel;          //!< Collection of port channels into the Switch Channel
  Ptr<Node>             m_node;             //!< Node this device is installed on
  Address               m_ctrlAddr;         //!< Controller Address
  Ptr<Socket>           m_ctrlSocket;       //!< Tcp Socket to controller
  uint32_t              m_ifIndex;          //!< Interface Index
  uint16_t              m_mtu;              //!< Maximum Transmission Unit
  Time                  m_timeout;          //!< Pipeline Timeout
  Time                  m_lookupDelay;      //!< Flow Table Lookup Delay [overhead].
  Time                  m_lastTimeout;      //!< Last datapath timeout
  struct ofl_config     m_config;           //!< Configuration, set from controller
  struct pipeline*      m_pipeline;         //!< Pipeline with multi-tables
  // struct dp_buffers*    m_buffers;          //!< Datapath buffers
  // struct group_table*   m_groups;           //!< Group tables
  // struct meter_table*   m_meters;           //!< Meter tables
  // struct ofl_exp*       exp;                //!< Experimenter handling
}; // Class OFSwitch13NetDevice

} // namespace ns3
#endif /* OFSWITCH13_NET_DEVICE_H */
