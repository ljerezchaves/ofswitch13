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
   * \param switchPort The NetDevice port to add.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int AddSwitchPort (Ptr<NetDevice> switchPort);

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
   * \return A pointer to the corresponding ofs::Port.
   */
  ofs::Port* PortGetOfsPort (Ptr<NetDevice> dev);

  /**
   * Search the switch ports looking for a specific port number.
   * \param no The port number (starting at 1).
   * \return A pointer to the corresponding ofs::Port.
   */
  ofs::Port* PortGetOfsPort (uint32_t no);

  /**
   * Update the port status field of the switch port. A non-zero return value
   * indicates some field has changed.
   * \see ofsoftswitch13 dp_port_live_update () at udatapath/dp_ports.c
   * \param p Port to update its config and flag fields.
   * \return 0 if unchanged, any value otherwise.
   */
  int PortLiveUpdate (ofs::Port *p);

  /**
   * Updates the time fields of the port statistics. Used before
   * generating port statistics messages.
   * \see ofsoftswitch13 dp_port_stats_update () at udatapath/dp_ports.c
   * \param p Port to update.
   */
  void PortStatsUpdate (ofs::Port *p);

  /**
   * Handles a port stats request message. 
   * \see dp_ports_handle_stats_request_port () at udatapath/dp_ports.c.
   * \param dp The datapath.
   * \param msg The OFLib message received.
   * \param sender The sender (controller) information (including xid).
   * \return 0 if everything's ok, otherwise an error number.
   */
  ofl_err PortMultipartStats (datapath *dp, 
      ofl_msg_multipart_request_port *msg, const sender *sender);
  
  /**
   * Handles a port description request message.
   * \see dp_ports_handle_port_desc_request () at udatapath/dp_ports.c.
   * \param dp The datapath.
   * \param msg The OFLib message received.
   * \param sender The sender (controller) information (including xid).
   * \return 0 if everything's ok, otherwise an error number.
   */
  ofl_err PortMultipartDesc (datapath *dp, 
      ofl_msg_multipart_request_header *msg, const sender *sender);
  
  /**
   * Handles a port mod message.
   * \see dp_ports_handle_port_mod () at udatapath/dp_ports.c.
   * \param dp The datapath.
   * \param msg The OFLib message received.
   * \param sender The sender (controller) information (including xid).
   * \return 0 if everything's ok, otherwise an error number.
   */
  ofl_err PortHandlePortMod (datapath *dp, ofl_msg_port_mod *msg, 
      const sender *sender);

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
      uint16_t protocol, const Address& src, const Address& dst, PacketType
      packetType);

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

  /**
   * Send a message over a specific switch port. Check port configuration,
   * create the ns3 packet, remove the ethernet header and trailer from packet
   * (which will be included again by CsmaNetDevice), send the packet over the
   * proper netdevice, and update port statistics.
   * \param pkt The internal packet to send.
   * \param port The Openflow port structure.
   * \return True if success, false otherwise.
   */
  bool SendToSwitchPort (packet *pkt, ofs::Port *port);

  /**
   * Send a message over all switch ports, except input port.
   * \see SendToSwitch ().
   * \param pkt The internal packet to send.
   * \return True if success, false otherwise.
   */
  bool FloodToSwitchPorts (packet *pkt);
  //\}

  ///\name Pipeline methods
  //\{
  /**
   * Run the packet through the pipeline. Looks up in the pipeline tables for a
   * match. If it doesn't match, it forwards the packet to the registered
   * controller, if the flag is set.
   * \see ofsoftswitch function process_buffer at udatapath/dp_ports.c.
   * \see ofsoftswitch function pipeline_process_packet at udatapath/pipeline.c.
   * \param pl The pipeline.
   * \param pkt The internal openflow packet.
   */
  void PipelineProcessPacket (pipeline* pl, packet* pkt);

  /**
   * Executes the instructions associated with a flow entry.
   * \see ofsoftswitch function execute_entry at udatapath/pipeline.c.
   * \param pl The pipeline.
   * \param entry The flow entry to execute.
   * \param next_table A pointer to next table (can be modified by entry).
   * \param pkt The packet associated with this flow entry.
   */
  void PipelineExecuteEntry (pipeline* pl, flow_entry *entry, 
      flow_table **next_table, packet **pkt);

  /**
   * Handles a flow mod message.
   * \see pipeline_handle_flow_mod () at udatapath/dp_control.c.
   * \param pl The pipeline.
   * \param msg The OFLib message received.
   * \param sender The sender (controller) information (including xid).
   * \return 0 if everything's ok, otherwise an error number.
   */
  ofl_err PipelineHandleFlowMod (pipeline *pl, ofl_msg_flow_mod *msg, 
      const sender *sender);

  /**
   * Create and send a packet_in to controller.
   * \see ofsoftswitch13 send_packet_to_controller () at udatapath/pipeline.c.
   * \param pl The pipeline.
   * \param pkt The internal packet to send.
   * \param tableId Table id with with entry match.
   * \param reason The reason to send this packet to controller.
   * \param cookie Controller data used to filter flow statistics.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int PipelineSendPacketIn (pipeline* pl, packet *pkt, 
      uint8_t tableId, ofp_packet_in_reason reason, uint64_t cookie);
  //\}

  ///\name Actions methods
  //\{
  /**
   * Executes the list of OFPIT_APPLY_ACTIONS actions on the given packet.
   * \see ofsoftswitch dp_execute_action_list at udatapath/dp_actions.c.
   * \param pkt The packet associated with this action.
   * \param actions_num The number of actions to execute.
   * \param actions A pointer to the list of actions.
   * \param cookie Controller data used to filter flow statistics.
   */
  void ActionsListExecute (packet *pkt, size_t actions_num, 
      ofl_action_header **actions, uint64_t cookie);
 
  /**
   * Executes the set of OFPIT_WRITE_ACTIONS actions on the given packet.
   * \see ofsoftswitch action_set_execute at udatapath/action_set.c.
   * \param set A pointer to the set of actions.
   * \param pkt The packet associated with this action set.
   * \param cookie Controller data used to filter flow statistics.
   */
  void ActionSetExecute (action_set *set, packet *pkt, uint64_t cookie);

  /**
   * Execute the ouput action sending the packet to an output port.
   * \see ofsoftswitch dp_actions_output_port at udatapath/dp_actions.c.
   * \param pkt The packet associated with this action.
   * \param out_port The port number.
   * \param out_queue The queue to use.
   * \param max_len The size of the packet to send.
   * \param cookie Controller data used to filter flow statistics.
   */
  void ActionOutputPort (packet *pkt, uint32_t out_port, uint32_t out_queue,
      uint16_t max_len, uint64_t cookie);

  /**
   * Validate actions before applying it.
   * \see ofsoftswitch13 dp_actions_validate () at udatapath/dp_actions.c.
   * \param dp The datapath.
   * \param num The number of actions.
   * \param actions The actions structure.
   * \return 0 if everything's ok, otherwise an error number.
   */
  ofl_err ActionsValidate (datapath *dp, size_t num, 
      ofl_action_header **actions);
  //\}
  
  ///\name Group methods
  //\{
  /**
   * Executes the given group entry on the packet. 
   * \see group_table_execute () at udatapath/group_table.c
   * \param table The group table.
   * \param packet The packet to execute actions.
   * \param group_id The group entry id.
   */
  void GroupTableExecute (group_table *table, packet *packet, uint32_t group_id);
  
  /**
   * Executes the group entry on the packet. 
   * \see ofsoftswitch13 group_entry_execute () at udatapath/group_entry.c
   * \param entry The group entry to execute.
   * \param pkt The packet.
   */
  void GroupEntryExecute (group_entry *entry, packet *pkt);

  /** 
   * Executes a group entry of type ALL.
   * \see ofsoftswitch13 execute_all (), execute_select (), execute_indirect ()
   * and execute_ff () at udatapath/group_entry.c
   * \param entry The group entry to execute.
   * \param pkt The packet.
   * \param i Bucket index.
   */
  void GroupEntryExecuteBucket (group_entry *entry, packet *pkt, size_t i); 

  /**
   * Handles a group mod message.
   * \see group_table_handle_group_mod () at udatapath/group_table.c.
   * \param table The group table.
   * \param msg The OFLib message received.
   * \param sender The sender (controller) information (including xid).
   * \return 0 if everything's ok, otherwise an error number.
   */
  ofl_err GroupHandleGroupMod  (group_table *table, ofl_msg_group_mod *msg, 
      const sender *sender);
  //\}

  /**
   * \name OpenFlow message handlers
   * Handlers used to proccess each OpenFlow message received from
   * controller.
   * \param dp The datapath.
   * \param msg The OFLib message received.
   * \param sender The sender (controller) information (including xid).
   * \return 0 if everything's ok, otherwise an error number.
   */
  //\{
  /**
   * Called by SocketRead when a packet is received from controller.
   * Dispatches control messages to appropriate handler functions.
   * \see handle_control_msg () at udatapath/dp_control.c.
   */
  ofl_err HandleControlMessage (datapath *dp, ofl_msg_header *msg, 
    const sender *sender);
  
  /**
   * Called by HandleControlMessage when a multipart request is received from
   * controller. Dispatches multipart request to appropriate handler
   * functions.
   * \see handle_control_stats_request () at udatapath/dp_control.c.
   */
  ofl_err HandleControlMultipartRequest (datapath *dp, 
      ofl_msg_multipart_request_header *msg, const sender *sender);

  /**
   * Handles a echo reply message.
   * \see handle_control_echo_reply () at udatapath/dp_control.c.
   */
  ofl_err HandleMsgEchoReply (datapath *dp, ofl_msg_echo *msg, 
      const sender *sender);

  /**
   * Handles a packet out from controller.
   * \see handle_control_packet_out () at udatapath/dp_control.c.
   */
  ofl_err HandleMsgPacketOut (datapath *dp, ofl_msg_packet_out *msg,
      const sender *sender);
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
 
  static uint64_t         m_globalDpId;       //!< Global counter of datapath IDs
  
  uint64_t                m_dpId;             //!< This datapath id
  uint32_t                m_xid;              //!< Transaction idx sequence
  Mac48Address            m_address;          //!< Address of this device
  Ptr<BridgeChannel>      m_channel;          //!< Port channels into the Switch Channel
  Ptr<Node>               m_node;             //!< Node this device is installed on
  Ptr<Socket>             m_ctrlSocket;       //!< Tcp Socket to controller
  Address                 m_ctrlAddr;         //!< Controller Address
  uint32_t                m_ifIndex;          //!< Interface Index
  uint16_t                m_mtu;              //!< Maximum Transmission Unit
  Time                    m_echo;             //!< Echo request interval
  Time                    m_timeout;          //!< Datapath Timeout
  Time                    m_lookupDelay;      //!< Flow Table Lookup Delay [overhead].
  datapath*               m_datapath;         //!< The OpenFlow datapath
  ofs::EchoMsgMap_t       m_echoMap;          //!< Metadata for echo requests
  ofs::Ports_t            m_ports;            //!< Metadata for switch ports

}; // Class OFSwitch13NetDevice
} // namespace ns3
#endif /* OFSWITCH13_NET_DEVICE_H */
