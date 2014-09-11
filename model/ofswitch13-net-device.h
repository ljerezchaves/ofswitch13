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
   * OpenFlow Switch datapath version 1.3", hardware description is "N/A" and
   * serial number is 1.
   */
  //\{
  static const char * GetManufacturerDescription ();
  static const char * GetHardwareDescription ();
  static const char * GetSoftwareDescription ();
  static const char * GetSerialNumber ();
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
   * have an IP address.  In order to add IP connectivity to a bridging node
   * you must enable IP on the OFSwitch13NetDevice itself, never on its port
   * netdevices.
   *
   * \param switchPort The port to add.
   * \return 0 if everything's ok, otherwise an error number.
   * \sa #EXFULL
   */
  int AddSwitchPort (Ptr<NetDevice> switchPort);

  /**
   * \return Number of switch ports attached to this switch.
   */
  uint32_t GetNSwitchPorts (void) const;

  /**
   * \brief Set up the connection between switch and controller.
   *
   * \param addr The controller address.
   */
  void SetController (Ptr<OFSwitch13Controller> c);
  void SetController (Address addr);


  void RegisterControllerPort (Ptr<NetDevice> controlPort);

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

protected:
  virtual void DoDispose (void);

  /**
   * \brief Search the switch ports looking for a specific device
   *
   * \param sed The Ptr<CsmaNetDevice> pointer to device.
   * \return A pointer to the corresponding ofs::Port.
   */
  ofs::Port* GetPortFromNetDevice (Ptr<NetDevice> dev);

  /**
   * \brief Search the switch ports looking for a specific port number
   *
   * \param no The port number (starting at 1) 
   * \return A pointer to the corresponding ofs::Port.
   */
  ofs::Port* GetPortFromNumber (uint32_t no);

  /**
   * Called when a packet is received on one of the switch's ports.
   *
   * \see ofsoftswitch13 function dp_ports_run () at udatapath/dp_ports.c 
   *
   * \param netdev The port the packet was received on.
   * \param packet The Packet itself.
   * \param protocol The protocol defining the Packet.
   * \param src The source address of the Packet.
   * \param dst The destination address of the Packet.
   * \param PacketType Type of the packet.
   */
  void ReceiveFromDevice (Ptr<NetDevice> netdev, Ptr<const Packet> packet,
      uint16_t protocol, const Address& src, const Address& dst, PacketType
      packetType);

  /**
   * \brief The registered controller calls this method when sending a message
   * to the switch.
   *
   * \param msg The message (ofpbuf) received from the controller.
   * \param length Length of the message.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int ReceiveFromController (ofpbuf* buffer, size_t length);

  /**
   * \brief Send a message to the controller. 
   *
   * This method is the key to communicating with the controller, it does the
   * actual sending. The other Send methods call this one when they are ready
   * to send a message.
   *
   * \param buffer Buffer of the message to send out.
   * \return 0 if successful, otherwise an error number.
   */
  int SendToController (ofpbuf *buffer);


private:
  /**
   * \brief Creates an OpenFlow packet from openflow buffer
   *
   * This packet in an internal ofsoftswitch13 structure to represent the
   * packet, and it is used to parse fields, lookup for flow matchs, etc.
   * 
   * \see ofsoftswitch13 function packet_create () at udatapath/packet.c
   *
   * \param in_port The id of the input port.
   * \param buf The openflow buffer with the packet
   * \param packet_out True if the packet arrived in a packet out msg
   * \return The pointer to the created packet
   */
  struct packet* Of13PacketCreate (uint32_t in_port, struct ofpbuf *buf, 
      bool packet_out);

  /**
   * Run the packet through the pipeline. Looks up in the pipeline tables for a
   * match.  If it doesn't match, it forwards the packet to the registered
   * controller, if the flag is set.
   *
   * \see ofsoftswitch function process_buffer at udatapath/dp_ports.c
   * \see ofsoftswitch function pipeline_process_packet at udatapath/pipeline.c
   *
   * \param packet_uid Packet UID; used to fetch the packet and its metadata.
   * \param port The port this packet was received over.
   */
  void PipelineProcessPacket (uint32_t packet_uid, struct packet* pkt, 
      ofs::Port* inPort);

  /**
   * Executes the instructions associated with a flow entry
   *
   * \see ofsoftswitch function execute_entry at udatapath/pipeline.c
   *
   * \param pl The pipelipe
   * \param entry The flow entry to execute
   * \param next_table A pointer to next table (can be modified by entry)
   * \param pkt The packet associated with this flow entry
   */
  void ExecuteEntry (struct pipeline *pl, struct flow_entry *entry, 
      struct flow_table **next_table, struct packet **pkt);

  /**
   * Executes the list of OFPIT_APPLY_ACTIONS actions on the given packet
   *
   * \see ofsoftswitch dp_execute_action_list at udatapath/dp_actions.c
   *
   * \param pkt The packet associated with this action
   * \param actions_num The number of actions to execute
   * \param actions A pointer to the list of actions
   * \param cookie The cookie that identifies the buffer ??? (not sure)
   */
  void ExecuteActionList (struct packet *pkt, size_t actions_num,
    struct ofl_action_header **actions, uint64_t cookie);

  /**
   * Ouputs the packet on the given port
   *
   * \see ofsoftswitch dp_actions_output_port at udatapath/dp_actions.c
   *
   * \param pkt The packet associated with this action
   * \param out_port The port number
   * \param out_queue The queue to use (Can I remove this?)
   * \param max_len The size of the packet to send
   * \param cookie The cookie that identifies the buffer ??? (not sure)
   */
  void ActionsOutputPort (struct packet *pkt, uint32_t out_port,
    uint32_t out_queue, uint16_t max_len, uint64_t cookie);

  void PortOutput (struct packet *pkt, int out_port);

  /**
   * \brief Handles a flow_mod message received from controller 
   * 
   * Modifications to a flow table from the controller are do ne with the
   * OFPT_FLOW_MOD message (including add, modify or delete).
   *
   * \see ofsoftswitch13 pipeline_handle_flow_mod () at udatapath/pipeline.c
   * and flow_table_flow_mod () at udatapath/flow_table.c
   *
   * \param msg The ofl_msg_flow_mod message
   * \return 0 if sucess or OpenFlow error code
   */
  ofl_err HandleFlowMod (struct ofl_msg_flow_mod *msg); 

  /**
   * \brief Handles a flow_mod message with OFPFC_ADD command. 
   * 
   * \attention new entries will be placed behind those with equal priority
   *
   * \see ofsoftswitch13 flow_table_add () at udatapath/flow_table.c
   *
   * \param table The table to add the flow
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
   * \brief Creates a new flow table 
   * 
   * \see ofsoftswitch13 flow_table_create () at udatapath/flow_table.c
   *
   * \param table_id The table id.
   * \return The pointer to the created table.
   */
  struct flow_table* FlowTableCreate (uint8_t table_id);

  /**
   * \brief Validate actions before applying it
   * 
   * \see ofsoftswitch13 dp_actions_validade () at udatapath/dp_actions.c
   *
   * \param num The number of actions
   * \param actions The actions structure
   * \return 0 if sucess or OpenFlow error code
   */
  ofl_err ActionsValidate (size_t num, struct ofl_action_header **actions);

  /**
   * \brief Add an Ethernet header and trailer to the packet
   *
   * This is an workaround to facilitate the creation of the openflow buffer.
   * When the packet gets inside the switch, the Ethernet header has already
   * been removed by CsmaNetDevice::Receive () method on the NetDevice port.
   * So, we are going to include it again to properly buffer the packet. We
   * will remove this header and trailer latter.
   *
   * \attention This method only works for DIX encapsulation mode.
   *
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
   * NetDevice callbacks
   */
  //\{
  NetDevice::ReceiveCallback        m_rxCallback;
  NetDevice::PromiscReceiveCallback m_promiscRxCallback;
  //\}

  /**
   * Handlers used as socket callbacks to TCP communication between this
   * switch and the controller.
   */
  //\{
  void HandleRead           (Ptr<Socket> socket);   //!< Receive packet from controller
  void HandleConnSucceeded  (Ptr<Socket> socket);   //!< TCP request accepted
  void HandleConnFailed     (Ptr<Socket> socket);   //!< TCP request refused
  //\}

  Mac48Address m_address;                 ///< Address of this device
  Ptr<Node> m_node;                       ///< Node this device is installed on
  Ptr<BridgeChannel> m_channel;           ///< Collection of port channels into the Switch Channel
  uint32_t m_ifIndex;                     ///< Interface Index
  uint16_t m_mtu;                         ///< Maximum Transmission Unit
   

  typedef std::vector<ofs::Port> Ports_t;
  Ports_t m_ports;                        ///< Switch's ports

  //typedef std::map<uint64_t, ofs::SwitchPacketMetadata> PacketData_t;
  //PacketData_t m_packetData;              ///< Packet data

  Ptr<OFSwitch13Controller> m_controller; ///< Connection to controller
  Address m_controllerAddr;               ///< Controller Address
  Ptr<Socket> m_ctrlSocket;               ///< Tcp Socket to controller



  // Considering the necessary datapath structs from ofsoftswitch13
  uint64_t m_id;                              ///< Unique identifier for this switch
  Time m_lastTimeout;                         ///< Last datapath timeout
  Time m_lookupDelay;                         ///< Flow Table Lookup Delay [overhead].
  // struct dp_buffers* m_buffers;            ///< Datapath buffers
  struct ofl_config m_config;                 ///< Configuration, set from controller
  struct pipeline* m_pipeline;                ///< Pipeline with multi-tables
  // struct group_table* m_groups;            ///< Group tables
  // struct meter_table* m_meters;            ///< Meter tables
  // struct ofl_exp* exp;                     ///< Experimenter handling

  };

} // namespace ns3
#endif /* OFSWITCH13_NET_DEVICE_H */
