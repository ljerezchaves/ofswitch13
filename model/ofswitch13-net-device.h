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
 * and acts like a switch. It implements OpenFlow compatibility,
 * according to the OpenFlow Switch Specification v1.3.
 *
 * \attention Each NetDevice used as port must only be assigned a Mac Address,
 * adding it to an Ipv4 or Ipv6 layer will cause an error. It also must support
 * a SendFrom call.
 */
class OFSwitch13NetDevice : public NetDevice
{
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
   * \brief Set up the switch's controller connection.
   *
   * \param c Pointer to an OFSwitch13Controller.
   */
  void SetController (Ptr<OFSwitch13Controller> c);


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

protected:
  virtual void DoDispose (void);

  /**
   * \brief Search the switch ports looking for a specific device
   *
   * \param sed The Ptr<CsmaNetDevice> pointer to device.
   * \return A pointer to the corresponding ofs::Port.
   */
  ofs::Port* GetPortFromNetDevice (Ptr<CsmaNetDevice> dev);

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
  void ReceiveFromDevice (Ptr<NetDevice> netdev, Ptr<const Packet> packet, uint16_t protocol, 
      const Address& src, const Address& dst, PacketType packetType);

  /**
   * \internal
   *
   * Takes a Ptr<Packet> and generates an OpenFlow buffer (ofpbuf*) from it,
   * loading the packet data as well as its headers into the buffer.
   * 
   * \see ofsoftswitch13 function netdev_recv () at lib/netdev.c
   *
   * \param packet The packet.
   * \param src The source address.
   * \param dst The destination address.
   * \param mtu The Maximum Transmission Unit (MTU).
   * \param protocol The L3 protocol defining the packet (as we are in L2).
   * \return The OpenFlow Buffer created from the packet.
   */
  ofpbuf* BufferFromPacket (Ptr<Packet> packet, Mac48Address src, Mac48Address dst, int mtu, uint16_t protocol);

 /**
   * \internal
   *
   * Run the packet through the pipeline. Looks up in the pipeline tables for a match.
   * If it doesn't match, it forwards the packet to the registered controller, if the flag is set.
   *
   * \see ofsoftswitch function process_buffer at udatapath/dp_ports.c
   * \see ofsoftswitch function pipeline_process_packet at udatapath/pipeline.c
   *
   * \param packet_uid Packet UID; used to fetch the packet and its metadata.
   * \param port The port this packet was received over.
   */
  void PipelineProcessBuffer (uint32_t packet_uid, ofpbuf* buffer, ofs::Port* inPort);


  /**
   * \internal
   *
   * \brief Handles a flow_mod message 
   * 
   * Modifications to a flow table from the controller are done with the
   * OFPT_FLOW_MOD message (including add, modify or delete).
   *
   * \see ofsoftswitch13 function pipeline_handle_flow_mod () at udatapath/pipeline.c
   *
   * \param msg The OpenFlow flow_mod message 
   * \return 0 if sucess or OpenFlow error code
   */
  //ofl_err HandleFlowMod (struct ofl_msg_flow_mod *msg);



void 
executarssaporra (struct pipeline *pl, struct flow_entry *entry, struct flow_table **next_table, struct packet **pkt);


  

private:
  NetDevice::ReceiveCallback m_rxCallback;
  NetDevice::PromiscReceiveCallback m_promiscRxCallback;

  Mac48Address m_address;               ///< Address of this device
  Ptr<Node> m_node;                     ///< Node this device is installed on
  Ptr<BridgeChannel> m_channel;         ///< Collection of port channels into the Switch Channel
  uint32_t m_ifIndex;                   ///< Interface Index
  uint16_t m_mtu;                       ///< Maximum Transmission Unit
   
  typedef std::vector<ofs::Port> Ports_t;
  Ports_t m_ports;                      ///< Switch's ports

  typedef std::map<uint32_t, ofs::SwitchPacketMetadata> PacketData_t;
  PacketData_t m_packetData;            ///< Packet data

  Ptr<OFSwitch13Controller> m_controller;    ///< Connection to controller

  // Considering the necessary datapath structs from ofsoftswitch13
  uint64_t m_id;                        ///< Unique identifier for this switch
  struct ofl_config m_config;           ///< Configuration, set from controller
  struct pipeline* m_pipeline;          ///< Pipeline with multi-tables
  // struct group_table* m_groups;         ///< Group tables
  // struct meter_table* m_meters;         ///< Meter tables


  // struct ofl_exp* exp;                  ///< Experimenter handling



// FIXME criar a tabela
struct flow_table* FlowTableCreate (uint8_t table_id);

// Criar o packet interno
struct packet* PacketCreate (uint32_t in_port, struct ofpbuf *buf, bool packet_out);

// Reinsere o cabecalho ethernet que foi removido TODO: precisa descobrir onde apagar esse cabecalho
// \see CsmaNetDevice::AddHeader ()
void AddEthernetHeaderBack (Ptr<Packet> p, Mac48Address source, Mac48Address dest, uint16_t protocolNumber);




};

} // namespace ns3

#endif /* OFSWITCH13_NET_DEVICE_H */
