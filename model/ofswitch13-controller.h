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

#ifndef OFSWITCH13_CONTROLLER_H
#define OFSWITCH13_CONTROLLER_H

#include "ns3/application.h"
#include "ns3/socket.h"
#include "ns3/tcp-socket-factory.h"
#include "ofswitch13-interface.h"
#include "ofswitch13-net-device.h"

namespace ns3 {

class OFSwitch13NetDevice;
class OFSwitch13Helper;

/**
 * \ingroup ofswitch13
 * \brief Switch metadata used by internal controller handlers
 */
struct SwitchInfo
{
  Ipv4Address ipv4;                 //!< Switch IPv4 address
  Ptr<OFSwitch13NetDevice> netdev;  //!< OpenFlow NetDevice
  Ptr<Node> node;                   //!< Switch node
  Ptr<Socket> socket;               //!< TCP socket connected to controller
  uint16_t port;                    //!< Socket port

  InetSocketAddress GetInet ();     //!< Get Inet address conversion
};

/**
 * \ingroup ofswitch13
 * \brief An OpenFlow 1.3 controller for OFSwitch13NetDevice devices
 * \attention Currently, It is not full-compliant with the protocol
 * specification. 
 */
class OFSwitch13Controller : public Application
{
public:
  OFSwitch13Controller ();
  virtual ~OFSwitch13Controller ();

  // inherited from Object
  static TypeId GetTypeId (void);
  virtual void DoDispose ();

  /**
   * \brief Register switch metadata information on this controller.
   * \param swInfo The switch metadata
   */
  void RegisterSwitchMetadata (SwitchInfo swInfo);

  /**
   * \brief Create a flow_mod message using the same syntax from dpctl, and
   * send it to the switch.
   * \param swtch The switch to receive the message.
   * \param textCmd The dpctl flow_mod command to create the message.
   * \return The number of bytes sent
   */
  int SendFlowModMsg (Ptr<OFSwitch13NetDevice> swtch, const char* textCmd);

protected:

private:
  // inherited from Application
  virtual void StartApplication (void);
  virtual void StopApplication (void);

  /**
   * \internal
   * Get the packet type on the buffer, which can then be used
   * to determine how to handle the buffer.
   *
   * \param buffer The packet in OpenFlow buffer format.
   * \return The packet type, as defined in the ofp_type struct.
   */
  ofp_type GetPacketType (ofpbuf* buffer);

  /**
   * \internal
   * \brief Handles any ofpbuf received from switch
   * \param swtch The switch the message was received from.
   * \param buffer The pointer to the buffer containing the message.
   */
  int ReceiveFromSwitch (SwitchInfo swtch, ofpbuf* buffer);

  /**
   * \internal
   * Send a message to a registered switch. It will encapsulate the ofl_msg
   * format into an ofpbuf wire format and send it over a TCP socekt to the
   * proper switch IP address.
   * \param pkt The packet to send
   * \param swtch The switch to receive the message.
   * \return The number of bytes sent
   */
  int SendToSwitch (SwitchInfo swtch, Ptr<Packet> pkt);

  void SendHello (SwitchInfo swtch);
  void SendEchoRequest (SwitchInfo swtch, size_t payloadSize = 0);
 
   /**
   * \internal
   * \name OpenFlow message handlers
   * Handlers used by ReceiveFromSwitch to proccess each type of OpenFlow
   * message received from the switch.
   *
   * \param msg The OpenFlow message.
   * \param swtch The switch information.
   * \param xid The transaction id from the request message.
   * \return 0 if everything's ok, otherwise an error number.
   */
  //\{
  ofl_err HandleMsgHello (ofl_msg_header *msg, SwitchInfo swtch, uint64_t xid);
  ofl_err HandleMsgError (ofl_msg_error *msg, SwitchInfo swtch, uint64_t xid);
  ofl_err HandleMsgEchoRequest (ofl_msg_echo *msg, SwitchInfo swtch, uint64_t xid);
  ofl_err HandleMsgEchoReply (ofl_msg_echo *msg, SwitchInfo swtch, uint64_t xid);
  ofl_err HandleMsgFeaturesReply (ofl_msg_features_reply *msg, SwitchInfo swtch, uint64_t xid);
  ofl_err HandleMsgGetConfigReply (ofl_msg_get_config_reply *msg, SwitchInfo swtch, uint64_t xid);
  ofl_err HandleMsgPacketIn (ofl_msg_packet_in *msg, SwitchInfo swtch, uint64_t xid);
  ofl_err HandleMsgFlowRemoved (ofl_msg_flow_removed *msg, SwitchInfo swtch, uint64_t xid);
  ofl_err HandleMsgPortStatus (ofl_msg_port_status *msg, SwitchInfo swtch, uint64_t xid);
  ofl_err HandleMsgAsyncReply (ofl_msg_async_config *msg, SwitchInfo swtch, uint64_t xid);
  ofl_err HandleMsgMultipartReply (ofl_msg_multipart_reply_header *msg, SwitchInfo swtch, uint64_t xid);
  ofl_err HandleMsgBarrierReply (ofl_msg_header *msg, SwitchInfo swtch, uint64_t xid);
  ofl_err HandleMsgRoleReply (ofl_msg_role_request *msg, SwitchInfo swtch, uint64_t xid);
  ofl_err HandleMsgQueueGetConfigReply (ofl_msg_queue_get_config_reply *msg, SwitchInfo swtch, uint64_t xid);
  //\}

  /**
   * \internal
   * \name Socket callbacks
   * Handlers used as socket callbacks to TCP communication between this
   * switch and the controller.
   * \param socket The TCP socket.
   * \param from The source Address
   */
  //\{
  void SocketRead       (Ptr<Socket> socket);                       //!< Receive packet from switch
  bool SocketRequest    (Ptr<Socket> s, const Address& from);       //!< TCP request from switch
  void SocketAccept     (Ptr<Socket> socket, const Address& from);  //!< TCP handshake succeeded
  void SocketPeerClose  (Ptr<Socket> socket);                       //!< TCP connection closed
  void SocketPeerError  (Ptr<Socket> socket);                       //!< TCP connection error
  //\}
  
  uint32_t              m_xid;          //!< Global transaction idx
  uint16_t              m_port;         //!< Local controller tcp port
  Ptr<Socket>           m_serverSocket; //!< Listening server socket
  
  typedef std::map<Ipv4Address, SwitchInfo> SwitchsMap_t;
  SwitchsMap_t m_switchesMap;           //!< Registered switch metadata (key is Ipv4Addres)
};

} // namespace ns3
#endif /* OFSWITCH13_CONTROLLER_H */
