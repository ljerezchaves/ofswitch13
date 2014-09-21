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
#include <string>

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
 * \brief An OpenFlow 1.3 controller base class for OFSwitch13NetDevice devices
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
   * Switch TCP connection started callback
   * \param The switch metadata that initiated a connection with controller
   */
  typedef Callback<void, SwitchInfo> SwitchConnectionCallback_t;

  /**
   * \brief Register a TCP connection callback
   * \param cb Callback to invoke whenever a switch starts a TCP connection to
   * this controller
   */
  void SetConnectionCallback (SwitchConnectionCallback_t cb);

  /**
   * \brief Execute a dpctl command to send an openflow message to the
   * switch.
   * \param swtch The target switch metadata
   * \param textCmd The dpctl command to create the message.
   * \return The number of bytes sent
   */
  int DpctlCommand (SwitchInfo swtch, const std::string textCmd);

protected:
  // inherited from Application
  virtual void StartApplication (void);
  virtual void StopApplication (void);

  /**
   * Send a ns3 packet to a registered switch. 
   * \param swtch The switch to receive the message
   * \param pkt The packet to send
   * \return The number of bytes sent
   */
  int SendToSwitch (SwitchInfo swtch, Ptr<Packet> pkt);

  /**
   * \name OpenFlow symmetric messages
   * Methods to send messages without solicitation
   * \param swtch The target switch metadata
   * \return The number of transmitted bytes.
   */
  //\{
  int SendHello (SwitchInfo swtch); //!< Send a hello message (upon connection establishment)
  int SendEchoRequest (SwitchInfo swtch, size_t payloadSize = 0); //!< Send an echo request
  //\}

  /**
   * \name OpenFlow controller-to-switch messages
   * \brief Send request messages to switch
   *
   * These methods can be used by controller to query switch configuration,
   * description or statistics. The response sent by switch will be received by
   * handlers methods.
   *
   * \param swtch The target switch metadata
   * \return The number of transmitted bytes.
   */
  //\{
  int RequestBarrier (SwitchInfo swtch);          //!< Send a barrier request
  int RequestAsync (SwitchInfo swtch);            //!< Query the asynchronous messages that it wants to receive
  int RequestFeatures (SwitchInfo swtch);         //!< Query switch features (during handshake)
  int RequestConfig (SwitchInfo swtch);           //!< Query switch configuration
  int RequestSwitchDesc (SwitchInfo swtch);       //!< Query switch datapath description
  int RequestTableStats (SwitchInfo swtch);       //!< Query table statistics
  int RequestPortStats (SwitchInfo swtch, uint32_t port = OFPP_ANY); //!< Query port statistcs (default: all ports)
  int RequestTableFeatures (SwitchInfo swtch);    //!< Query table features
  int RequestPortDesc (SwitchInfo swtch);         //!< Query port description
  //\}

  /**
   * \name OpenFlow message handlers
   * \brief Handlers used by ReceiveFromSwitch to proccess each type of
   *
   * OpenFlow message received from the switch. 
   * Some handler methods can not be overwritten by derived class (hello, echo
   * request/reply and barrier reply, as they must behave as already
   * implemented. In constrast, packetIn must be implementd by the derived
   * controller, to proper handle packets sent from switch to controller. The
   * current implementation of other virtual methods does nothing: just free
   * the received message and returns 0.
   *
   * \attention Handlers \em MUST free received msg when everything is ok.
   *
   * \param msg The OpenFlow message.
   * \param swtch The source switch metadata.
   * \param xid The transaction id from the request message.
   * \return 0 if everything's ok, otherwise an error number.
   */
  //\{
  ofl_err HandleMsgHello (ofl_msg_header *msg, SwitchInfo swtch, uint64_t xid);
  ofl_err HandleMsgEchoRequest (ofl_msg_echo *msg, SwitchInfo swtch, uint64_t xid);
  ofl_err HandleMsgEchoReply (ofl_msg_echo *msg, SwitchInfo swtch, uint64_t xid);
  ofl_err HandleMsgBarrierReply (ofl_msg_header *msg, SwitchInfo swtch, uint64_t xid);
  
  virtual ofl_err HandleMsgPacketIn (ofl_msg_packet_in *msg, SwitchInfo swtch, uint64_t xid) = 0;
  
  virtual ofl_err HandleMsgError (ofl_msg_error *msg, SwitchInfo swtch, uint64_t xid);
  virtual ofl_err HandleMsgFeaturesReply (ofl_msg_features_reply *msg, SwitchInfo swtch, uint64_t xid);
  virtual ofl_err HandleMsgGetConfigReply (ofl_msg_get_config_reply *msg, SwitchInfo swtch, uint64_t xid);
  virtual ofl_err HandleMsgFlowRemoved (ofl_msg_flow_removed *msg, SwitchInfo swtch, uint64_t xid);
  virtual ofl_err HandleMsgPortStatus (ofl_msg_port_status *msg, SwitchInfo swtch, uint64_t xid);
  virtual ofl_err HandleMsgAsyncReply (ofl_msg_async_config *msg, SwitchInfo swtch, uint64_t xid);
  virtual ofl_err HandleMsgMultipartReply (ofl_msg_multipart_reply_header *msg, SwitchInfo swtch, uint64_t xid);
  virtual ofl_err HandleMsgRoleReply (ofl_msg_role_request *msg, SwitchInfo swtch, uint64_t xid);
  virtual ofl_err HandleMsgQueueGetConfigReply (ofl_msg_queue_get_config_reply *msg, SwitchInfo swtch, uint64_t xid);
  //\}

  typedef std::map<Ipv4Address, SwitchInfo> SwitchsMap_t;
  SwitchsMap_t m_switchesMap;           //!< Registered switch metadata

private:
  /**
   * \internal
   * \brief Called by the SocketRead when a packet is received from the switch.
   * Dispatches control messages to appropriate handler functions.
   * \param swtch The switch the message was received from.
   * \param buffer The pointer to the buffer containing the message.
   */
  int ReceiveFromSwitch (SwitchInfo swtch, ofpbuf* buffer);

  /**
   * \internal
   * \name Dcptl commands
   * Methods to create the openflow messages based on dpctl commands
   * \param swtch The target switch metadata
   * \param argc The number of arguments 
   * \param argv The argument's values
   * \return The number of bytes sent
   */
  //\{
  int DpctlFlowModCommand (SwitchInfo swtch, int argc, char *argv[]);
  int DpctlSetConfigCommand (SwitchInfo swtch, int argc, char *argv[]);
  int DpctlStatsFlowCommand (SwitchInfo swtch, int argc, char *argv[]);
  int DpctlStatsAggrCommand (SwitchInfo swtch, int argc, char *argv[]);
  int DpctlStatsPortCommand (SwitchInfo swtch, int argc, char *argv[]);
  int DpctlPortModCommand (SwitchInfo swtch, int argc, char *argv[]);
  int DpctlTableModCommand (SwitchInfo swtch, int argc, char *argv[]);
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
  
  ofs::EchoMsgMap_t m_echoMap;                     //!< Metadata for echo requests
  SwitchConnectionCallback_t m_connectionCallback; //!< TCP connection callback
};

} // namespace ns3
#endif /* OFSWITCH13_CONTROLLER_H */
