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
  OFSwitch13Controller ();          //!< Default constructor
  virtual ~OFSwitch13Controller (); //!< Dummy destructor, see DoDispose.

  /**
   * Switch TCP connection started callback
   * \param The switch metadata that initiated a connection with controller
   */
  typedef Callback<void, SwitchInfo> SwitchConnectionCallback_t;
  
  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);

  /** 
   * Destructor implementation 
   */
  virtual void DoDispose ();

  /**
   * \brief Register switch metadata information on this controller.
   * \param swInfo The switch metadata
   */
  void RegisterSwitchMetadata (SwitchInfo swInfo);

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
   * \return The next (in sequence) transaction ID for this controller.
   */
  uint32_t GetNextXid ();

  /**
   * Send a OFLib message to a registered switch. 
   * \param swtch The switch to receive the message
   * \param msg The OFLib message to send.
   * \param xid The transaction id to use.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int SendToSwitch (SwitchInfo swtch, ofl_msg_header *msg, uint32_t xid = 0);

  /**
   * \name Symmetric messages
   * These methods can send messages to switch at any time.
   * \param swtch The target switch metadata.
   * \return 0 if everything's ok, otherwise an error number.
   */
  //\{
  int SendHello (SwitchInfo swtch); //!< Send a hello message
  int SendEcho (SwitchInfo swtch, size_t payloadSize = 0); //!< Send an echo request
  int SendBarrier (SwitchInfo swtch); //!< Send a barrier request
  //\}

  /**
   * \name Controller-to-switch messages
   * These methods can be used by controller to query or set switch
   * configuration, description and statistics. The response sent by switch
   * will be received by handlers methods.
   * \param swtch The target switch metadata.
   * \param argc The number of arguments.
   * \param argv The argument's values in Dcptl syntax.
   * \return 0 if everything's ok, otherwise an error number.
   */
  //\{
  int RequestFeatures (SwitchInfo swtch);      //!< Query switch for features
  int RequestConfig (SwitchInfo swtch);        //!< Query switch configuration
  int RequestTableFeatures (SwitchInfo swtch); //!< Query table features
  int RequestGroupFeatures (SwitchInfo swtch); //!< Query group features
  int RequestMeterFeatures (SwitchInfo swtch); //!< Query meter features
  int RequestSwitchDesc (SwitchInfo swtch);    //!< Query switch description
  int RequestFlowStats (SwitchInfo swtch, int argc, char *argv[]);  //!< Query flow statistics
  int RequestFlowAggr (SwitchInfo swtch, int argc, char *argv[]);   //!< Query flow aggregated statistics
  int RequestPortStats (SwitchInfo swtch, int argc, char *argv[]);  //!< Query port statistics
  int RequestGroupStats (SwitchInfo swtch, int argc, char *argv[]); //!< Query group statistics
  int RequestGroupDesc (SwitchInfo swtch, int argc, char *argv[]);  //!< Query group description
  int RequestMeterStats (SwitchInfo swtch, int argc, char *argv[]); //!< Query meter statistics
  int RequestPortDesc (SwitchInfo swtch);     //!< Query port description
  int RequestTableStats (SwitchInfo swtch);   //!< Query table statistics
  int RequestAsyncConfig (SwitchInfo swtch);  //!< Query asynchronous configuration
  int MeterConfig (SwitchInfo swtch, int argc, char *argv[]); //!< Set a meter configuration
  int SetConfig (SwitchInfo swtch, int argc, char *argv[]); //!< Set switch configuration
  int FlowMod (SwitchInfo swtch, int argc, char *argv[]);   //!< Send a flow-mod command
  int GroupMod (SwitchInfo swtch, int argc, char *argv[]);  //!< Send a group-mod command
  int MeterMod (SwitchInfo swtch, int argc, char *argv[]);  //!< Send a meter-mod command
  int PortMod (SwitchInfo swtch, int argc, char *argv[]);   //!< Send a port-mod command
  int TableMod (SwitchInfo swtch, int argc, char *argv[]);  //!< Send a table-mod command
  //\}

  /**
   * \name OpenFlow message handlers
   * Handlers used by ReceiveFromSwitch to proccess each type of OpenFlow
   * message received from the switch. Some handler methods can not be
   * overwritten by derived class (echo request/reply), as they must behave as
   * already implemented. In constrast, packetIn must be implementd by the
   * derived controller, to proper handle packets sent from switch to
   * controller. The current implementation of other virtual methods does
   * nothing: just free the received message and returns 0.
   * \attention Handlers \em MUST free received msg when everything is ok.
   * \param msg The OpenFlow message.
   * \param swtch The source switch metadata.
   * \param xid The transaction id from the request message.
   * \return 0 if everything's ok, otherwise an error number.
   */
  //\{
  ofl_err HandleEchoRequest (ofl_msg_echo *msg, SwitchInfo swtch, uint64_t xid);
  ofl_err HandleEchoReply (ofl_msg_echo *msg, SwitchInfo swtch, uint64_t xid);
  virtual ofl_err HandlePacketIn (ofl_msg_packet_in *msg, SwitchInfo swtch, uint64_t xid) = 0;
  virtual ofl_err HandleError (ofl_msg_error *msg, SwitchInfo swtch, uint64_t xid);
  virtual ofl_err HandleFeaturesReply (ofl_msg_features_reply *msg, SwitchInfo swtch, uint64_t xid);
  virtual ofl_err HandleGetConfigReply (ofl_msg_get_config_reply *msg, SwitchInfo swtch, uint64_t xid);
  virtual ofl_err HandleFlowRemoved (ofl_msg_flow_removed *msg, SwitchInfo swtch, uint64_t xid);
  virtual ofl_err HandlePortStatus (ofl_msg_port_status *msg, SwitchInfo swtch, uint64_t xid);
  virtual ofl_err HandleAsyncReply (ofl_msg_async_config *msg, SwitchInfo swtch, uint64_t xid);
  virtual ofl_err HandleMultipartReply (ofl_msg_multipart_reply_header *msg, SwitchInfo swtch, uint64_t xid);
  virtual ofl_err HandleRoleReply (ofl_msg_role_request *msg, SwitchInfo swtch, uint64_t xid);
  virtual ofl_err HandleQueueGetConfigReply (ofl_msg_queue_get_config_reply *msg, SwitchInfo swtch, uint64_t xid);
  //\}

  typedef std::map<Ipv4Address, SwitchInfo> SwitchsMap_t;   //!< Structure to map IPv4 to switch info
  SwitchsMap_t m_switchesMap;                               //!< Registered switch metadata

private:
  /**
   * Called by the SocketRead when a packet is received from the switch.
   * Dispatches control messages to appropriate handler functions.
   * \param swtch The switch the message was received from.
   * \param msg The OFLib message received.
   * \param xid The transaction id.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int ReceiveFromSwitch (SwitchInfo swtch, ofl_msg_header *msg, uint32_t xid);

  /**
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

  uint32_t              m_xid;                      //!< Global transaction idx
  uint16_t              m_port;                     //!< Local controller tcp port
  Ptr<Socket>           m_serverSocket;             //!< Listening server socket
  
  ofs::EchoMsgMap_t m_echoMap;                      //!< Metadata for echo requests
  SwitchConnectionCallback_t m_connectionCallback;  //!< TCP connection callback
};

} // namespace ns3
#endif /* OFSWITCH13_CONTROLLER_H */
