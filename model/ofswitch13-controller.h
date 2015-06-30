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
class OFSwitch13Controller;

/**
 * \ingroup ofswitch13
 * \brief Switch metadata used by controller
 */
struct SwitchInfo
{
  Ipv4Address ipv4;                 //!< Switch IPv4 address
  Ptr<OFSwitch13NetDevice> netdev;  //!< OpenFlow NetDevice
  Ptr<Node> node;                   //!< Switch node
  Ptr<OFSwitch13Controller> ctrl;   //!< Controller application
  Ptr<Socket> socket;               //!< TCP socket connected to controller
  uint16_t port;                    //!< Socket port

  InetSocketAddress GetInet ();     //!< Get Inet address conversion
};

/**
 * \ingroup ofswitch13
 * \brief An OpenFlow 1.3 controller base class for OFSwitch13NetDevice devices.
 */
class OFSwitch13Controller : public Application
{
public:
  OFSwitch13Controller ();          //!< Default constructor
  virtual ~OFSwitch13Controller (); //!< Dummy destructor, see DoDispose.

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
   * Look for registered switch metadata from OpenFlow device.
   * \param dev The OpenFlow NetDevice.
   * \return The switch metadata information.
   */
  SwitchInfo GetSwitchMetadata (Ptr<const OFSwitch13NetDevice> dev);

  /**
   * \brief Execute a dpctl command to interact with the switch.
   * \param swtch The target switch metadata
   * \param textCmd The dpctl command to create the message.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int DpctlCommand (SwitchInfo swtch, const std::string textCmd);

  /**
   * \brief Execute a dpctl command to interact with the switch.
   * \param swtch The target switch device
   * \param textCmd The dpctl command to create the message.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int DpctlCommand (Ptr<const OFSwitch13NetDevice> swtch, 
                    const std::string textCmd);

  /**
   * Overriding ofsoftswitch13 dpctl_send_and_print  and
   * dpctl_transact_and_print weak functions from utilities/dpctl.c. Send a
   * message from controller to switch.
   * \param swtch The SwitchInfo pointer, sent from controller to
   * dpctl_exec_ns3_command function and get back here to proper identify the
   * controller object.
   * \param msg The OFLib message to send.
   */
  static void DpctlSendAndPrint (vconn *swtch, ofl_msg_header *msg);

protected:
  // inherited from Application
  virtual void StartApplication (void);
  virtual void StopApplication (void);

  /**
   * \return The next (in sequence) transaction ID for this controller.
   */
  uint32_t GetNextXid ();

  /**
   * \brief Function invoked whenever a switch starts a TCP connection to this
   * controller. Derived classes can override this function to implement any
   * relevant logic.
   * \param swtch The connected switch.
   */
  virtual void ConnectionStarted (SwitchInfo swtch);

  /**
   * Send a OFLib message to a registered switch.
   * \param swtch The switch to receive the message.
   * \param msg The OFLib message to send.
   * \param xid The transaction id to use.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int SendToSwitch (SwitchInfo *swtch, ofl_msg_header *msg, uint32_t xid = 0);

  /**
   * Send an echo request message to switch, and wait for a reply.
   * \param swtch The switch to receive the message.
   * \param payloadSize The ammount of dummy bytes in echo message.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int SendEchoRequest (SwitchInfo swtch, size_t payloadSize = 0);

  /**
   * Send a barrier request message to switch, and wait for a reply.
   * \param swtch The switch to receive the message.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int SendBarrierRequest (SwitchInfo swtch);

  /**
   * \name OpenFlow message handlers
   * Handlers used by ReceiveFromSwitch to proccess each type of OpenFlow
   * message received from the switch. Some handler methods can not be
   * overwritten by derived class (echo request/reply), as they must behave as
   * already implemented. In constrast, packetIn must be implementd by the
   * derived controller, to proper handle packets sent from switch to
   * controller. The current implementation of other virtual methods does
   * nothing: just free the received message and returns 0. Derived controllers
   * can reimplement them as they wish.
   *
   * For HandleMultipartReply, note that there are several types of multipart
   * replies. Derived controlleres can filter by the type they wish.
   *
   * \attention Handlers \em MUST free received msg when everything is ok.
   * \param msg The OpenFlow received message.
   * \param swtch The source switch metadata.
   * \param xid The transaction id from the request message.
   * \return 0 if everything's ok, otherwise an error number.
   */
  //\{
  ofl_err
  HandleEchoRequest (ofl_msg_echo *msg, SwitchInfo swtch, uint32_t xid);

  ofl_err
  HandleEchoReply (ofl_msg_echo *msg, SwitchInfo swtch, uint32_t xid);

  virtual ofl_err
  HandlePacketIn (ofl_msg_packet_in *msg, SwitchInfo swtch, uint32_t xid) = 0;

  virtual ofl_err
  HandleError (ofl_msg_error *msg, SwitchInfo swtch, uint32_t xid);

  virtual ofl_err
  HandleFeaturesReply (ofl_msg_features_reply *msg, SwitchInfo swtch, uint32_t xid);

  virtual ofl_err
  HandleGetConfigReply (ofl_msg_get_config_reply *msg, SwitchInfo swtch, uint32_t xid);

  virtual ofl_err
  HandleFlowRemoved (ofl_msg_flow_removed *msg, SwitchInfo swtch, uint32_t xid);

  virtual ofl_err
  HandlePortStatus (ofl_msg_port_status *msg, SwitchInfo swtch, uint32_t xid);

  virtual ofl_err
  HandleAsyncReply (ofl_msg_async_config *msg, SwitchInfo swtch, uint32_t xid);

  virtual ofl_err
  HandleMultipartReply (ofl_msg_multipart_reply_header *msg, SwitchInfo swtch, uint32_t xid);

  virtual ofl_err
  HandleRoleReply (ofl_msg_role_request *msg, SwitchInfo swtch, uint32_t xid);

  virtual ofl_err
  HandleQueueGetConfigReply (ofl_msg_queue_get_config_reply *msg, SwitchInfo swtch, uint32_t xid);
  //\}

  /** Echo request metadata used by controller. */
  struct EchoInfo
  {
    bool waiting;                 //!< True when waiting for reply
    Time send;                    //!< Send time
    Time recv;                    //!< Received time
    Ipv4Address destIp;           //!< Destination IPv4

    EchoInfo (Ipv4Address ip);    //!< Constructor
    Time GetRtt ();               //!< Compute the echo RTT
  };

  /** Structure to map IPv4 to switch info */
  typedef std::map<Ipv4Address, SwitchInfo> SwitchsMap_t;
  SwitchsMap_t m_switchesMap; //!< Registered switches metadata's

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
  bool SocketRequest    (Ptr<Socket> socket, const Address& from);  //!< TCP request from switch
  void SocketAccept     (Ptr<Socket> socket, const Address& from);  //!< TCP handshake succeeded
  void SocketPeerClose  (Ptr<Socket> socket);                       //!< TCP connection closed
  void SocketPeerError  (Ptr<Socket> socket);                       //!< TCP connection error
  //\}

  /**
   * Save a Dpctl command to be executed just after the connection
   * establishment between switch and controller.
   * \param textCmd The Dpctl command.
   * \param swtch The switch metadata.
   */
  void ScheduleCommand (SwitchInfo swtch, const std::string textCmd);

  /** Structure to store echo information */
  typedef std::map<uint32_t, EchoInfo> EchoMsgMap_t;

  /** Multimap saving pair <pointer to device / dpctl command str> */
  typedef std::multimap<Ptr<OFSwitch13NetDevice>, std::string> DevCmdMap_t;

  uint32_t      m_xid;              //!< Global transaction idx
  uint16_t      m_port;             //!< Local controller tcp port
  Ptr<Socket>   m_serverSocket;     //!< Listening server socket

  EchoMsgMap_t  m_echoMap;          //!< Metadata for echo requests
  DevCmdMap_t   m_schedCommands;    //!< Scheduled commands for execution
};

} // namespace ns3
#endif /* OFSWITCH13_CONTROLLER_H */
