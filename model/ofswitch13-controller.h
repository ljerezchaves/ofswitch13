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

#include <ns3/application.h>
#include <ns3/socket.h>
#include "ofswitch13-interface.h"
#include "ofswitch13-socket-handler.h"
#include <string>

namespace ns3 {

/**
 * \ingroup ofswitch13
 * OpenFlow 1.3 controller base class that can handle a collection of OpenFlow
 * switches and provides the basic functionalities for controller
 * implementation. For constructing OpenFlow configuration messages and sending
 * them to the switches, this class uses the DpctlCommand function, which
 * relies on command-line syntax from the dpctl utility. For OpenFlow messages
 * coming from the switches, this class provides a collection of internal
 * handlers to deal with the different types of messages.
 */
class OFSwitch13Controller : public Application
{
protected:
  /**
   * \ingroup ofswitch13
   * Inner class to save information of a remote active OpenFlow switch
   * connected to this controller.
   */
  class RemoteSwitch : public SimpleRefCount<RemoteSwitch>
  {
    friend class OFSwitch13Controller;

public:
    /** Default (empty) constructor. */
    RemoteSwitch ();

    /**
     * Get the IP from socket connection address.
     * \return the IPv4 address.
     */
    Ipv4Address GetIpv4 (void) const;

    /**
     * Get the port from socket connection address.
     * \return the port number.
     */
    uint16_t GetPort (void) const;

    /**
     * Get the datapath ID.
     * \return the datapath ID.
     */
    uint64_t GetDpId (void) const;

private:
    Ptr<OFSwitch13SocketHandler>  m_handler;  //!< Socket handler.
    Address                       m_address;  //!< Switch connection address.
    Ptr<OFSwitch13Controller>     m_ctrlApp;  //!< Controller application.
    uint64_t                      m_dpId;     //!< OpenFlow datapath ID.
    enum ofp_controller_role      m_role;     //!< Controller role over switch.

    /**
     * Switch features informed to the controller during handshake procedure.
     */
    //\{
    uint32_t  m_nBuffers;     //!< Max packets buffered at once.
    uint8_t   m_nTables;      //!< Number of tables supported by datapath.
    uint8_t   m_auxiliaryId;  //!< Identify auxiliary connections.
    uint32_t  m_capabilities; //!< Bitmap of support ofp_capabilities.
    //\}

  };  // class RemoteSwitch

  /**
   * \ingroup ofswitch13
   * Structure to save echo request metadata used by the controller interface.
   */
  struct EchoInfo
  {
    friend class OFSwitch13Controller;

public:
    /**
     * Complete constructor, with remote switch.
     * \param swtch The remote switch.
     */
    EchoInfo (Ptr<const RemoteSwitch> swtch);

    /**
     * Compute the echo RTT time.
     * \return the RTT time.
     */
    Time GetRtt (void) const;

private:
    bool                    m_waiting;    //!< True when waiting for reply.
    Time                    m_send;       //!< Send time.
    Time                    m_recv;       //!< Received time.
    Ptr<const RemoteSwitch> m_swtch;      //!< Remote switch.
  };

  /**
   * \ingroup ofswitch13
   * Structure to save barrier metadata used by the controller interface.
   */
  struct BarrierInfo
  {
    friend class OFSwitch13Controller;

public:
    /**
     * Complete constructor, with remote switch.
     * \param swtch The remote switch.
     */
    BarrierInfo (Ptr<const RemoteSwitch> swtch);

private:
    bool                    m_waiting;    //!< True when waiting for reply.
    Ptr<const RemoteSwitch> m_swtch;      //!< Remote switch.
  };

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
   * Execute a dpctl command to interact with the remote switch.
   * \param swtch The target remote switch.
   * \param textCmd The dpctl command to execute.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int DpctlExecute (Ptr<const RemoteSwitch> swtch, const std::string textCmd);

  /**
   * Execute a dpctl command to interact with the remote switch.
   * \param dpId The OpenFlow datapath ID.
   * \param textCmd The dpctl command to execute.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int DpctlExecute (uint64_t dpId, const std::string textCmd);

  /**
   * Schedule a dpctl command to be executed after a successfull handshake with
   * the remote switch.
   * \param dpId The OpenFlow datapath ID.
   * \param textCmd The dpctl command to be executed.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int DpctlSchedule (uint64_t dpId, const std::string textCmd);

  /**
   * Overriding ofsoftswitch13 dpctl_send_and_print  and
   * dpctl_transact_and_print weak functions from utilities/dpctl.c. Send a
   * message from controller to switch.
   * \param vconn The RemoteSwitch pointer, sent from controller to
   * dpctl_exec_ns3_command function and get back here to proper identify the
   * controller object.
   * \param msg The OFLib message to send.
   */
  static void DpctlSendAndPrint (struct vconn *vconn,
                                 struct ofl_msg_header *msg);

protected:
  // inherited from Application
  virtual void StartApplication (void);
  virtual void StopApplication (void);

  /**
   * \return The next (in sequence) transaction ID for this controller.
   */
  uint32_t GetNextXid ();

  /**
   * Function invoked after a successfully handshake procedure between
   * this controller and a remote switch. Derived classes can override this
   * function to implement any relevant logic, as sending initial configuration
   * messages to the switch.
   * \param swtch The remote switch.
   */
  virtual void HandshakeSuccessful (Ptr<const RemoteSwitch> swtch);

  /**
   * Get the remote switch for this OpenFlow datapath ID.
   * \param dpId The OpenFlow datapath ID.
   * \return The remote switch.
   */
  Ptr<const RemoteSwitch> GetRemoteSwitch (uint64_t dpId) const;

  /**
   * Send a OFLib message to a registered switch.
   * \param swtch The remote switch to receive the message.
   * \param msg The OFLib message to send.
   * \param xid The transaction id to use.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int SendToSwitch (Ptr<const RemoteSwitch> swtch, struct ofl_msg_header *msg,
                    uint32_t xid = 0);

  /**
   * Send an echo request message to switch, and wait for a non-blocking reply.
   * \param swtch The remote switch to receive the message.
   * \param payloadSize The ammount of dummy bytes in echo message.
   */
  void SendEchoRequest (Ptr<const RemoteSwitch> swtch, size_t payloadSize = 0);

  /**
   * Send a barrier request message to switch, and wait for a non-blocking
   * reply. Note that current OpenFlow device implementation is single-threaded
   * and messages are processed in the same order that are received from the
   * controller, so a barrier request will simply be replied by the switch.
   * \param swtch The remote switch to receive the message.
   */
  void SendBarrierRequest (Ptr<const RemoteSwitch> swtch);

  /**
   * \name OpenFlow message handlers
   * Handlers used by HandleSwitchMsg to process each type of OpenFlow message
   * received from the switch. Some (non virtual) handlers can not be
   * overwritten by derived class, as they must behave as already implemented.
   * The current implementation of other virtual handler methods does nothing:
   * just free the received message and returns 0. Derived controllers can
   * override them as they wish to implement the desired control logic.
   *
   * Note that for HandleMultipartReply there are several types of multipart
   * messages. Derived controllers can filter by the type they wish.
   *
   * \attention Handlers \em MUST free received msg when everything is ok.
   * \param msg The OpenFlow received message.
   * \param swtch The remote switch metadata.
   * \param xid The transaction id from the request message.
   * \return 0 if everything's ok, otherwise an error number.
   */
  //\{
  ofl_err HandleEchoRequest (
    struct ofl_msg_echo *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

  ofl_err HandleEchoReply (
    struct ofl_msg_echo *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

  ofl_err HandleBarrierReply (
    struct ofl_msg_header *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

  ofl_err HandleHello (
    struct ofl_msg_header *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

  ofl_err HandleFeaturesReply (
    struct ofl_msg_features_reply *msg, Ptr<RemoteSwitch> swtch,
    uint32_t xid);

  virtual ofl_err HandlePacketIn (
    struct ofl_msg_packet_in *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

  virtual ofl_err HandleError (
    struct ofl_msg_error *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

  virtual ofl_err HandleGetConfigReply (
    struct ofl_msg_get_config_reply *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

  virtual ofl_err HandleFlowRemoved (
    struct ofl_msg_flow_removed *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

  virtual ofl_err HandlePortStatus (
    struct ofl_msg_port_status *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

  virtual ofl_err HandleAsyncReply (
    struct ofl_msg_async_config *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

  virtual ofl_err HandleMultipartReply (
    struct ofl_msg_multipart_reply_header *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

  virtual ofl_err HandleRoleReply (
    struct ofl_msg_role_request *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);

  virtual ofl_err HandleQueueGetConfigReply (
    struct ofl_msg_queue_get_config_reply *msg, Ptr<const RemoteSwitch> swtch,
    uint32_t xid);
  //\}

private:
  /**
   * Called when an OpenFlow message is received from a switch.
   * Dispatches control messages to appropriate handler functions.
   * \param msg The OFLib message received.
   * \param swtch The remote switch the message was received from.
   * \param xid The transaction id.
   * \return 0 if everything's ok, otherwise an error number.
   */
  ofl_err HandleSwitchMsg (struct ofl_msg_header *msg, Ptr<RemoteSwitch> swtch,
                           uint32_t xid);

  /**
   * Receive an OpenFlow packet from switch.
   * \param packet The packet with the OpenFlow message.
   * \param from The packet sender address.
   */
  void ReceiveFromSwitch (Ptr<Packet> packet, Address from);

  /**
   * Get the remote switch for this address.
   * \param address The socket address.
   * \return The remote switch.
   */
  Ptr<RemoteSwitch> GetRemoteSwitch (Address address);

  /**
   * \name Socket callbacks
   * Handlers used as socket callbacks to TCP communication between this
   * switch and the controller.
   * \param socket The TCP socket.
   * \param from The source Address
   */
  //\{
  /** TCP request from switch */
  bool SocketRequest    (Ptr<Socket> socket, const Address& from);

  /** TCP handshake succeeded */
  void SocketAccept     (Ptr<Socket> socket, const Address& from);

  /** TCP connection closed */
  void SocketPeerClose  (Ptr<Socket> socket);

  /** TCP connection error */
  void SocketPeerError  (Ptr<Socket> socket);
  //\}

  /** Map to store echo information by transaction id */
  typedef std::map <uint32_t, EchoInfo> EchoMsgMap_t;

  /** Map to store barrier information by transaction id */
  typedef std::map <uint32_t, BarrierInfo> BarrierMsgMap_t;

  /** Multimap saving pair <datapath id / dpctl commands> */
  typedef std::multimap <uint64_t, std::string> DpIdCmdMap_t;

  /** Map to store switch info by Address */
  typedef std::map <Address, Ptr<RemoteSwitch> > SwitchsMap_t;

  uint32_t        m_xid;              //!< Global transaction idx.
  uint16_t        m_port;             //!< Local controller tcp port.
  Ptr<Socket>     m_serverSocket;     //!< Listening server socket.

  EchoMsgMap_t    m_echoMap;          //!< Metadata for echo requests.
  BarrierMsgMap_t m_barrierMap;       //!< Metadata for barrier requests.
  DpIdCmdMap_t    m_schedCommands;    //!< Scheduled commands for execution.
  SwitchsMap_t    m_switchesMap;      //!< Registered switches metadata's.
};

} // namespace ns3
#endif /* OFSWITCH13_CONTROLLER_H */
