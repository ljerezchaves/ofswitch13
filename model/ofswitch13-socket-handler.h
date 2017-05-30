/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017 University of Campinas (Unicamp)
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

#ifndef OFSWITCH13_SOCKET_HANDLER_H
#define OFSWITCH13_SOCKET_HANDLER_H

#include <ns3/simulator.h>
#include <ns3/log.h>
#include <ns3/packet.h>
#include <ns3/socket.h>
#include "ofswitch13-interface.h"
#include <queue>

namespace ns3 {

/**
 * \ingroup ofswitch13
 * Class used to read/send single OpenFlow message from/to an open socket.
 * The TCP socket receive callback is connected to the Recv () method, which is
 * responsible for reading the correct number of bytes of a complete OpenFlow
 * message. When the OpenFlow message is completely received, it is sent to the
 * connected callback that was previously set using the SetReceiveCallback ()
 * method. On the other direction, the TCP socket send callback is connected to
 * the Send () method that forwards OpenFlow message received by the
 * SendMessage () method to the open socket, respecting the original order of
 * the messages.
 */
class OFSwitch13SocketHandler : public Object
{
public:
  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);

  /**
   * Complete constructor.
   * \param socket The socket pointer.
   */
  OFSwitch13SocketHandler (Ptr<Socket> socket);
  virtual ~OFSwitch13SocketHandler ();   //!< Dummy destructor, see DoDispose.

  /**
   * \param packet The packet with the received OpenFlow message.
   * \param sender The address of the sender.
   */
  typedef Callback <void, Ptr<Packet>, Address > MessageCallback;

  /**
   * Set the callback to invoke whenever an OpenFlow message has been received
   * at the associated socket.
   * \param cb The callback to invoke.
   */
  void SetReceiveCallback (MessageCallback cb);

  /**
   * Send an OpenFlow message to the TCP socket.
   * \param packet The packet with the OpenFlow message.
   * \return 0 if everything's ok, otherwise an error number.
   */
  int SendMessage (Ptr<Packet> packet);

protected:
  /** Destructor implementation */
  virtual void DoDispose ();

private:
  /**
   * Callback for bytes available in tx buffer.
   * \param socket The connected socket.
   * \param available The number of bytes available into tx buffer.
   */
  void Send (Ptr<Socket> socket, uint32_t available);

  /**
   * Callback for bytes available in rx buffer.
   * \param socket The connected socket.
   */
  void Recv (Ptr<Socket> socket);

  Ptr<Socket>               m_socket;         //!< TCP socket.
  Ptr<Packet>               m_pendingPacket;  //!< Buffer for receiving bytes.
  uint32_t                  m_pendingBytes;   //!< Pending bytes for message.
  MessageCallback           m_receivedMsg;    //!< OpenFlow message callback.
  std::queue<Ptr<Packet> >  m_txQueue;        //!< TX queue.
};

} // namespace ns3
#endif /* OFSWITCH13_SOCKET_HANDLER_H */
