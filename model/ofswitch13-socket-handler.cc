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

#include "ofswitch13-socket-handler.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13SocketHandler");
NS_OBJECT_ENSURE_REGISTERED (OFSwitch13SocketHandler);

TypeId
OFSwitch13SocketHandler::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OFSwitch13SocketHandler")
    .SetParent<Object> ()
    .SetGroupName ("OFSwitch13")
  ;
  return tid;
}

OFSwitch13SocketHandler::OFSwitch13SocketHandler (Ptr<Socket> socket)
  : m_socket (socket),
  m_pendingPacket (0),
  m_pendingBytes (0),
  m_txQueue ()
{
  NS_LOG_FUNCTION (this << socket);

  // Setup socket callbacks.
  socket->SetSendCallback (
    MakeCallback (&OFSwitch13SocketHandler::Send, this));
  socket->SetRecvCallback (
    MakeCallback (&OFSwitch13SocketHandler::Recv, this));
}

OFSwitch13SocketHandler::~OFSwitch13SocketHandler ()
{
  NS_LOG_FUNCTION (this);
}

void
OFSwitch13SocketHandler::SetReceiveCallback (MessageCallback cb)
{
  NS_LOG_FUNCTION (this);

  m_receivedMsg = cb;
}

int
OFSwitch13SocketHandler::SendMessage (Ptr<Packet> packet)
{
  NS_LOG_FUNCTION (this << packet);

  // Insert this message into tx queue and try to forward it to the socket.
  m_txQueue.push (packet);
  Send (m_socket, m_socket->GetTxAvailable ());
  return 0;
}

void
OFSwitch13SocketHandler::DoDispose ()
{
  NS_LOG_FUNCTION (this);

  m_socket = 0;
  m_pendingPacket = 0;
}

void
OFSwitch13SocketHandler::Send (Ptr<Socket> socket, uint32_t available)
{
  NS_LOG_FUNCTION (this << socket << available);

  while (!m_txQueue.empty ())
    {
      // Get a reference for the next packet in the queue and check for
      // available space in socket tx buffer.
      Ptr<Packet> packet = m_txQueue.front ();
      if (socket->GetTxAvailable () < packet->GetSize ())
        {
          NS_LOG_WARN ("No space available to send message now.");
          return;
        }

      // Remove the packet from the queue and send it to the socket.
      m_txQueue.pop ();
      int retval = socket->Send (packet);
      if (retval == -1)
        {
          NS_LOG_ERROR ("Error while sending OpenFlow message to socket. " <<
                        "Discarding. Socket error: " << socket->GetErrno ());
        }
    }
}

void
OFSwitch13SocketHandler::Recv (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);

  static const size_t ofpHeaderSize = sizeof (struct ofp_header);
  Address from;

  // Repeat the loop until socket buffer gets empty.
  while (socket->GetRxAvailable ())
    {
      // If we don't have pending bytes from an incomplete OpenFlow messages it
      // means that this is the start of a new message.
      if (!m_pendingBytes)
        {
          // At least 8 bytes from the OpenFlow header must be available.
          if (socket->GetRxAvailable () < 8)
            {
              return; // Wait for more bytes.
            }

          // Read the OpenFlow header and get the OpenFlow message size.
          struct ofp_header header;
          m_pendingPacket = socket->RecvFrom (ofpHeaderSize, 0, from);
          m_pendingPacket->CopyData ((uint8_t*)&header, ofpHeaderSize);
          m_pendingBytes = ntohs (header.length) - ofpHeaderSize;
        }

      // If we have pending bytes from an incomplete OpenFlow message and we
      // also have bytes available to read at socket, let's read them now.
      uint32_t read = std::min (m_pendingBytes, socket->GetRxAvailable ());
      if (read)
        {
          m_pendingPacket->AddAtEnd (socket->RecvFrom (read, 0, from));
          m_pendingBytes -= read;
        }

      // If we don't have pending bytes anymore it means that now we have a
      // complete OpenFlow message.
      if (!m_pendingBytes)
        {
          // Let's send the message to the registered callback.
          if (!m_receivedMsg.IsNull ())
            {
              m_receivedMsg (m_pendingPacket, from);
            }
          m_pendingPacket = 0;
        }
    }
}

} // namespace ns3
