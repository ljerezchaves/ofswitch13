/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2016 University of Campinas (Unicamp)
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

#include "tunnel-user-app.h"
#include <ns3/epc-gtpu-header.h>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("TunnelUserApp");
NS_OBJECT_ENSURE_REGISTERED (TunnelUserApp);

TunnelUserApp::TunnelUserApp ()
{
}

TunnelUserApp::~TunnelUserApp ()
{
}

TunnelUserApp::TunnelUserApp (
  Ptr<VirtualNetDevice> logicalPort, Ipv4Address ipHostAddr,
  Address macHostAddr, Address macPortAddr, Ipv4Address ipTunnelAddr)
  : m_logicalPort (logicalPort),
    m_ipTunnelAddr (ipTunnelAddr),
    m_ipHostAddr (ipHostAddr),
    m_macHostAddr (Mac48Address::ConvertFrom (macHostAddr)),
    m_macPortAddr (Mac48Address::ConvertFrom (macPortAddr))
{
  m_logicalPort->SetSendCallback (
    MakeCallback (&TunnelUserApp::RecvFromLogicalPort, this));
}

TypeId
TunnelUserApp::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::TunnelUserApp")
    .SetParent<Application> ()
    .SetGroupName ("OFSwitch13")
  ;
  return tid;
}

void
TunnelUserApp::DoDispose ()
{
  NS_LOG_FUNCTION (this);

  m_tunnelSocket = 0;
  m_logicalPort = 0;
}

void
TunnelUserApp::StartApplication ()
{
  NS_LOG_FUNCTION (this << "Starting TunnelUserApp");

  // Create and open the UDP socket for tunnel
  m_tunnelSocket = Socket::CreateSocket (
      GetNode (), TypeId::LookupByName ("ns3::UdpSocketFactory"));
  m_tunnelSocket->Bind (InetSocketAddress (Ipv4Address::GetAny (), 2152));
  m_tunnelSocket->SetRecvCallback (
    MakeCallback (&TunnelUserApp::RecvFromTunnelSocket, this));
}

bool
TunnelUserApp::RecvFromLogicalPort (
  Ptr<Packet> packet, const Address& source, const Address& dest,
  uint16_t protocolNumber)
{
  NS_LOG_FUNCTION (this << packet << source << dest << protocolNumber);

  // Retrieve the GTP TEID from TunnelId tag, if available.
  TunnelIdTag tunnelIdTag;
  uint64_t teid = 0;
  if (packet->RemovePacketTag (tunnelIdTag))
    {
      teid = (uint32_t)tunnelIdTag.GetTunnelId ();
    }

  // Add the GTP header
  GtpuHeader gtpu;
  gtpu.SetTeid (teid);
  gtpu.SetLength (packet->GetSize () + gtpu.GetSerializedSize () - 8);
  packet->AddHeader (gtpu);

  // Send the packet to the tunnel socket
  NS_LOG_INFO ("Sending packet to IP " << m_ipTunnelAddr);
  m_tunnelSocket->SendTo (packet, 0, InetSocketAddress (m_ipTunnelAddr, 2152));
  return true;
}

void
TunnelUserApp::RecvFromTunnelSocket (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);

  NS_ASSERT (socket == m_tunnelSocket);
  Ptr<Packet> packet = socket->Recv ();

  // Remove the GTP header
  GtpuHeader gtpu;
  packet->RemoveHeader (gtpu);

  // Attach the GTP TEID withing the TunnelId tag.
  TunnelIdTag tunnelIdTag (gtpu.GetTeid ());
  packet->AddPacketTag (tunnelIdTag);

  // Add the Ethernet header to the packet and send it to the logical port
  AddHeader (packet, m_macPortAddr, m_macHostAddr, Ipv4L3Protocol::PROT_NUMBER);
  m_logicalPort->Receive (packet, Ipv4L3Protocol::PROT_NUMBER, m_macPortAddr,
                          m_macHostAddr, NetDevice::PACKET_HOST);
}

void
TunnelUserApp::AddHeader (Ptr<Packet> packet, Mac48Address source,
                          Mac48Address dest, uint16_t protocolNumber)
{
  NS_LOG_FUNCTION (packet << source << dest << protocolNumber);

  //
  // All Ethernet frames must carry a minimum payload of 46 bytes.  We need
  // to pad out if we don't have enough bytes.  These must be real bytes
  // since they will be written to pcap files and compared in regression
  // trace files.
  //
  if (packet->GetSize () < 46)
    {
      uint8_t buffer[46];
      memset (buffer, 0, 46);
      Ptr<Packet> padd = Create<Packet> (buffer, 46 - packet->GetSize ());
      packet->AddAtEnd (padd);
    }

  EthernetHeader header (false);
  header.SetSource (source);
  header.SetDestination (dest);
  header.SetLengthType (protocolNumber);
  packet->AddHeader (header);

  EthernetTrailer trailer;
  if (Node::ChecksumEnabled ())
    {
      trailer.EnableFcs (true);
    }
  trailer.CalcFcs (packet);
  packet->AddTrailer (trailer);
}

} // namespace ns3
