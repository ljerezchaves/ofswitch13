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

#include "tunnel.h"
#include <ns3/epc-gtpu-header.h>

using namespace ns3;

NS_OBJECT_ENSURE_REGISTERED (TunnelController);

TunnelController::TunnelController ()
{
}

TunnelController::~TunnelController ()
{
}

void
TunnelController::HandshakeSuccessful (Ptr<const RemoteSwitch> swtch)
{
  // Allow ARP packets to be forwarded regardless logical ports and tunnel ids.
  DpctlExecute (swtch,
                "flow-mod cmd=add,table=0,prio=2 "
                "in_port=1,eth_type=0x0806 "
                "write:output=2");
  DpctlExecute (swtch,
                "flow-mod cmd=add,table=0,prio=2 "
                "in_port=2,eth_type=0x0806 "
                "write:output=1");

  // IP packets entering the switch from the physical port 1 are coming from
  // the host node. In this case, set the arbitrary value 0xFFFF for the tunnel
  // id at table 0 and match this tunnel id at table 1. These packets are
  // forwarded to the other switch on the logical port 2.
  DpctlExecute (swtch,
                "flow-mod cmd=add,table=0,prio=1 "
                "in_port=1,eth_type=0x0800 "
                "apply:set_field=tunn_id:0xFFFF goto:1");
  DpctlExecute (swtch,
                "flow-mod cmd=add,table=1,prio=1 "
                "tunn_id=0xFFFF "
                "write:output=2");

  // IP packets entering the switch from the logical port have already been
  // de-encapsulated by the logical port operation, and the tunnel id must
  // match the arbitrary value 0xFFFF. Theses packets are forwarded to the host
  // on the physical port 1.
  DpctlExecute (swtch,
                "flow-mod cmd=add,table=0,prio=1 "
                "in_port=2,eth_type=0x0800,tunn_id=0xFFFF "
                "write:output=1");
}

TunnelHandler::TunnelHandler ()
{
}

TunnelHandler::~TunnelHandler ()
{
}

uint64_t
TunnelHandler::Receive (uint64_t dpId, uint32_t portNo, Ptr<Packet> packet)
{
  uint64_t teid = 0;

  // Remove the existing Ethernet header and trailer
  EthernetTrailer ethTrailer;
  packet->RemoveTrailer (ethTrailer);
  EthernetHeader ethHeader;
  packet->RemoveHeader (ethHeader);

  // We only de-encapsulate IP packets
  if (ethHeader.GetLengthType () == Ipv4L3Protocol::PROT_NUMBER)
    {
      // Remove IP header
      Ipv4Header ipHeader;
      packet->RemoveHeader (ipHeader);

      // Remove UDP header
      UdpHeader udpHeader;
      packet->RemoveHeader (udpHeader);

      // Remove GTP-U header and set return value
      GtpuHeader gtpuHeader;
      packet->RemoveHeader (gtpuHeader);
      teid = gtpuHeader.GetTeid ();
    }

  // Add Ethernet header and trailer back
  packet->AddHeader (ethHeader);
  packet->AddTrailer (ethTrailer);

  return teid;
}

void
TunnelHandler::Send (uint64_t dpId, uint32_t portNo, Ptr<Packet> packet,
                     uint64_t tunnelId)
{
  // Remove the existing Ethernet header and trailer
  EthernetTrailer ethTrailer;
  packet->RemoveTrailer (ethTrailer);
  EthernetHeader ethHeader;
  packet->RemoveHeader (ethHeader);

  // We only encapsulate IP packets within GTP-U/UDP/IP protocols
  if (ethHeader.GetLengthType () == Ipv4L3Protocol::PROT_NUMBER)
    {
      // We are using arbitrary IP addresses for the tunnel
      Ipv4Address srcAddr = Ipv4Address ("192.168.1.1");
      Ipv4Address dstAddr = Ipv4Address ("192.168.1.2");

      // Add GTP-U header using parameter tunnelId
      GtpuHeader gtpuHeader;
      gtpuHeader.SetTeid (tunnelId);
      gtpuHeader.SetLength (packet->GetSize () +
                            gtpuHeader.GetSerializedSize () - 8);
      packet->AddHeader (gtpuHeader);

      // Add UDP header
      UdpHeader udpHeader;
      udpHeader.EnableChecksums ();
      udpHeader.InitializeChecksum (srcAddr, dstAddr,
                                    UdpL4Protocol::PROT_NUMBER);
      udpHeader.SetDestinationPort (2152);
      udpHeader.SetSourcePort (2152);
      packet->AddHeader (udpHeader);

      // Add IP header
      Ipv4Header ipHeader;
      ipHeader.SetSource (srcAddr);
      ipHeader.SetDestination (dstAddr);
      ipHeader.SetProtocol (UdpL4Protocol::PROT_NUMBER);
      ipHeader.SetPayloadSize (packet->GetSize ());
      ipHeader.SetTtl (64);
      ipHeader.SetTos (0);
      ipHeader.SetDontFragment ();
      ipHeader.SetIdentification (0);
      ipHeader.EnableChecksum ();
      packet->AddHeader (ipHeader);
    }

  // Add Ethernet header and trailer back
  packet->AddHeader (ethHeader);
  packet->AddTrailer (ethTrailer);
}
