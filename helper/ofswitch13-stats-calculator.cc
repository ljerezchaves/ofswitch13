/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
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

#include <ns3/simulator.h>
#include <ns3/log.h>
#include <ns3/config.h>
#include <iomanip>
#include <iostream>
#include <numeric>
#include "ofswitch13-stats-calculator.h"

using namespace std;

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13StatsCalculator");
NS_OBJECT_ENSURE_REGISTERED (OFSwitch13StatsCalculator);

OFSwitch13StatsCalculator::OFSwitch13StatsCalculator ()
{
  NS_LOG_FUNCTION (this);
  ResetCounters ();
}

OFSwitch13StatsCalculator::~OFSwitch13StatsCalculator ()
{
  NS_LOG_FUNCTION (this);
}

TypeId
OFSwitch13StatsCalculator::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::OFSwitch13StatsCalculator")
    .SetParent<Object> ()
    .SetGroupName ("OFSwitch13")
    .AddConstructor<OFSwitch13StatsCalculator> ()
    .AddAttribute ("OutputFilename",
                   "Filename for dumping switch statistics.",
                   TypeId::ATTR_GET | TypeId::ATTR_CONSTRUCT,
                   StringValue ("ofswitch_stats.log"),
                   MakeStringAccessor (&OFSwitch13StatsCalculator::m_filename),
                   MakeStringChecker ())
    .AddAttribute ("DumpTimeout",
                   "The interval between dumping switch statistics.",
                   TimeValue (Seconds (1)),
                   MakeTimeAccessor (&OFSwitch13StatsCalculator::m_timeout),
                   MakeTimeChecker (Seconds (1)))
    .AddAttribute ("EwmaAlpha",
                   "The EWMA alpha parameter for averaging statistics.",
                   DoubleValue (0.85),
                   MakeDoubleAccessor (&OFSwitch13StatsCalculator::m_alpha),
                   MakeDoubleChecker<double> (0.0, 1.0))
  ;
  return tid;
}

void
OFSwitch13StatsCalculator::HookSinks (Ptr<OFSwitch13Device> device)
{
  NS_LOG_FUNCTION (this << device);

  device->TraceConnectWithoutContext (
    "PipelinePacket", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyPipelinePacket,
      Ptr<OFSwitch13StatsCalculator> (this)));
  device->TraceConnectWithoutContext (
    "MeterDrop", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyMeterDrop,
      Ptr<OFSwitch13StatsCalculator> (this)));
  device->TraceConnectWithoutContext (
    "PipelineDelay", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyPipelineDelay,
      Ptr<OFSwitch13StatsCalculator> (this)));
  device->TraceConnectWithoutContext (
    "BufferUsage", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyBufferUsage,
      Ptr<OFSwitch13StatsCalculator> (this)));
  device->TraceConnectWithoutContext (
    "FlowEntries", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyFlowEntries,
      Ptr<OFSwitch13StatsCalculator> (this)));
  device->TraceConnectWithoutContext (
    "MeterEntries", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyMeterEntries,
      Ptr<OFSwitch13StatsCalculator> (this)));
  device->TraceConnectWithoutContext (
    "GroupEntries", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyGroupEntries,
      Ptr<OFSwitch13StatsCalculator> (this)));
  device->TraceConnectWithoutContext (
    "FlowModCounter", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyFlowModCounter,
      Ptr<OFSwitch13StatsCalculator> (this)));
  device->TraceConnectWithoutContext (
    "MeterModCounter", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyMeterModCounter,
      Ptr<OFSwitch13StatsCalculator> (this)));
  device->TraceConnectWithoutContext (
    "GroupModCounter", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyGroupModCounter,
      Ptr<OFSwitch13StatsCalculator> (this)));
  device->TraceConnectWithoutContext (
    "PacketInCounter", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyPacketInCounter,
      Ptr<OFSwitch13StatsCalculator> (this)));
  device->TraceConnectWithoutContext (
    "PacketOutCounter", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyPacketOutCounter,
      Ptr<OFSwitch13StatsCalculator> (this)));
}

void
OFSwitch13StatsCalculator::DoDispose ()
{
  NS_LOG_FUNCTION (this);
  m_wrapper = 0;
}

void
OFSwitch13StatsCalculator::NotifyConstructionCompleted (void)
{
  NS_LOG_FUNCTION (this);

  // Open output file and print header line
  m_wrapper = Create<OutputStreamWrapper> (m_filename, std::ios::out);
  *m_wrapper->GetStream ()
  << fixed << setprecision (2)
  << left
  << setw (10) << "Time_s"
  << right
  << setw (12) << "Pkts/s"
  << setw (12) << "Drops/s"
  << setw (12) << "Kbits/s"
  << setw (12) << "FlowMod/s"
  << setw (12) << "MeterMod/s"
  << setw (12) << "GroupMod/s"
  << setw (12) << "PktIn/s"
  << setw (12) << "PktOut/s"
  << setw (12) << "Buffer_%"
  << setw (12) << "AvgFlows"
  << setw (12) << "AvgMeters"
  << setw (12) << "AvgGroups"
  << setw (12) << "AvgDelay_ns"
  << std::endl;

  // Scheduling first dump operation
  Simulator::Schedule (m_timeout, &OFSwitch13StatsCalculator::DumpStatistics,
                       this);

  // Chain up
  Object::NotifyConstructionCompleted ();
}

void
OFSwitch13StatsCalculator::NotifyPipelinePacket (Ptr<const Packet> packet)
{
  NS_LOG_FUNCTION (this << packet);

  m_pipelinePackets++;
  m_pipelineBytes += packet->GetSize ();
}

void
OFSwitch13StatsCalculator::NotifyMeterDrop (Ptr<const Packet> packet,
                                            uint32_t meterId)
{
  NS_LOG_FUNCTION (this << packet << meterId);

  m_droppedPackets++;
}

void
OFSwitch13StatsCalculator::NotifyPipelineDelay (Time oldValue,
                                                Time newValue)
{
  NS_LOG_FUNCTION (this << oldValue << newValue);

  m_avgPipelineDelay = newValue.GetDouble () * m_alpha
    + m_avgPipelineDelay * (1 - m_alpha);
}

void
OFSwitch13StatsCalculator::NotifyBufferUsage (double oldValue,
                                              double newValue)
{
  NS_LOG_FUNCTION (this << oldValue << newValue);

  m_avgBufferUsage = newValue * m_alpha + m_avgBufferUsage * (1 - m_alpha);
}

void
OFSwitch13StatsCalculator::NotifyFlowEntries (uint32_t oldValue,
                                              uint32_t newValue)
{
  NS_LOG_FUNCTION (this << oldValue << newValue);

  m_avgFlowEntries = newValue * m_alpha + m_avgFlowEntries * (1 - m_alpha);
}

void
OFSwitch13StatsCalculator::NotifyMeterEntries (uint32_t oldValue,
                                               uint32_t newValue)
{
  NS_LOG_FUNCTION (this << oldValue << newValue);

  m_avgMeterEntries = newValue * m_alpha + m_avgMeterEntries * (1 - m_alpha);
}

void
OFSwitch13StatsCalculator::NotifyGroupEntries (uint32_t oldValue,
                                               uint32_t newValue)
{
  NS_LOG_FUNCTION (this << oldValue << newValue);

  m_avgGroupEntries = newValue * m_alpha + m_avgGroupEntries * (1 - m_alpha);
}

void
OFSwitch13StatsCalculator::NotifyFlowModCounter (uint32_t oldValue,
                                                 uint32_t newValue)
{
  NS_LOG_FUNCTION (this << oldValue << newValue);

  m_flowModCounter++;
}

void
OFSwitch13StatsCalculator::NotifyMeterModCounter (uint32_t oldValue,
                                                  uint32_t newValue)
{
  NS_LOG_FUNCTION (this << oldValue << newValue);

  m_meterModCounter++;
}

void
OFSwitch13StatsCalculator::NotifyGroupModCounter (uint32_t oldValue,
                                                  uint32_t newValue)
{
  NS_LOG_FUNCTION (this << oldValue << newValue);

  m_groupModCounter++;
}

void
OFSwitch13StatsCalculator::NotifyPacketInCounter (uint32_t oldValue,
                                                  uint32_t newValue)
{
  NS_LOG_FUNCTION (this << oldValue << newValue);

  m_packetInCounter++;
}

void
OFSwitch13StatsCalculator::NotifyPacketOutCounter (uint32_t oldValue,
                                                   uint32_t newValue)
{
  NS_LOG_FUNCTION (this << oldValue << newValue);

  m_packetOutCounter++;
}

double
OFSwitch13StatsCalculator::GetPktsPerSec (void) const
{
  NS_LOG_FUNCTION (this);

  return (double)m_pipelinePackets / GetElapsedSeconds ();
}

double
OFSwitch13StatsCalculator::GetDropsPerSec (void) const
{
  NS_LOG_FUNCTION (this);

  return (double)m_droppedPackets / GetElapsedSeconds ();
}

double
OFSwitch13StatsCalculator::GetKbitsPerSec (void) const
{
  NS_LOG_FUNCTION (this);

  return (double)m_pipelineBytes * 8 / 1000 / GetElapsedSeconds ();
}

double
OFSwitch13StatsCalculator::GetFlowModsPerSec (void) const
{
  NS_LOG_FUNCTION (this);

  return (double)m_flowModCounter / GetElapsedSeconds ();
}

double
OFSwitch13StatsCalculator::GetMeterModsPerSec (void) const
{
  NS_LOG_FUNCTION (this);

  return (double)m_meterModCounter / GetElapsedSeconds ();
}

double
OFSwitch13StatsCalculator::GetGroupModsPerSec (void) const
{
  NS_LOG_FUNCTION (this);

  return (double)m_groupModCounter / GetElapsedSeconds ();
}

double
OFSwitch13StatsCalculator::GetPktsInPerSec (void) const
{
  NS_LOG_FUNCTION (this);

  return (double)m_packetInCounter / GetElapsedSeconds ();
}

double
OFSwitch13StatsCalculator::GetPktsOutPerSec (void) const
{
  NS_LOG_FUNCTION (this);

  return (double)m_packetOutCounter / GetElapsedSeconds ();
}

uint32_t
OFSwitch13StatsCalculator::GetAvgBufferUsage (void) const
{
  NS_LOG_FUNCTION (this);

  return std::round (100 * m_avgBufferUsage);
}

uint32_t
OFSwitch13StatsCalculator::GetAvgFlowEntries (void) const
{
  NS_LOG_FUNCTION (this);

  return std::round (m_avgFlowEntries);
}

uint32_t
OFSwitch13StatsCalculator::GetAvgMeterEntries (void) const
{
  NS_LOG_FUNCTION (this);

  return std::round (m_avgMeterEntries);
}

uint32_t
OFSwitch13StatsCalculator::GetAvgGroupEntries (void) const
{
  NS_LOG_FUNCTION (this);

  return std::round (m_avgGroupEntries);
}

uint32_t
OFSwitch13StatsCalculator::GetAvgPipelineDelay (void) const
{
  NS_LOG_FUNCTION (this);

  return (Time (m_avgPipelineDelay)).GetNanoSeconds ();
}

void
OFSwitch13StatsCalculator::DumpStatistics ()
{
  NS_LOG_FUNCTION (this);

  // Print statistics to file
  *m_wrapper->GetStream ()
  << left
  << setw (10) << Simulator::Now ().GetSeconds () << " "
  << right
  << setw (11) << GetPktsPerSec ()                << " "
  << setw (11) << GetDropsPerSec ()               << " "
  << setw (11) << GetKbitsPerSec ()               << " "
  << setw (11) << GetFlowModsPerSec ()            << " "
  << setw (11) << GetMeterModsPerSec ()           << " "
  << setw (11) << GetGroupModsPerSec ()           << " "
  << setw (11) << GetPktsInPerSec ()              << " "
  << setw (11) << GetPktsOutPerSec ()             << " "
  << setw (11) << GetAvgBufferUsage ()            << " "
  << setw (11) << GetAvgFlowEntries ()            << " "
  << setw (11) << GetAvgMeterEntries ()           << " "
  << setw (11) << GetAvgGroupEntries ()           << " "
  << setw (11) << GetAvgPipelineDelay ()          << " "
  << std::endl;

  // Reset counters and schedule next dump operation
  ResetCounters ();
  Simulator::Schedule (m_timeout, &OFSwitch13StatsCalculator::DumpStatistics,
                       this);
}

void
OFSwitch13StatsCalculator::ResetCounters ()
{
  NS_LOG_FUNCTION (this);
  m_lastDump = Simulator::Now ();

  m_pipelinePackets = 0;
  m_pipelineBytes = 0;
  m_droppedPackets = 0;
  m_flowModCounter = 0;
  m_meterModCounter = 0;
  m_groupModCounter = 0;
  m_packetInCounter = 0;
  m_packetOutCounter = 0;
}

double
OFSwitch13StatsCalculator::GetElapsedSeconds () const
{
  return (Simulator::Now () - m_lastDump).GetSeconds ();
}

} // Namespace ns3
