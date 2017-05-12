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
  : m_device (0),
    m_wrapper (0),
    m_lastUpdate (Simulator::Now ()),
    m_avgBufferUsage (0),
    m_avgFlowEntries (0),
    m_avgGroupEntries (0),
    m_avgMeterEntries (0),
    m_avgPipelineDelay (0),
    m_bufferUsageUp (false),
    m_flowEntriesUp (false),
    m_groupEntriesUp (false),
    m_meterEntriesUp (false),
    m_pipelineDelayUp (false),
    m_byteCounter (0),
    m_loadDropCounter (0),
    m_meterDropCounter (0),
    m_flowModCounter (0),
    m_groupModCounter (0),
    m_meterModCounter (0),
    m_packetInCounter (0),
    m_packetOutCounter (0),
    m_lastFlowModCounter (0),
    m_lastGroupModCounter (0),
    m_lastMeterModCounter (0),
    m_lastPacketInCounter (0),
    m_lastPacketOutCounter (0)
{
  NS_LOG_FUNCTION (this);
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
    .AddAttribute ("EwmaAlpha",
                   "The EWMA alpha parameter for averaging statistics.",
                   DoubleValue (0.9),
                   MakeDoubleAccessor (&OFSwitch13StatsCalculator::m_alpha),
                   MakeDoubleChecker<double> (0.0, 1.0))
    .AddAttribute ("DumpTimeout",
                   "The interval to update and dump switch statistics.",
                   TimeValue (Seconds (1)),
                   MakeTimeAccessor (&OFSwitch13StatsCalculator::m_timeout),
                   MakeTimeChecker (Seconds (1)))
    .AddAttribute ("OutputFilename",
                   "Filename for dumping switch statistics.",
                   TypeId::ATTR_GET | TypeId::ATTR_CONSTRUCT,
                   StringValue ("ofswitch_stats.log"),
                   MakeStringAccessor (&OFSwitch13StatsCalculator::m_filename),
                   MakeStringChecker ())
  ;
  return tid;
}

void
OFSwitch13StatsCalculator::HookSinks (Ptr<OFSwitch13Device> device)
{
  NS_LOG_FUNCTION (this << device);

  // Save switch device pointer.
  m_device = device;

  // Hook sinks.
  device->TraceConnectWithoutContext (
    "LoadDrop", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyLoadDrop,
      Ptr<OFSwitch13StatsCalculator> (this)));
  device->TraceConnectWithoutContext (
    "MeterDrop", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyMeterDrop,
      Ptr<OFSwitch13StatsCalculator> (this)));
  device->TraceConnectWithoutContext (
    "PipelinePacket", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyPipelinePacket,
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
    "GroupEntries", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyGroupEntries,
      Ptr<OFSwitch13StatsCalculator> (this)));
  device->TraceConnectWithoutContext (
    "MeterEntries", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyMeterEntries,
      Ptr<OFSwitch13StatsCalculator> (this)));
  device->TraceConnectWithoutContext (
    "PipelineDelay", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyPipelineDelay,
      Ptr<OFSwitch13StatsCalculator> (this)));
}

Time
OFSwitch13StatsCalculator::GetElapsedTime () const
{
  return Simulator::Now () - m_lastUpdate;
}

uint32_t
OFSwitch13StatsCalculator::GetEwmaBufferUsage (void) const
{
  return std::round (100 * m_avgBufferUsage);
}

uint32_t
OFSwitch13StatsCalculator::GetEwmaFlowEntries (void) const
{
  return std::round (m_avgFlowEntries);
}

uint32_t
OFSwitch13StatsCalculator::GetEwmaGroupEntries (void) const
{
  return std::round (m_avgGroupEntries);
}

uint32_t
OFSwitch13StatsCalculator::GetEwmaMeterEntries (void) const
{
  return std::round (m_avgMeterEntries);
}

Time
OFSwitch13StatsCalculator::GetEwmaPipelineDelay (void) const
{
  return Time (m_avgPipelineDelay);
}

uint64_t
OFSwitch13StatsCalculator::GetFlowMods (void) const
{
  return m_flowModCounter - m_lastFlowModCounter;
}

uint64_t
OFSwitch13StatsCalculator::GetGroupMods (void) const
{
  return m_groupModCounter - m_lastGroupModCounter;
}

uint64_t
OFSwitch13StatsCalculator::GetLoadDrops (void) const
{
  return m_loadDropCounter;
}

uint64_t
OFSwitch13StatsCalculator::GetMeterDrops (void) const
{
  return m_meterDropCounter;
}

uint64_t
OFSwitch13StatsCalculator::GetMeterMods (void) const
{
  return m_meterModCounter - m_lastMeterModCounter;
}

double
OFSwitch13StatsCalculator::GetPipelineLoad (void) const
{
  double seconds = GetElapsedTime ().GetSeconds ();
  return (double)m_byteCounter * 8 / 1000 / seconds;
}

uint64_t
OFSwitch13StatsCalculator::GetPktsIn (void) const
{
  return m_packetInCounter - m_lastPacketInCounter;
}

uint64_t
OFSwitch13StatsCalculator::GetPktsOut (void) const
{
  return m_packetOutCounter - m_lastPacketOutCounter;
}

void
OFSwitch13StatsCalculator::DoDispose ()
{
  NS_LOG_FUNCTION (this);

  m_device = 0;
  m_wrapper = 0;
}

void
OFSwitch13StatsCalculator::NotifyConstructionCompleted (void)
{
  NS_LOG_FUNCTION (this);

  // Open output file and print header line.
  m_wrapper = Create<OutputStreamWrapper> (m_filename, std::ios::out);
  *m_wrapper->GetStream ()
  << fixed << setprecision (2)
  << left
  << setw (10) << "Time(s)"
  << right
  << setw (12) << "Load(Kbps)"
  << setw (11) << "LoadDrops"
  << setw (11) << "MeterDrops"
  << setw (11) << "FlowMods"
  << setw (11) << "MeterMods"
  << setw (11) << "GroupMods"
  << setw (11) << "PktsIn"
  << setw (11) << "PktsOut"
  << setw (11) << "BuffUse(%)"
  << setw (11) << "AvgFlows"
  << setw (11) << "AvgMeters"
  << setw (11) << "AvgGroups"
  << setw (13) << "AvgDelay(us)"
  << std::endl;

  // Scheduling first update and dump.
  Simulator::Schedule (
    m_timeout, &OFSwitch13StatsCalculator::UpdateAndDumpStatistics, this);

  // Chain up.
  Object::NotifyConstructionCompleted ();
}

void
OFSwitch13StatsCalculator::NotifyLoadDrop (Ptr<const Packet> packet)
{
  NS_LOG_FUNCTION (this << packet);

  m_loadDropCounter++;
}

void
OFSwitch13StatsCalculator::NotifyMeterDrop (Ptr<const Packet> packet,
                                            uint32_t meterId)
{
  NS_LOG_FUNCTION (this << packet << meterId);

  m_meterDropCounter++;
}

void
OFSwitch13StatsCalculator::NotifyPipelinePacket (Ptr<const Packet> packet)
{
  NS_LOG_FUNCTION (this << packet);

  m_byteCounter += packet->GetSize ();
}

void
OFSwitch13StatsCalculator::NotifyBufferUsage (double oldValue,
                                              double newValue)
{
  NS_LOG_FUNCTION (this << oldValue << newValue);

  m_bufferUsageUp = true;
  m_avgBufferUsage = newValue * m_alpha + m_avgBufferUsage * (1 - m_alpha);
}

void
OFSwitch13StatsCalculator::NotifyFlowEntries (uint32_t oldValue,
                                              uint32_t newValue)
{
  NS_LOG_FUNCTION (this << oldValue << newValue);

  m_flowEntriesUp = true;
  m_avgFlowEntries = newValue * m_alpha + m_avgFlowEntries * (1 - m_alpha);
}

void
OFSwitch13StatsCalculator::NotifyGroupEntries (uint32_t oldValue,
                                               uint32_t newValue)
{
  NS_LOG_FUNCTION (this << oldValue << newValue);

  m_groupEntriesUp = true;
  m_avgGroupEntries = newValue * m_alpha + m_avgGroupEntries * (1 - m_alpha);
}

void
OFSwitch13StatsCalculator::NotifyMeterEntries (uint32_t oldValue,
                                               uint32_t newValue)
{
  NS_LOG_FUNCTION (this << oldValue << newValue);

  m_meterEntriesUp = true;
  m_avgMeterEntries = newValue * m_alpha + m_avgMeterEntries * (1 - m_alpha);
}

void
OFSwitch13StatsCalculator::NotifyPipelineDelay (Time oldValue,
                                                Time newValue)
{
  NS_LOG_FUNCTION (this << oldValue << newValue);

  m_pipelineDelayUp = true;
  m_avgPipelineDelay = newValue.GetDouble () * m_alpha
    + m_avgPipelineDelay * (1 - m_alpha);
}

void
OFSwitch13StatsCalculator::UpdateAndDumpStatistics ()
{
  NS_LOG_FUNCTION (this);

  // Update counters.
  m_lastFlowModCounter    = m_flowModCounter;
  m_lastGroupModCounter   = m_groupModCounter;
  m_lastMeterModCounter   = m_meterModCounter;
  m_lastPacketInCounter   = m_packetInCounter;
  m_lastPacketOutCounter  = m_packetOutCounter;

  m_flowModCounter    = m_device->GetFlowModCounter ();
  m_groupModCounter   = m_device->GetGroupModCounter ();
  m_meterModCounter   = m_device->GetMeterModCounter ();
  m_packetInCounter   = m_device->GetPacketInCounter ();
  m_packetOutCounter  = m_device->GetPacketOutCounter ();

  // Check for metrics without updates during the last interval.
  if (!m_bufferUsageUp)
    {
      m_avgBufferUsage = m_device->GetBufferUsage ();
    }
  if (!m_flowEntriesUp)
    {
      m_avgFlowEntries = m_device->GetFlowEntries ();
    }
  if (!m_groupEntriesUp)
    {
      m_avgGroupEntries = m_device->GetGroupEntries ();
    }
  if (!m_meterEntriesUp)
    {
      m_avgMeterEntries = m_device->GetMeterEntries ();
    }
  if (!m_pipelineDelayUp)
    {
      m_avgPipelineDelay = m_device->GetPipelineDelay ().GetDouble ();
    }

  // Print statistics to file.
  *m_wrapper->GetStream ()
  << left
  << setw (10) << Simulator::Now ().GetSeconds ()             << " "
  << right
  << setw (11) << GetPipelineLoad ()                          << " "
  << setw (10) << GetLoadDrops ()                             << " "
  << setw (10) << GetMeterDrops ()                            << " "
  << setw (10) << GetFlowMods ()                              << " "
  << setw (10) << GetMeterMods ()                             << " "
  << setw (10) << GetGroupMods ()                             << " "
  << setw (10) << GetPktsIn ()                                << " "
  << setw (10) << GetPktsOut ()                               << " "
  << setw (10) << GetEwmaBufferUsage ()                       << " "
  << setw (10) << GetEwmaFlowEntries ()                       << " "
  << setw (10) << GetEwmaMeterEntries ()                      << " "
  << setw (10) << GetEwmaGroupEntries ()                      << " "
  << setw (12) << GetEwmaPipelineDelay ().GetMicroSeconds ()  << " "
  << std::endl;

  // Reset counters and flags.
  m_byteCounter = 0;
  m_loadDropCounter = 0;
  m_meterDropCounter = 0;
  m_bufferUsageUp = false;
  m_flowEntriesUp = false;
  m_groupEntriesUp = false;
  m_meterEntriesUp = false;
  m_pipelineDelayUp = false;

  // Scheduling next update.
  m_lastUpdate = Simulator::Now ();
  Simulator::Schedule (
    m_timeout, &OFSwitch13StatsCalculator::UpdateAndDumpStatistics, this);
}

} // Namespace ns3
