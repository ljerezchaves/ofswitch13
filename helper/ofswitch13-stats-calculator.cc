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
    m_avgPipelineDelay (0),
    m_avgBufferUsage (0),
    m_avgFlowEntries (0),
    m_avgMeterEntries (0),
    m_avgGroupEntries (0),
    m_packetCounter (0),
    m_byteCounter (0),
    m_dropCounter (0),
    m_flowModCounter (0),
    m_meterModCounter (0),
    m_groupModCounter (0),
    m_packetInCounter (0),
    m_packetOutCounter (0),
    m_lastPacketCounter (0),
    m_lastByteCounter (0),
    m_lastDropCounter (0),
    m_lastFlowModCounter (0),
    m_lastMeterModCounter (0),
    m_lastGroupModCounter (0),
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
    .AddAttribute ("OutputFilename",
                   "Filename for dumping switch statistics.",
                   TypeId::ATTR_GET | TypeId::ATTR_CONSTRUCT,
                   StringValue ("ofswitch_stats.log"),
                   MakeStringAccessor (&OFSwitch13StatsCalculator::m_filename),
                   MakeStringChecker ())
    .AddAttribute ("DumpTimeout",
                   "The interval to update and dump switch statistics.",
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

  // Save switch device pointer.
  m_device = device;

  // Hook sinks.
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

  // Open output file and print header line.
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

  // Scheduling first update and dump.
  Simulator::Schedule (
    m_timeout, &OFSwitch13StatsCalculator::UpdateAndDumpStatistics, this);

  // Chain up.
  Object::NotifyConstructionCompleted ();
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

double
OFSwitch13StatsCalculator::GetPktsPerSec (void) const
{
  NS_LOG_FUNCTION (this);

  uint32_t packets = m_packetCounter - m_lastPacketCounter;
  return (double)packets / GetElapsedSeconds ();
}

double
OFSwitch13StatsCalculator::GetDropsPerSec (void) const
{
  NS_LOG_FUNCTION (this);

  uint32_t drops = m_dropCounter - m_lastDropCounter;
  return (double)drops / GetElapsedSeconds ();
}

double
OFSwitch13StatsCalculator::GetKbitsPerSec (void) const
{
  NS_LOG_FUNCTION (this);

  uint32_t bytes = m_byteCounter - m_lastByteCounter;
  return (double)bytes * 8 / 1000 / GetElapsedSeconds ();
}

double
OFSwitch13StatsCalculator::GetFlowModsPerSec (void) const
{
  NS_LOG_FUNCTION (this);

  uint32_t mods = m_flowModCounter - m_lastFlowModCounter;
  return (double)mods / GetElapsedSeconds ();
}

double
OFSwitch13StatsCalculator::GetMeterModsPerSec (void) const
{
  NS_LOG_FUNCTION (this);

  uint32_t mods = m_meterModCounter - m_lastMeterModCounter;
  return (double)mods / GetElapsedSeconds ();
}

double
OFSwitch13StatsCalculator::GetGroupModsPerSec (void) const
{
  NS_LOG_FUNCTION (this);

  uint32_t mods = m_groupModCounter - m_lastGroupModCounter;
  return (double)mods / GetElapsedSeconds ();
}

double
OFSwitch13StatsCalculator::GetPktsInPerSec (void) const
{
  NS_LOG_FUNCTION (this);

  uint32_t packets = m_packetInCounter - m_lastPacketInCounter;
  return (double)packets / GetElapsedSeconds ();
}

double
OFSwitch13StatsCalculator::GetPktsOutPerSec (void) const
{
  NS_LOG_FUNCTION (this);

  uint32_t packets = m_packetOutCounter - m_lastPacketOutCounter;
  return (double)packets / GetElapsedSeconds ();
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
OFSwitch13StatsCalculator::UpdateAndDumpStatistics ()
{
  NS_LOG_FUNCTION (this);

  // Update counters.
  m_lastPacketCounter     = m_packetCounter;
  m_lastByteCounter       = m_byteCounter;
  m_lastDropCounter       = m_dropCounter;
  m_lastFlowModCounter    = m_flowModCounter;
  m_lastMeterModCounter   = m_meterModCounter;
  m_lastGroupModCounter   = m_groupModCounter;
  m_lastPacketInCounter   = m_packetInCounter;
  m_lastPacketOutCounter  = m_packetOutCounter;

  m_packetCounter     = m_device->GetPacketCounter ();
  m_byteCounter       = m_device->GetByteCounter ();
  m_dropCounter       = m_device->GetDropCounter ();
  m_flowModCounter    = m_device->GetFlowModCounter ();
  m_meterModCounter   = m_device->GetMeterModCounter ();
  m_groupModCounter   = m_device->GetGroupModCounter ();
  m_packetInCounter   = m_device->GetPacketInCounter ();
  m_packetOutCounter  = m_device->GetPacketOutCounter ();

  // Print statistics to file.
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

  // Scheduling next update and dump.
  m_lastUpdate = Simulator::Now ();
  Simulator::Schedule (
    m_timeout, &OFSwitch13StatsCalculator::UpdateAndDumpStatistics, this);
}

double
OFSwitch13StatsCalculator::GetElapsedSeconds () const
{
  return (Simulator::Now () - m_lastUpdate).GetSeconds ();
}

} // Namespace ns3
