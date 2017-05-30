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
    m_avgPipelineLoad (0),
    m_bytes (0),
    m_lastFlowMods (0),
    m_lastGroupMods (0),
    m_lastMeterMods (0),
    m_lastPacketsIn (0),
    m_lastPacketsOut (0),
    m_loadDrops (0),
    m_meterDrops (0)
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
                   DoubleValue (0.25),
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
    "DatapathTimeout", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyDatapathTimeout,
      Ptr<OFSwitch13StatsCalculator> (this)));
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

DataRate
OFSwitch13StatsCalculator::GetEwmaPipelineLoad (void) const
{
  return DataRate (std::round (m_avgPipelineLoad));
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
  << setw (12) << "Time(s)"
  << right
  << setw (12) << "Load(Kbps)"
  << setw (8)  << "LdDrops"
  << setw (8)  << "MtDrops"
  << setw (8)  << "FloMods"
  << setw (8)  << "MetMods"
  << setw (8)  << "GroMods"
  << setw (8)  << "PktsIn"
  << setw (8)  << "PktsOut"
  << setw (8)  << "NFlows"
  << setw (8)  << "NMeters"
  << setw (8)  << "NGroups"
  << setw (8)  << "Buff(%)"
  << setw (8)  << "Dly(us)"
  << std::endl;

  // Scheduling first update and dump.
  Simulator::Schedule (m_timeout,
                       &OFSwitch13StatsCalculator::DumpStatistics, this);

  // Chain up.
  Object::NotifyConstructionCompleted ();
}

void
OFSwitch13StatsCalculator::NotifyDatapathTimeout (Ptr<const OFSwitch13Device> device)
{
  NS_LOG_FUNCTION (this);

  NS_ASSERT_MSG (m_device == device, "Invalid device pointer.");
  m_avgBufferUsage = m_alpha * m_device->GetBufferUsage ()
    + (1 - m_alpha) * m_avgBufferUsage;
  m_avgFlowEntries = m_alpha * m_device->GetFlowEntries ()
    + (1 - m_alpha) * m_avgFlowEntries;
  m_avgGroupEntries = m_alpha * m_device->GetGroupEntries ()
    + (1 - m_alpha) * m_avgGroupEntries;
  m_avgMeterEntries = m_alpha * m_device->GetMeterEntries ()
    + (1 - m_alpha) * m_avgMeterEntries;
  m_avgPipelineDelay = m_alpha * m_device->GetPipelineDelay ().GetDouble ()
    + (1 - m_alpha) * m_avgPipelineDelay;
  m_avgPipelineLoad = m_alpha * m_device->GetPipelineLoad ().GetBitRate ()
    + (1 - m_alpha) * m_avgPipelineLoad;
}

void
OFSwitch13StatsCalculator::NotifyLoadDrop (Ptr<const Packet> packet)
{
  NS_LOG_FUNCTION (this << packet);

  m_loadDrops++;
}

void
OFSwitch13StatsCalculator::NotifyMeterDrop (Ptr<const Packet> packet,
                                            uint32_t meterId)
{
  NS_LOG_FUNCTION (this << packet << meterId);

  m_meterDrops++;
}

void
OFSwitch13StatsCalculator::NotifyPipelinePacket (Ptr<const Packet> packet)
{
  NS_LOG_FUNCTION (this << packet);

  m_bytes += packet->GetSize ();
}

void
OFSwitch13StatsCalculator::DumpStatistics (void)
{
  NS_LOG_FUNCTION (this);

  // Collect statistics from switch device.
  uint64_t flowMods   = m_device->GetFlowModCounter ();
  uint64_t groupMods  = m_device->GetGroupModCounter ();
  uint64_t meterMods  = m_device->GetMeterModCounter ();
  uint64_t packetsIn  = m_device->GetPacketInCounter ();
  uint64_t packetsOut = m_device->GetPacketOutCounter ();

  double elapSeconds = (Simulator::Now () - m_lastUpdate).GetSeconds ();

  // Print statistics to file.
  *m_wrapper->GetStream ()
  << left
  << setw (11) << Simulator::Now ().GetSeconds ()
  << right
  << " " << setw (12) << (double)m_bytes * 8 / 1000 / elapSeconds
  << " " << setw (7)  << m_loadDrops
  << " " << setw (7)  << m_meterDrops
  << " " << setw (7)  << flowMods - m_lastFlowMods
  << " " << setw (7)  << meterMods - m_lastMeterMods
  << " " << setw (7)  << groupMods - m_lastGroupMods
  << " " << setw (7)  << packetsIn - m_lastPacketsIn
  << " " << setw (7)  << packetsOut - m_lastPacketsOut
  << " " << setw (7)  << GetEwmaFlowEntries ()
  << " " << setw (7)  << GetEwmaMeterEntries ()
  << " " << setw (7)  << GetEwmaGroupEntries ()
  << " " << setw (7)  << GetEwmaBufferUsage ()
  << " " << setw (7)  << GetEwmaPipelineDelay ().GetMicroSeconds ()
  << std::endl;

  // Update internal counters.
  m_bytes = 0;
  m_lastFlowMods   = flowMods;
  m_lastGroupMods  = groupMods;
  m_lastMeterMods  = meterMods;
  m_lastPacketsIn  = packetsIn;
  m_lastPacketsOut = packetsOut;
  m_loadDrops = 0;
  m_meterDrops = 0;

  // Scheduling next update.
  m_lastUpdate = Simulator::Now ();
  Simulator::Schedule (m_timeout,
                       &OFSwitch13StatsCalculator::DumpStatistics, this);
}

} // Namespace ns3
