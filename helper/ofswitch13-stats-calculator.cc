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
  m_ewmaBufferEntries (0.0),
  m_ewmaCpuLoad (0.0),
  m_ewmaGroupEntries (0.0),
  m_ewmaMeterEntries (0.0),
  m_ewmaPipelineDelay (0.0),
  m_ewmaSumFlowEntries (0.0),
  m_bytes (0),
  m_lastFlowMods (0),
  m_lastGroupMods (0),
  m_lastMeterMods (0),
  m_lastPacketsIn (0),
  m_lastPacketsOut (0),
  m_loadDrops (0),
  m_meterDrops (0),
  m_packets (0)
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
                   DoubleValue (0.2),
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
    .AddAttribute ("FlowTableDetails",
                   "Dump individual pipeline flow table statistics.",
                   BooleanValue (false),
                   MakeBooleanAccessor (&OFSwitch13StatsCalculator::m_details),
                   MakeBooleanChecker ())
  ;
  return tid;
}

void
OFSwitch13StatsCalculator::HookSinks (Ptr<OFSwitch13Device> device)
{
  NS_LOG_FUNCTION (this << device);

  // Save switch device pointer.
  m_device = device;

  // Print the header line.
  *m_wrapper->GetStream ()
    << boolalpha << right << fixed << setprecision (3)
    << " " << setw (8)  << "TimeSec"
    << " " << setw (12) << "LoaKbps"
    << " " << setw (7)  << "LoaUsag"
    << " " << setw (7)  << "Packets"
    << " " << setw (7)  << "DlyUsec"
    << " " << setw (7)  << "LoaDrop"
    << " " << setw (7)  << "MetDrps"
    << " " << setw (7)  << "FloMods"
    << " " << setw (7)  << "MetMods"
    << " " << setw (7)  << "GroMods"
    << " " << setw (7)  << "PktsIn"
    << " " << setw (7)  << "PktsOut"
    << " " << setw (7)  << "FloEntr"
    << " " << setw (7)  << "FloUsag"
    << " " << setw (7)  << "MetEntr"
    << " " << setw (7)  << "MetUsag"
    << " " << setw (7)  << "GroEntr"
    << " " << setw (7)  << "GroUsag"
    << " " << setw (7)  << "BufPkts"
    << " " << setw (7)  << "BufUsag";

  if (m_details)
    {
      for (size_t i = 0; i < m_device->GetNPipelineTables (); i++)
        {
          std::string field1 = "T" + to_string (i) + "Entr";
          std::string field2 = "T" + to_string (i) + "Usag";
          *m_wrapper->GetStream ()
            << " " << setw (7) << field1
            << " " << setw (7) << field2;
        }
    }

  *m_wrapper->GetStream () << std::endl;

  // Hook sinks.
  device->TraceConnectWithoutContext (
    "DatapathTimeout", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyDatapathTimeout,
      Ptr<OFSwitch13StatsCalculator> (this)));
  device->TraceConnectWithoutContext (
    "OverloadDrop", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyOverloadDrop,
      Ptr<OFSwitch13StatsCalculator> (this)));
  device->TraceConnectWithoutContext (
    "MeterDrop", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyMeterDrop,
      Ptr<OFSwitch13StatsCalculator> (this)));
  device->TraceConnectWithoutContext (
    "PipelinePacket", MakeCallback (
      &OFSwitch13StatsCalculator::NotifyPipelinePacket,
      Ptr<OFSwitch13StatsCalculator> (this)));

  m_ewmaFlowEntries.resize (device->GetNPipelineTables (), 0.0);
}

uint32_t
OFSwitch13StatsCalculator::GetEwmaBufferEntries (void) const
{
  return std::round (m_ewmaBufferEntries);
}

DataRate
OFSwitch13StatsCalculator::GetEwmaCpuLoad (void) const
{
  return DataRate (std::round (m_ewmaCpuLoad));
}

uint32_t
OFSwitch13StatsCalculator::GetEwmaFlowTableEntries (uint8_t tableId) const
{
  return std::round (m_ewmaFlowEntries.at (tableId));
}

uint32_t
OFSwitch13StatsCalculator::GetEwmaGroupTableEntries (void) const
{
  return std::round (m_ewmaGroupEntries);
}

uint32_t
OFSwitch13StatsCalculator::GetEwmaMeterTableEntries (void) const
{
  return std::round (m_ewmaMeterEntries);
}

Time
OFSwitch13StatsCalculator::GetEwmaPipelineDelay (void) const
{
  return Time (m_ewmaPipelineDelay);
}

uint32_t
OFSwitch13StatsCalculator::GetEwmaSumFlowEntries (void) const
{
  return std::round (m_ewmaSumFlowEntries);
}

uint32_t
OFSwitch13StatsCalculator::GetAvgBufferUsage (void) const
{
  if (m_device->GetBufferSize () == 0)
    {
      return 0;
    }
  return std::round (static_cast<double> (GetEwmaBufferEntries ()) * 100 /
                     static_cast<double> (m_device->GetBufferSize ()));
}

uint32_t
OFSwitch13StatsCalculator::GetAvgCpuUsage (void) const
{
  if (m_device->GetCpuCapacity ().GetBitRate () == 0)
    {
      return 0;
    }
  return std::round (
    static_cast<double> (GetEwmaCpuLoad ().GetBitRate ()) * 100 /
    static_cast<double> (m_device->GetCpuCapacity ().GetBitRate ()));
}

uint32_t
OFSwitch13StatsCalculator::GetAvgFlowTableUsage (uint8_t tableId) const
{
  if (m_device->GetFlowTableSize (tableId) == 0)
    {
      return 0;
    }
  return std::round (
    static_cast<double> (GetEwmaFlowTableEntries (tableId)) * 100 /
    static_cast<double> (m_device->GetFlowTableSize (tableId)));
}

uint32_t
OFSwitch13StatsCalculator::GetAvgGroupTableUsage (void) const
{
  if (m_device->GetGroupTableSize () == 0)
    {
      return 0;
    }
  return std::round (static_cast<double> (GetEwmaGroupTableEntries ()) * 100 /
                     static_cast<double> (m_device->GetGroupTableSize ()));
}

uint32_t
OFSwitch13StatsCalculator::GetAvgMeterTableUsage (void) const
{
  if (m_device->GetMeterTableSize () == 0)
    {
      return 0;
    }
  return std::round (static_cast<double> (GetEwmaMeterTableEntries ()) * 100 /
                     static_cast<double> (m_device->GetMeterTableSize ()));
}

uint32_t
OFSwitch13StatsCalculator::GetAvgActFlowTableUsage (void) const
{
  uint32_t sumSize = 0;
  for (size_t i = 0; i < m_device->GetNPipelineTables (); i++)
    {
      if (m_device->GetFlowTableEntries (i))
        {
          sumSize += m_device->GetFlowTableSize (i);
        }
    }

  if (sumSize == 0)
    {
      return 0;
    }
  return std::round (static_cast<double> (GetEwmaSumFlowEntries ()) * 100 /
                     static_cast<double> (sumSize));
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

  // Open output file.
  m_wrapper = Create<OutputStreamWrapper> (m_filename, std::ios::out);

  // Scheduling first update and dump.
  Simulator::Schedule (m_timeout,
                       &OFSwitch13StatsCalculator::DumpStatistics, this);

  // Chain up.
  Object::NotifyConstructionCompleted ();
}

void
OFSwitch13StatsCalculator::NotifyDatapathTimeout (
  Ptr<const OFSwitch13Device> device)
{
  NS_LOG_FUNCTION (this);

  NS_ASSERT_MSG (m_device == device, "Invalid device pointer.");
  m_ewmaBufferEntries = m_alpha * m_device->GetBufferEntries ()
    + (1 - m_alpha) * m_ewmaBufferEntries;
  m_ewmaCpuLoad = m_alpha * m_device->GetCpuLoad ().GetBitRate ()
    + (1 - m_alpha) * m_ewmaCpuLoad;
  m_ewmaSumFlowEntries = m_alpha * m_device->GetSumFlowEntries ()
    + (1 - m_alpha) * m_ewmaSumFlowEntries;
  m_ewmaGroupEntries = m_alpha * m_device->GetGroupTableEntries ()
    + (1 - m_alpha) * m_ewmaGroupEntries;
  m_ewmaMeterEntries = m_alpha * m_device->GetMeterTableEntries ()
    + (1 - m_alpha) * m_ewmaMeterEntries;
  m_ewmaPipelineDelay = m_alpha * m_device->GetPipelineDelay ().GetDouble ()
    + (1 - m_alpha) * m_ewmaPipelineDelay;

  for (size_t i = 0; i < m_device->GetNPipelineTables (); i++)
    {
      m_ewmaFlowEntries.at (i) = m_alpha * m_device->GetFlowTableEntries (i)
        + (1 - m_alpha) * m_ewmaFlowEntries.at (i);
    }
}

void
OFSwitch13StatsCalculator::NotifyOverloadDrop (Ptr<const Packet> packet)
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
  m_packets++;
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

  // We don't use the EWMA CPU load here. Instead, we use the number of
  // bytes transmitted since the last dump operation to get a precise average
  // CPU load.
  double elapSeconds = (Simulator::Now () - m_lastUpdate).GetSeconds ();
  uint64_t cpuLoad = m_bytes * 8 / elapSeconds;
  uint64_t cpuCapy = m_device->GetCpuCapacity ().GetBitRate ();
  uint32_t cpuUsage = 0;
  if (cpuCapy)
    {
      cpuUsage = std::round (static_cast<double> (cpuLoad) * 100 /
                             static_cast<double> (cpuCapy));
    }

  // Print statistics to file.
  *m_wrapper->GetStream ()
    << " " << setw (8)  << Simulator::Now ().GetSeconds ()
    << " " << setw (12) << static_cast<double> (cpuLoad) / 1000
    << " " << setw (7)  << cpuUsage
    << " " << setw (7)  << m_packets
    << " " << setw (7)  << GetEwmaPipelineDelay ().GetMicroSeconds ()
    << " " << setw (7)  << m_loadDrops
    << " " << setw (7)  << m_meterDrops
    << " " << setw (7)  << flowMods - m_lastFlowMods
    << " " << setw (7)  << meterMods - m_lastMeterMods
    << " " << setw (7)  << groupMods - m_lastGroupMods
    << " " << setw (7)  << packetsIn - m_lastPacketsIn
    << " " << setw (7)  << packetsOut - m_lastPacketsOut
    << " " << setw (7)  << GetEwmaSumFlowEntries ()
    << " " << setw (7)  << GetAvgActFlowTableUsage ()
    << " " << setw (7)  << GetEwmaMeterTableEntries ()
    << " " << setw (7)  << GetAvgMeterTableUsage ()
    << " " << setw (7)  << GetEwmaGroupTableEntries ()
    << " " << setw (7)  << GetAvgGroupTableUsage ()
    << " " << setw (7)  << GetEwmaBufferEntries ()
    << " " << setw (7)  << GetAvgBufferUsage ();

  if (m_details)
    {
      for (size_t i = 0; i < m_device->GetNPipelineTables (); i++)
        {
          *m_wrapper->GetStream ()
            << " " << setw (7) << GetEwmaFlowTableEntries (i)
            << " " << setw (7) << GetAvgFlowTableUsage (i);
        }
    }

  *m_wrapper->GetStream () << std::endl;

  // Update internal counters.
  m_bytes = 0;
  m_lastFlowMods   = flowMods;
  m_lastGroupMods  = groupMods;
  m_lastMeterMods  = meterMods;
  m_lastPacketsIn  = packetsIn;
  m_lastPacketsOut = packetsOut;
  m_loadDrops = 0;
  m_meterDrops = 0;
  m_packets = 0;

  // Scheduling next update.
  m_lastUpdate = Simulator::Now ();
  Simulator::Schedule (m_timeout,
                       &OFSwitch13StatsCalculator::DumpStatistics, this);
}

} // Namespace ns3
