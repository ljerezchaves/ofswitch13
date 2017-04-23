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

#ifndef OFSWITCH13_STATS_CALCULATOR_H
#define OFSWITCH13_STATS_CALCULATOR_H

#include <ns3/ofswitch13-device.h>

namespace ns3 {

/**
 * \ingroup ofswitch13
 * \brief This class monitors a single OpenFlow switch device to collect
 * statistics and save write them to an output file. This stats calculator
 * connects to a collection of trace sources in the OpenFlow switch device to
 * monitor the following metrics:
 *  -# Packets per second sent to the pipeline;
 *  -# Packets per second dropped by meter bands;
 *  -# Kbits per second of data processed by the pipeline;
 *  -# Flow-mod per second operations executed by the switch;
 *  -# Meter-mod per second operations executed by the switch;
 *  -# Group-mod per second operations executed by the OpenFlow switch;
 *  -# Packets-in per second sent from the switch to the controller;
 *  -# Packets-out per second sent from the controller to the switch;
 *  -# Average switch buffer space usage (percent);
 *  -# Average number of flow entries in pipeline tables;
 *  -# Average number of meter entries in meter table;
 *  -# Average number of group entries in group table;
 *  -# Average pipeline lookup delay for packet processing (nanoseconds).
 */
class OFSwitch13StatsCalculator : public Object
{
public:
  OFSwitch13StatsCalculator ();          //!< Default constructor.
  virtual ~OFSwitch13StatsCalculator (); //!< Default destructor.

  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);

  /**
   * Hook switch device trace sources to internal stats calculator trace sinks.
   * \param device The OpenFlow switch device to monitor.
   */
  void HookSinks (Ptr<OFSwitch13Device> device);

protected:
  /** Destructor implementation. */
  virtual void DoDispose ();

  // Inherited from ObjectBase.
  virtual void NotifyConstructionCompleted (void);

private:
  /**
   * \name Trace sinks for monitoring traced values.
   * Trace sinks used to monitor traced values on the OpenFlow switch datapath.
   * \param oldValue The old value.
   * \param newValue The new just updated value.
   */
  //\{
  void NotifyPipelineDelay  (Time     oldValue, Time     newValue);
  void NotifyBufferUsage    (double   oldValue, double   newValue);
  void NotifyFlowEntries    (uint32_t oldValue, uint32_t newValue);
  void NotifyMeterEntries   (uint32_t oldValue, uint32_t newValue);
  void NotifyGroupEntries   (uint32_t oldValue, uint32_t newValue);
  //\}

  /**
   * \name Statistics calculators.
   * Functions used to calculate average metric values based on data collected
   * since the last update operation.
   * \return The requested average metric value.
   */
  //\{
  double   GetPktsPerSec        (void) const;
  double   GetDropsPerSec       (void) const;
  double   GetKbitsPerSec       (void) const;
  double   GetFlowModsPerSec    (void) const;
  double   GetMeterModsPerSec   (void) const;
  double   GetGroupModsPerSec   (void) const;
  double   GetPktsInPerSec      (void) const;
  double   GetPktsOutPerSec     (void) const;
  uint32_t GetAvgBufferUsage    (void) const;
  uint32_t GetAvgFlowEntries    (void) const;
  uint32_t GetAvgMeterEntries   (void) const;
  uint32_t GetAvgGroupEntries   (void) const;
  uint32_t GetAvgPipelineDelay  (void) const;
  //\}

  /**
   * Read statistics from switch, update internal counters,
   * and dump data into output file.
   */
  void UpdateAndDumpStatistics ();

  /**
   * Get the elapsed time since last update.
   * \return The elapsed time, in seconds.
   */
  double GetElapsedSeconds (void) const;

  Ptr<OFSwitch13Device>     m_device;       //!< OpenFlow switch device.
  Ptr<OutputStreamWrapper>  m_wrapper;      //!< Output file wrapper.
  std::string               m_filename;     //!< Output file name.
  Time                      m_timeout;      //!< Update timeout.
  Time                      m_lastUpdate;   //!< Last update time.
  double                    m_alpha;        //!< EWMA alpha parameter.

  /** \name Internal counters. */
  //\{
  double    m_avgPipelineDelay;
  double    m_avgBufferUsage;
  double    m_avgFlowEntries;
  double    m_avgMeterEntries;
  double    m_avgGroupEntries;

  uint32_t  m_packetCounter;
  uint32_t  m_byteCounter;
  uint32_t  m_dropCounter;
  uint32_t  m_flowModCounter;
  uint32_t  m_meterModCounter;
  uint32_t  m_groupModCounter;
  uint32_t  m_packetInCounter;
  uint32_t  m_packetOutCounter;

  uint32_t  m_lastPacketCounter;
  uint32_t  m_lastByteCounter;
  uint32_t  m_lastDropCounter;
  uint32_t  m_lastFlowModCounter;
  uint32_t  m_lastMeterModCounter;
  uint32_t  m_lastGroupModCounter;
  uint32_t  m_lastPacketInCounter;
  uint32_t  m_lastPacketOutCounter;
  //\}
};

} // namespace ns3
#endif /* OFSWITCH13_STATS_CALCULATOR_H */
