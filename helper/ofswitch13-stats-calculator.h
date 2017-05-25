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
 * statistics and write them to an output file. This stats calculator connects
 * to a collection of trace sources in the OpenFlow switch device to monitor
 * the following metrics:
 *  -# Pipeline load in terms of throughput (Kbits);
 *  -# Packets dropped while exceeding pipeline load capacity;
 *  -# Packets dropped by meter bands;
 *  -# Flow-mod operations executed by the switch;
 *  -# Meter-mod operations executed by the switch;
 *  -# Group-mod operations executed by the switch;
 *  -# Packets-in sent from the switch to the controller;
 *  -# Packets-out sent from the controller to the switch;
 *  -# Average number of flow entries in pipeline tables;
 *  -# Average number of meter entries in meter table;
 *  -# Average number of group entries in group table;
 *  -# Average switch buffer space usage (percent);
 *  -# Average pipeline lookup delay for packet processing (microseconds).
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

  /**
   * \name EWMA statistics calculators.
   * Get the average metric values that are updated at every datapath timeout
   * operation using an Exponentially Weighted Moving Average.
   * \return The requested metric value.
   */
  //\{
  uint32_t GetEwmaBufferUsage   (void) const;
  uint32_t GetEwmaFlowEntries   (void) const;
  uint32_t GetEwmaGroupEntries  (void) const;
  uint32_t GetEwmaMeterEntries  (void) const;
  Time     GetEwmaPipelineDelay (void) const;
  DataRate GetEwmaPipelineLoad  (void) const;
  //\}

protected:
  /** Destructor implementation. */
  virtual void DoDispose ();

  // Inherited from ObjectBase.
  virtual void NotifyConstructionCompleted (void);

private:
  /**
   * Notify when a datapath timeout operation is completed.
   * \param device The OpenFlow device pointer.
   */
  void NotifyDatapathTimeout (Ptr<const OFSwitch13Device> device);

  /**
   * Notify when a packet is dropped due to pipeline load.
   * \param packet The packet.
   */
  void NotifyLoadDrop (Ptr<const Packet> packet);

  /**
   * Notify when a packet is dropped by a meter band.
   * \param packet The packet.
   * \param meterId The meter ID.
   */
  void NotifyMeterDrop (Ptr<const Packet> packet, uint32_t meterId);

  /**
   * Notify when a packet is sent to pipeline.
   * \param packet The packet.
   */
  void NotifyPipelinePacket (Ptr<const Packet> packet);

  /**
   * Read statistics from switch, update internal counters,
   * and dump data into output file.
   */
  void DumpStatistics (void);

  Ptr<OFSwitch13Device>     m_device;       //!< OpenFlow switch device.
  Ptr<OutputStreamWrapper>  m_wrapper;      //!< Output file wrapper.
  std::string               m_filename;     //!< Output file name.
  Time                      m_timeout;      //!< Update timeout.
  Time                      m_lastUpdate;   //!< Last update time.
  double                    m_alpha;        //!< EWMA alpha parameter.

  /** \name Internal counters, average values, and updated flags. */
  //\{
  double    m_avgBufferUsage;
  double    m_avgFlowEntries;
  double    m_avgGroupEntries;
  double    m_avgMeterEntries;
  double    m_avgPipelineDelay;
  double    m_avgPipelineLoad;

  uint64_t  m_bytes;
  uint64_t  m_lastFlowMods;
  uint64_t  m_lastGroupMods;
  uint64_t  m_lastMeterMods;
  uint64_t  m_lastPacketsIn;
  uint64_t  m_lastPacketsOut;
  uint64_t  m_loadDrops;
  uint64_t  m_meterDrops;
  //\}
};

} // namespace ns3
#endif /* OFSWITCH13_STATS_CALCULATOR_H */
