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
 * statistics and periodically write them to an output file. This stats
 * calculator connects to a collection of trace sources in the OpenFlow switch
 * device to monitor the following metrics:
 *
 * -# [LoaKbps] CPU porocessing load in the last interval (Kbps);
 * -# [LoaUsag] Average CPU processing capacity usage (percent);
 * -# [Packets] Packets processed by the pipeline in the last interval;
 * -# [DlyUsec] EWMA pipeline lookup delay for packet processing (usecs);
 * -# [LoaDrop] Packets dropped by capacity overloaded in the last interval;
 * -# [MetDrps] Packets dropped by meter bands in the last interval;
 * -# [FloMods] Flow-mod operations executed in the last interval;
 * -# [MetMods] Meter-mod operations executed in the last interval;
 * -# [GroMods] Group-mod operations executed in the last interval;
 * -# [PktsIn]  Packets-in sent to the controller in the last interval;
 * -# [PktsOut] Packets-out received from the controller in the last interval;
 * -# [FloEntr] EWMA sum of entries in all pipeline flow tables;
 * -# [FloUsag] Average flow table usage, considering the sum of entries in
 *    all flow tables divided by the aggregated sizes of all flow tables with
 *    at least one flow entry installed (percent);
 * -# [MetEntr] EWMA number of entries in meter table;
 * -# [MetUsag] Average meter table usage (percent);
 * -# [GroEntr] EWMA number of entries in group table;
 * -# [GroUsag] Average group table usage (percent);
 * -# [BufPkts] EWMA number of packets in switch buffer;
 * -# [BufUsag] Average switch buffer usage (percent);
 *
 * When the FlowTableDetails attribute is set to 'true', the EWMA number of
 * entries and the average flow table usage for each pipeline flow table is
 * also available under the columns ``T**Entr`` and ``T**Usag``.
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
   * \param tableId The pipeline table ID.
   * \return The requested metric value.
   */
  //\{
  uint32_t GetEwmaBufferEntries       (void) const;
  DataRate GetEwmaCpuLoad             (void) const;
  uint32_t GetEwmaFlowTableEntries    (uint8_t tableId) const;
  uint32_t GetEwmaGroupTableEntries   (void) const;
  uint32_t GetEwmaMeterTableEntries   (void) const;
  Time     GetEwmaPipelineDelay       (void) const;
  uint32_t GetEwmaSumFlowEntries      (void) const;
  //\}

  /**
   * \name Datapath usage statistics.
   * Get the usage statistics for datapath resources considering the EWMA
   * values and resources size. For the flow table usage, only those tables
   * with active flow entries are considered when calculating the average
   * usage value.
   * \param tableId The pipeline table ID.
   * \return The requested metric value.
   */
  //\{
  uint32_t GetAvgBufferUsage       (void) const;
  uint32_t GetAvgCpuUsage          (void) const;
  uint32_t GetAvgFlowTableUsage    (uint8_t tableId) const;
  uint32_t GetAvgGroupTableUsage   (void) const;
  uint32_t GetAvgMeterTableUsage   (void) const;
  uint32_t GetAvgActFlowTableUsage (void) const;
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
  void NotifyOverloadDrop (Ptr<const Packet> packet);

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
  bool                      m_details;      //!< Pipeline table details.

  /** \name Internal counters, average values, and updated flags. */
  //\{
  double    m_ewmaBufferEntries;
  double    m_ewmaCpuLoad;
  double    m_ewmaGroupEntries;
  double    m_ewmaMeterEntries;
  double    m_ewmaPipelineDelay;
  double    m_ewmaSumFlowEntries;

  std::vector<double> m_ewmaFlowEntries;

  uint64_t  m_bytes;
  uint64_t  m_lastFlowMods;
  uint64_t  m_lastGroupMods;
  uint64_t  m_lastMeterMods;
  uint64_t  m_lastPacketsIn;
  uint64_t  m_lastPacketsOut;
  uint64_t  m_loadDrops;
  uint64_t  m_meterDrops;
  uint64_t  m_packets;
  //\}
};

} // namespace ns3
#endif /* OFSWITCH13_STATS_CALCULATOR_H */
