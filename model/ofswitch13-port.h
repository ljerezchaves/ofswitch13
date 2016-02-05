/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2015 University of Campinas (Unicamp)
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

#ifndef OFSWITCH13_PORT_H
#define OFSWITCH13_PORT_H

#include "ns3/object.h"
#include "ns3/net-device.h"
#include "ns3/csma-net-device.h"
#include "ns3/packet.h"
#include "ns3/traced-callback.h"
#include "ofswitch13-interface.h"
#include "ofswitch13-queue.h"

namespace ns3 {

class OFSwitch13NetDevice;

/**
 * \ingroup ofswitch13
 *
 * A OpenFlow switch port, interconnecting the ns-3 underlying CsmaNetDevice to
 * the OpenFlow OFSwitch13NetDevice. It handles the ofsoftswitch13 internal
 * sw_port structure.
 * \see ofsoftswitch13 udatapath/dp_ports.h
 * \attention Each underlying CsmaNetDevice used as port must only be assigned
 * a Mac Address. Adding an Ipv4 or Ipv6 layer to it will cause an error.
 */
class OFSwitch13Port : public Object
{
public:
  OFSwitch13Port ();            //!< Default constructor
  virtual ~OFSwitch13Port ();   //!< Dummy destructor, see DoDipose

  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);

  /**
   * Get the OpenFlow port number for this port.
   * \return The port number.
   */
  uint32_t GetPortNo (void) const;

  /**
   * Complete Constructor. Create and populate a new datapath port, notifying
   * the controller of this new port.
   * \see ofsoftswitch new_port () at udatapath/dp_ports.c
   * \param dp The datapath.
   * \param csmaDev The underlying CsmaNetDevice.
   * \param openflowDev The OpenFlow NetDevice.
   */
  OFSwitch13Port (datapath *dp, Ptr<CsmaNetDevice> csmaDev,
                  Ptr<OFSwitch13NetDevice> openflowDev);

  /**
   * Update the port state field based on netdevice status, and notify the
   * controller when changes occurs.
   * \return true if the state of the port has changed, false otherwise.
   */
  bool PortUpdateState ();

  /**
   * Send a packet over this OpenFlow switch port. It will check port
   * configuration, update counters and send the packet over the underlying
   * CsmaNetDevice.
   * \see ofsoftswitch13 function dp_ports_run () at udatapath/dp_ports.c
   * \param packet The Packet to send.
   * \param queueNo The queue to use.
   * \return true if the packet was sent successfully, false otherwise.
   */
  bool Send (Ptr<Packet> packet, uint32_t queueNo);

  /**
   * Get a pointer to the collection of output queues at this port.
   * \return The OFSwitch13Queue pointer.
   */
  Ptr<OFSwitch13Queue> GetOutputQueue ();

protected:
  /** Destructor implementation */
  virtual void DoDispose ();

private:
  /**
   * Create the bitmaps of OFPPF_* describing port features, based on
   * ns3::NetDevice.
   * \see ofsoftswitch netdev_get_features () at lib/netdev.c
   * \return Port features bitmap.
   */
  uint32_t PortGetFeatures ();

  /**
   * Called when a packet is received on this OpenFlow switch port. This
   * method is a trace sink for the OpenFlowRx trace source at the underlying
   * CsmaNetDevice. It will check port configuration, update counter and send
   * the packet to the OpenFlow pipeline.
   * \see ofsoftswitch13 function dp_ports_run () at udatapath/dp_ports.c
   * \param packet The received packet.
   */
  void Receive (Ptr<Packet> packet);

  /** Trace source fired when a packet arrives at this switch port. */
  TracedCallback<Ptr<const Packet> > m_rxTrace;

  /** Trace source fired when a packet will be sent over this switch port. */
  TracedCallback<Ptr<const Packet> > m_txTrace;

  uint32_t                  m_portNo;       //!< Port number
  sw_port*                  m_swPort;       //!< ofsoftswitch13 struct sw_port
  Ptr<CsmaNetDevice>        m_csmaDev;      //!< Underlying CsmaNetDevice
  Ptr<OFSwitch13Queue>      m_portQueue;    //!< OpenFlow Port Queue
  Ptr<OFSwitch13NetDevice>  m_openflowDev;  //!< OpenFlow NetDevice
};

} // namespace ns3
#endif /* OFSWITCH13_PORT_H */
