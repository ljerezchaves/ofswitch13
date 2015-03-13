/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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

#include <errno.h>

#include "ns3/object.h"
#include "ns3/net-device.h"
#include "ns3/mac48-address.h"
#include "ns3/bridge-channel.h"
#include "ns3/csma-net-device.h"
#include "ns3/node.h"
#include "ns3/packet.h"
#include "ns3/socket.h"
#include "ns3/simple-ref-count.h"
#include "ns3/traced-callback.h"

#include "ofswitch13-interface.h"

namespace ns3 {

class OFSwitch13NetDevice;

/**
 * \ingroup ofswitch13
 * A OpenFlow switch port metadata, saving the port number, the pointer to ns3
 * NetDevice and the pointer to ofsoftswitch internal sw_port structure.
 * \see ofsoftswitch13 udatapath/dp_ports.h
 */
class OFSwitch13Port : public SimpleRefCount<OFSwitch13Port>
{
  friend class OFSwitch13NetDevice;

public:
  /**
   * Create and populate a new datapath port.
   * \see ofsoftswitch new_port () at udatapath/dp_ports.c
   * \param dp The datapath.
   * \param csmaDev The underlying CsmaNetDevice.
   * \param openflowDev The OpenFlow NetDevice.
   */
  OFSwitch13Port (datapath *dp, Ptr<CsmaNetDevice> csmaDev, 
                  Ptr<OFSwitch13NetDevice> openflowDev);

  /** Default destructor */
  ~OFSwitch13Port ();

private:
  /**
   * Create the bitmaps of OFPPF_* describing port features, based on
   * ns3::NetDevice.
   * \see ofsoftswitch netdev_get_features () at lib/netdev.c
   * \return Port features bitmap.
   */
  uint32_t PortGetFeatures ();

  /**
   * Update the port state field based on netdevice status.
   * \return true if the state of the port has changed, false otherwise.
   */
  bool PortUpdateState ();

  /**
   * Called when a packet is received on the underlying CsmaNetDevice. 
   * This method is a trace sink for the OpenFlowRx trace source at
   * CsmaNetDevice. It will check port configuration, update counter and send
   * the packet to the OpenFlow pipeline.
   * \see ofsoftswitch13 function dp_ports_run () at udatapath/dp_ports.c
   * \param sender The underlying NetDevice where the packet was received on.
   * \param packet The Packet itself.
   */
  void Receive (Ptr<const NetDevice> sender, Ptr<Packet> packet);

  uint32_t       m_portNo; //!< Port number
  sw_port*       m_swPort; //!< Pointer to datapath sw_port
  
  Ptr<CsmaNetDevice>        m_csmaDev;      //!< Underlying CsmaNetDevice
  Ptr<OFSwitch13NetDevice>  m_openflowDev;  //!< OpenFlow NetDevice
};

} // namespace ns3
#endif /* OFSWITCH13_PORT_H */
