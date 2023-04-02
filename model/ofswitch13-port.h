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
 * Author: Luciano Jerez Chaves <ljerezchaves@gmail.com>
 */

#ifndef OFSWITCH13_PORT_H
#define OFSWITCH13_PORT_H

#include "ofswitch13-interface.h"
#include "ofswitch13-queue.h"

#include <ns3/net-device.h>
#include <ns3/object.h>
#include <ns3/packet.h>
#include <ns3/traced-callback.h>

namespace ns3
{

// The following explicit template instantiation declaration prevents modules
// including this header file from implicitly instantiating Queue<Packet>.
extern template class Queue<Packet>;

class OFSwitch13Device;

/**
 * \ingroup ofswitch13
 *
 * A OpenFlow switch port to interconnect the underlying NetDevice to the
 * OpenFlow device through the OpenFlow receive callback. This class handles the
 * BOFUSS internal sw_port structure.
 * \see BOFUSS udatapath/dp_ports.h
 * \attention Each underlying NetDevice used as port must only be assigned a MAC
 *            Address. Adding an Ipv4/IPv6 layer to it may cause error.
 */
class OFSwitch13Port : public Object
{
  public:
    OFSwitch13Port();           //!< Default constructor
    ~OFSwitch13Port() override; //!< Dummy destructor, see DoDispose

    /**
     * Complete Constructor. Create and populate a new datapath port, notifying
     * the controller of this new port.
     * \see BOFUSS new_port() at udatapath/dp_ports.c
     * \param dp The datapath.
     * \param netDev The underlying NetDevice.
     * \param openflowDev The OpenFlow device.
     */
    OFSwitch13Port(struct datapath* dp, Ptr<NetDevice> netDev, Ptr<OFSwitch13Device> openflowDev);

    /**
     * Register this type.
     * \return The object TypeId.
     */
    static TypeId GetTypeId();

    /**
     * Get the NetDevice pointer from the underlying port.
     * \return A pointer to the corresponding underlying NetDevice.
     */
    Ptr<NetDevice> GetPortDevice() const;

    /**
     * Get the OpenFlow port number for this port.
     * \return The port number.
     */
    uint32_t GetPortNo() const;

    /**
     * Get the OpenFlow queue for this port.
     * \return The port queue.
     */
    Ptr<OFSwitch13Queue> GetPortQueue() const;

    /**
     * Get a pointer to the internal BOFUSS port structure.
     * \return The requested pointer.
     */
    struct sw_port* GetPortStruct();

    /**
     * Get the OFSwitch13Device pointer from this port.
     * \return A pointer to the corresponding OFSwitch13Device.
     */
    Ptr<OFSwitch13Device> GetSwitchDevice() const;

    /**
     * Update the port state field based on NetDevice status, and notify the
     * controller when changes occurs.
     * \return true if the state of the port has changed, false otherwise.
     */
    bool PortUpdateState();

    /**
     * Send a packet over this OpenFlow switch port. It will check port
     * configuration, update counters and send the packet to the underlying
     * device.
     * \see BOFUSS function dp_ports_run() at udatapath/dp_ports.c
     * \param packet The Packet to send.
     * \param queueNo The queue to use.
     * \param tunnelId The metadata associated with a logical port.
     * \return true if the packet was sent successfully, false otherwise.
     */
    bool Send(Ptr<const Packet> packet, uint32_t queueNo = 0, uint64_t tunnelId = 0);

  protected:
    /** Destructor implementation */
    void DoDispose() override;

    // Inherited from ObjectBase.
    void NotifyConstructionCompleted() override;

  private:
    /**
     * Create the bitmaps of OFPPF_* describing port features.
     * \see BOFUSS netdev_get_features() at lib/netdev.c
     * \return Port features bitmap.
     */
    uint32_t GetPortFeatures();

    /**
     * Called when a packet is received on this OpenFlow switch port by the
     * underlying NetDevice. It will check port configuration, update counter
     * and send the packet to the OpenFlow pipeline.
     * \see BOFUSS function dp_ports_run() at udatapath/dp_ports.c
     * \param device Underlying ns-3 network device.
     * \param packet The received packet.
     * \param protocol Next protocol header value.
     * \param from Address of the correspondent.
     * \param to Address of the destination.
     * \param packetType Type of the packet.
     * \return true.
     */
    bool Receive(Ptr<NetDevice> device,
                 Ptr<const Packet> packet,
                 uint16_t protocol,
                 const Address& from,
                 const Address& to,
                 NetDevice::PacketType packetType);

    /** Trace source fired when a packet arrives at this switch port. */
    TracedCallback<Ptr<const Packet>> m_rxTrace;

    /** Trace source fired when a packet will be sent over this switch port. */
    TracedCallback<Ptr<const Packet>> m_txTrace;

    uint64_t m_dpId;                     //!< OpenFlow datapath ID.
    uint32_t m_portNo;                   //!< Port number.
    struct sw_port* m_swPort;            //!< BOFUSS port structure.
    Ptr<NetDevice> m_netDev;             //!< Underlying NetDevice.
    Ptr<OFSwitch13Queue> m_portQueue;    //!< OpenFlow port Queue.
    ObjectFactory m_factQueue;           //!< Factory for port queue.
    Ptr<OFSwitch13Device> m_openflowDev; //!< OpenFlow device.
};

} // namespace ns3
#endif /* OFSWITCH13_PORT_H */
