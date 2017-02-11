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

#ifndef OFSWITCH13_DEVICE_CONTAINER_H
#define OFSWITCH13_DEVICE_CONTAINER_H

#include <cstdint>
#include <vector>
#include <ns3/ofswitch13-device.h>

namespace ns3 {

/**
 * \ingroup ofswitch13
 * \brief Holds a vector of ns3::OFSwitch13Device pointers
 *
 * Typically OpenFlow Devices are aggregated to nodes using the
 * OFSwitch13Helper. The helper InstallSwitch* methods takes a NodeContainer
 * which holds some number of Ptr<Node>. For each of the Nodes in the
 * NodeContainer the helper will instantiate an OpenFlow device and aggregate
 * it to the node.  For each of the devices, the helper also adds the device
 * into a Container for later use by the caller. This is that container used to
 * hold the Ptr<OFSwitch13Device> which are instantiated by the device
 * helper.
 */
class OFSwitch13DeviceContainer
{
public:
  /// OFSwitch13Device container iterator
  typedef std::vector<Ptr<OFSwitch13Device> >::const_iterator Iterator;

  /**
   * Create an empty OFSwitch13DeviceContainer.
   */
  OFSwitch13DeviceContainer ();

  /**
   * Create a OFSwitch13DeviceContainer with exactly one device that has
   * previously been instantiated.
   *
   * \param dev An OpenFlow device to add to the container.
   */
  OFSwitch13DeviceContainer (Ptr<OFSwitch13Device> dev);

  /**
   * Create a OFSwitch13DeviceContainer with exactly one device. Create a
   * OFSwitch13DeviceContainer with exactly one device which has been
   * previously instantiated and assigned a name using the Object name service.
   * This OpenFlow device is specified by its assigned name.
   *
   * \param devName The name of the device to add to the container.
   */
  OFSwitch13DeviceContainer (std::string devName);

  /**
   * Create a device container which is a concatenation of the two input
   * OFSwitch13DeviceContainers.
   *
   * \note A frequently seen idiom that uses these constructors involves the
   * implicit conversion by constructor of Ptr<OFSwitch13Device>. When used,
   * two Ptr<OFSwitch13Device> will be passed to this constructor instead of
   * OFSwitch13DeviceContainer&.  C++ will notice the implicit conversion path
   * that goes through the OFSwitch13DeviceContainer (Ptr<OFSwitch13Device>
   * dev) constructor above. Using this conversion one may provide optionally
   * provide arguments of Ptr<OFSwitch13Device> to these constructors.
   *
   * \param a A device container
   * \param b Another device container
   *
   */
  OFSwitch13DeviceContainer (const OFSwitch13DeviceContainer &a,
                             const OFSwitch13DeviceContainer &b);

  /**
   * \brief Get an iterator which refers to the first OpenFlow device in the
   * container.
   *
   * OpenFlow devices can be retrieved from the container in two ways. First,
   * directly by an index into the container, and second, using an iterator.
   * This method is used in the iterator method and is typically used in a
   * for-loop to run through the devices.
   *
   * \code
   *   OFSwitch13DeviceContainer::Iterator i;
   *   for (i = container.Begin (); i != container.End (); ++i)
   *     {
   *       (*i)->method ();  // some OFSwitch13Device method
   *     }
   * \endcode
   *
   * \returns an iterator which refers to the first device in the container.
   */
  Iterator Begin (void) const;

  /**
   * \brief Get an iterator which indicates past-the-last  OpenFlow device in
   * the container.
   *
   * OpenFlow devices can be retrieved from the container in two ways. First,
   * directly by an index into the container, and second, using an iterator.
   * This method is used in the iterator method and is typically used in a
   * for-loop to run through the devices
   *
   * \code
   *   OFSwitch13DeviceContainer::Iterator i;
   *   for (i = container.Begin (); i != container.End (); ++i)
   *     {
   *       (*i)->method ();  // some OFSwitch13Device method
   *     }
   * \endcode
   *
   * \returns an iterator which indicates an ending condition for a loop.
   */
  Iterator End (void) const;

  /**
   * \brief Get the number of Ptr<OFSwitch13Device> stored in this container.
   *
   * OpenFlow devices can be retrieved from the container in two ways. First,
   * directly by an index into the container, and second, using an iterator.
   * This method is used in the direct method and is typically used to
   * define an ending condition in a for-loop that runs through the stored
   * devices
   *
   * \code
   *   uint32_t nDevices = container.GetN ();
   *   for (uint32_t i = 0 i < nDevices; ++i)
   *     {
   *       Ptr<OFSwitch13Device> p = container.Get (i);
   *       p->method ();  // some OFSwitch13Device method
   *     }
   * \endcode
   *
   * \returns the number of Ptr<OFSwitch13Device> stored in this container.
   */
  uint32_t GetN (void) const;

  /**
   * \brief Get the Ptr<OFSwitch13Device> stored in this container at a given
   * index.
   *
   * OpenFlow devices can be retrieved from the container in two ways.First,
   * directly by an index into the container, and second, using an iterator.
   * This method is used in the direct method and is used to retrieve the
   * indexed Ptr<OFSwitch13Device>.
   *
   * \code
   *   uint32_t nDevices = container.GetN ();
   *   for (uint32_t i = 0 i < nDevices; ++i)
   *     {
   *       Ptr<OFSwitch13Device> p = container.Get (i);
   *       p->method ();  // some OFSwitch13Device method
   *     }
   * \endcode
   *
   * \param i the index of the requested device pointer.
   * \returns the requested device pointer.
   */
  Ptr<OFSwitch13Device> Get (uint32_t i) const;

  /**
   * \brief Append the contents of another OFSwitch13DeviceContainer to the end
   * of this container.
   *
   * \param other The OFSwitch13DeviceContainer to append.
   */
  void Add (OFSwitch13DeviceContainer other);

  /**
   * \brief Append a single Ptr<OFSwitch13Device> to this container.
   *
   * \param device The Ptr<OFSwitch13Device> to append.
   */
  void Add (Ptr<OFSwitch13Device> device);

  /**
   * \brief Append to this container the single Ptr<OFSwitch13Device> referred
   * to via its object name service registered name.
   *
   * \param deviceName The name of the OFSwitch13Device object to add to the
   * container.
   */
  void Add (std::string deviceName);

private:
  std::vector<Ptr<OFSwitch13Device> > m_devices; //!< OFSwitch13Device pointers
};

} // namespace ns3

#endif /* OFSWITCH13_DEVICE_CONTAINER_H */
