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

#ifndef OFSWITCH13_CONTROLLER_H
#define OFSWITCH13_CONTROLLER_H

#include "ofswitch13-interface.h"
#include "ofswitch13-net-device.h"

namespace ns3 {

class OFSwitch13NetDevice;

namespace ofs {

/**
 * \brief An interface for a Controller of OFSwitch13NetDevices
 *
 * Follows the OpenFlow 1.3 specification for a controller.
 */
class Controller : public Object
{
public:
  static TypeId GetTypeId (void)
  {
    static TypeId tid = TypeId ("ns3::ofs::Controller")
      .SetParent<Object> ()
      .AddConstructor<Controller> ()
    ;
    return tid;
  }

  virtual ~Controller ()
  {
    m_switches.clear ();
  }

  /**
   * Adds a switch to the controller.
   *
   * \param swtch The switch to register.
   */
  virtual void AddSwitch (Ptr<OFSwitch13NetDevice> swtch);

  /**
   * A switch calls this method to pass a message on to the Controller.
   *
   * \param swtch The switch the message was received from.
   * \param buffer The message.
   */
  virtual void ReceiveFromSwitch (Ptr<OFSwitch13NetDevice> swtch, ofpbuf* buffer)
  {
  }

protected:
  /**
   * \internal
   *
   * However the controller is implemented, this method is to
   * be used to pass a message on to a switch.
   *
   * \param swtch The switch to receive the message.
   * \param msg The message to send.
   * \param length The length of the message.
   */
  virtual void SendToSwitch (Ptr<OFSwitch13NetDevice> swtch, void * msg, size_t length);

  /**
   * \internal
   *
   * Get the packet type on the buffer, which can then be used
   * to determine how to handle the buffer.
   *
   * \param buffer The packet in OpenFlow buffer format.
   * \return The packet type, as defined in the ofp_type struct.
   */
  uint8_t GetPacketType (ofpbuf* buffer);

  typedef std::set<Ptr<OFSwitch13NetDevice> > Switches_t;
  Switches_t m_switches;  ///< The collection of switches registered to this controller.
};



} // namespace ofs
} // namespace ns3
#endif /* OFSWITCH13_CONTROLLER_H */
