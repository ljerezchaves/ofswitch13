/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
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

#ifndef TUNNEL_ID_TAG_H
#define TUNNEL_ID_TAG_H

#include <ns3/tag.h>

namespace ns3 {

class Tag;

/**
 * \ingroup ofswitch13
 * Tag used to hold the tunnel metadata information (tunnel ID) when
 * sending/receiving a packet to/from a logical port device.
 */
class TunnelIdTag : public Tag
{
public:
  /**
   * Register this type.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);
  virtual TypeId GetInstanceTypeId (void) const;

  TunnelIdTag ();            //!< Default constructor

  /**
   * Complete constructor.
   * \param id The tunnel metadata information.
   */
  TunnelIdTag (uint64_t id);

  /**
   * Set the internal tunnel metadata information.
   * \param id The tunnel metadata information.
   */
  void SetTunnelId (uint64_t id);

  /** \return The tunnel metadata information */
  uint64_t GetTunnelId (void) const;

  // Inherited from Tag
  virtual void Serialize (TagBuffer i) const;
  virtual void Deserialize (TagBuffer i);
  virtual uint32_t GetSerializedSize () const;
  virtual void Print (std::ostream &os) const;

private:
  uint64_t m_tunnelId;      //!< Tunnel metadata information.
};

} // namespace ns3
#endif // TUNNEL_ID_TAG_H

