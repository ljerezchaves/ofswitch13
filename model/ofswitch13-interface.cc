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
#ifdef NS3_OFSWITCH13

#include "ofswitch13-interface.h"


namespace ns3 {
namespace ofs {

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Interface");

// \see new_port () at udatapath/dp_ports.c
Port::Port (Ptr<NetDevice> netdev, uint32_t port_no) : 
            flags (0),
            netdev (netdev)
{   
    conf = (ofl_port*)xmalloc (sizeof (struct ofl_port));
    memset (conf, 0x00, sizeof (struct ofl_port));
    conf->port_no = port_no;
    conf->state = 0x00000000 | OFPPS_LIVE;
    // Mac48Address a = Mac48Address::ConvertFrom (netdev_->GetAddress ());
    // memcpy (conf->hw_addr, (const void*)&a, ETH_ADDR_LEN);
    // conf->curr       = netdev_get_features(netdev, NETDEV_FEAT_CURRENT);
    // conf->advertised = netdev_get_features(netdev, NETDEV_FEAT_ADVERTISED);
    // conf->supported  = netdev_get_features(netdev, NETDEV_FEAT_SUPPORTED);
    // conf->peer       = netdev_get_features(netdev, NETDEV_FEAT_PEER);
    // conf->curr_speed = port_speed(port->conf->curr);
    // conf->max_speed  = port_speed(port->conf->supported);

    stats = (ofl_port_stats*)xmalloc (sizeof (struct ofl_port_stats));
    memset (stats, 0x00, sizeof (struct ofl_port_stats));
    stats->port_no = port_no;

    flags |= SWP_USED;
}


} // namespace ofs
} // namespace ns3
#endif // NS3_OFSWITCH13
