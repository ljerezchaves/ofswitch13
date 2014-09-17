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

#ifndef LEARNING_CONTROLLER_H
#define LEARNING_CONTROLLER_H

#include "ofswitch13-interface.h"
#include "ofswitch13-net-device.h"
#include "ofswitch13-controller.h"

namespace ns3 {

/**
 * \ingroup ofswitch13
 * \brief An Learning OpenFlow 1.3 controller (works as L2 switch)
 */
class LearningController : public OFSwitch13Controller
{
public:
  LearningController ();
  virtual ~LearningController ();

  // inherited from Object
  static TypeId GetTypeId (void);
  virtual void DoDispose ();
  
  // inherited from OFSwitch13Controller
  ofl_err HandleMsgPacketIn (ofl_msg_packet_in *msg, SwitchInfo swtch, uint64_t xid);
  ofl_err HandleMsgFeaturesReply (ofl_msg_features_reply *msg, SwitchInfo swtch, uint64_t xid);

private:
  // inherited from Application
  void StartApplication (void);
  void StopApplication (void);
};

} // namespace ns3
#endif /* LEARNING_CONTROLLER_H */
