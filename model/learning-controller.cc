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

#include "learning-controller.h"

NS_LOG_COMPONENT_DEFINE ("LearningController");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (LearningController);


/********** Public methods ***********/


LearningController::LearningController ()
{
  NS_LOG_FUNCTION_NOARGS ();
  SetConnectionCallback (MakeCallback (&LearningController::ConnectionStarted, this));
}

LearningController::~LearningController ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

TypeId 
LearningController::GetTypeId (void) 
{
  static TypeId tid = TypeId ("ns3::LearningController") 
    .SetParent<OFSwitch13Controller> ()
    .AddConstructor<LearningController> ()
    ;
  return tid; 
}

void
LearningController::DoDispose ()
{
  OFSwitch13Controller::DoDispose ();
  Application::DoDispose ();
}

ofl_err 
LearningController::HandleMsgPacketIn (ofl_msg_packet_in *msg, SwitchInfo swtch, uint64_t xid)
{
  NS_LOG_FUNCTION (swtch.ipv4 << xid);
  // TODO: Make this pure virtual and implement in subclass
  // All handlers must free the message when everything is ok
  ofl_msg_free ((ofl_msg_header*)msg, NULL/*dp->exp*/);
  return 0;
}

/********** Private methods **********/
void
LearningController::StartApplication ()
{
  OFSwitch13Controller::StartApplication ();
}

void
LearningController::StopApplication ()
{
  OFSwitch13Controller::StopApplication ();
}

void 
LearningController::ConnectionStarted (SwitchInfo swtch)
{
  NS_LOG_FUNCTION (this << swtch.ipv4);

  // After a successfull handshake, let's install table-miss entry
  SendFlowModMsg (swtch, "cmd=add,table=0,prio=0, apply:output=ctrl");

  // Create the L2 switching table
  // MacAddrPortMap_t l2Table

}

} // namespace ns3
#endif // NS3_OFSWITCH13
