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

  static int prio = 0;
  uint32_t outPort = OFPP_FLOOD;
  uint64_t dpId = swtch.netdev->GetDatapathId ();
  enum ofp_packet_in_reason reason = msg->reason;
  if (reason == OFPR_NO_MATCH)
    {
      // Let's get necessary information (input port and mac address)
      uint32_t inPort;
      size_t portLen = OXM_LENGTH(OXM_OF_IN_PORT); // (Always 4 bytes)
      ofl_match_tlv *input = oxm_match_lookup (OXM_OF_IN_PORT, (ofl_match*)msg->match);
      memcpy (&inPort, input->value, portLen);
      
      Mac48Address src48;
      ofl_match_tlv *ethSrc = oxm_match_lookup (OXM_OF_ETH_SRC, (ofl_match*)msg->match);
      src48.CopyFrom (ethSrc->value);
     
      Mac48Address dst48;
      ofl_match_tlv *ethDst = oxm_match_lookup (OXM_OF_ETH_DST, (ofl_match*)msg->match);
      dst48.CopyFrom (ethDst->value);
 
      DatapathMap_t::iterator it = m_learnedInfo.find (dpId);
      if (it != m_learnedInfo.end ())
        {
          L2Table_t *l2Table = &it->second;

          // Looking for port based on destination address (except for broadcast)
          if (!dst48.IsBroadcast ())
            {
              L2Table_t::iterator itDst = l2Table->find (dst48);
              if (itDst != l2Table->end ())
                {
                  outPort = itDst->second; 
                }
              else 
                {
                  NS_LOG_DEBUG ("No L2 switch information for mac " << dst48 << " yet. Flooding...");
                }
            }

          // Learning port from source address
          NS_ASSERT_MSG (!src48.IsBroadcast (), "Invalid source broadcast address");
          L2Table_t::iterator itSrc = l2Table->find (src48);
          if (itSrc == l2Table->end ())
            {
              std::pair <L2Table_t::iterator, bool> ret;
              ret = l2Table->insert (std::pair<Mac48Address, uint32_t> (src48, inPort));
              if (ret.second == false) 
                {
                  NS_LOG_ERROR ("Can't insert mac48address / port pair");
                }
              else
                {
                  // Send a flow-mod to switch creating this flow;
                  std::ostringstream cmd;
                  cmd << "cmd=add,table=0,prio=" << ++prio << " eth_dst=" << src48 << " apply:output="<< inPort;
                  SendFlowModMsg (swtch, cmd.str().c_str());
                }
            }
          else
            {
              NS_ASSERT_MSG (itSrc->second == inPort, "Inconsistent L2 switching table");
            }
        }
      else 
        {
          NS_LOG_WARN ("No L2Table for this datapath id " << dpId);
        }
      
      NS_UNUSED (outPort);
      // TODO: create packet out and set proper actions
      // Lets send the packet out to switch.
      ofl_msg_packet_out reply;
      reply.header.type = OFPT_PACKET_OUT;
      reply.buffer_id = msg->buffer_id;
      reply.in_port = OFPP_CONTROLLER;
      reply.data_length = msg->data_length;
      reply.data = msg->data;

      // Create output action
      ofl_action_output *a = (ofl_action_output*)xmalloc (sizeof (struct ofl_action_output));
      a->header.type = OFPAT_OUTPUT;
      a->port = outPort;
      a->max_len = OFPCML_NO_BUFFER; // FIXME Should be 0?
      
      reply.actions_num = 1;
      reply.actions = (ofl_action_header**)&a;
      
      char *str;
      str = ofl_msg_to_string ((ofl_msg_header*)&reply, NULL);
      NS_LOG_INFO ("TX to swtc: " << str);
      free (str);

      SendToSwitch (swtch, ofs::PacketFromMsg ((ofl_msg_header*)&reply, xid));
      free (a);
    }
  else
    {
      NS_LOG_WARN ("This packet was sent to controller for a reason that we can't handle.");
    }
 
 
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

  // Create an empty L2SwitchingTable and insert it into m_learnedInfo
  L2Table_t l2Table;
  uint64_t dpId = swtch.netdev->GetDatapathId ();
  
  std::pair <DatapathMap_t::iterator, bool> ret;
  ret =  m_learnedInfo.insert (std::pair<uint64_t, L2Table_t> (dpId, l2Table));
  if (ret.second == false) 
    {
      NS_LOG_ERROR ("There is already a table for this datapath");
    }
}

} // namespace ns3
#endif // NS3_OFSWITCH13
