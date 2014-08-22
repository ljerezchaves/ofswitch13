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

#include "ofswitch13-controller.h"
#include "ofswitch13-net-device.h"

NS_LOG_COMPONENT_DEFINE ("OFSwitch13Controller");

namespace ns3 {

NS_OBJECT_ENSURE_REGISTERED (OFSwitch13Controller)
  ;

OFSwitch13Controller::OFSwitch13Controller ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

OFSwitch13Controller::~OFSwitch13Controller ()
{
  NS_LOG_FUNCTION_NOARGS ();
}


void
OFSwitch13Controller::DoDispose ()
{
  m_switches.clear ();
}

TypeId 
OFSwitch13Controller::GetTypeId (void) 
{
  static TypeId tid = TypeId ("ns3::OFSwitch13Controller") 
    .SetParent<Object> ()
    .AddConstructor<OFSwitch13Controller> ()
    ;
  return tid; 
}
void
OFSwitch13Controller::AddSwitch (Ptr<OFSwitch13NetDevice> swtch)
{
  if (m_switches.find (swtch) != m_switches.end ())
    {
      NS_LOG_INFO ("This Controller has already registered this switch!");
    }
  else
    {
      NS_LOG_INFO ("Registering switch " << swtch << " at controller " << this);
      m_switches.insert (swtch);
    }
}


void
OFSwitch13Controller::SendToSwitch (Ptr<OFSwitch13NetDevice> swtch, void * msg, size_t length)
{
  if (m_switches.find (swtch) == m_switches.end ())
    {
      NS_LOG_ERROR ("Can't send to this switch, not registered to the Controller.");
      return;
    }

 // swtch->ForwardControlInput (msg, length);
}


uint8_t
OFSwitch13Controller::GetPacketType (ofpbuf* buffer)
{
  ofp_header* hdr = (ofp_header*)ofpbuf_try_pull (buffer, sizeof (ofp_header));
  uint8_t type = hdr->type;
  ofpbuf_push_uninit (buffer, sizeof (ofp_header));
  return type;
}


void
OFSwitch13Controller::CreateFlowModMsg () 
{
  struct ofl_msg_flow_mod msg =
       {{.type = OFPT_FLOW_MOD},
         .cookie = 0x0000000000000000ULL,
         .cookie_mask = 0x0000000000000000ULL,
         .table_id = 0xff,
         .command = OFPFC_ADD,
         .idle_timeout = OFP_FLOW_PERMANENT,
         .hard_timeout = OFP_FLOW_PERMANENT,
         .priority = OFP_DEFAULT_PRIORITY,
         .buffer_id = 0xffffffff,
         .out_port = OFPP_ANY,
         .out_group = OFPG_ANY,
         .flags = 0x0000,
         .match = NULL,
         .instructions_num = 0,
         .instructions = NULL
       };

  // Essas duas linhas sao lixo, apenas pra compilar...
  if(msg.command == OFPFC_DELETE) 
    NS_LOG_UNCOND ("ok");
  
//    parse_flow_mod_args(argv[0], &msg);
//    if (argc > 1) {
//        size_t i, j;
//        size_t inst_num = 0;
//        if (argc > 2){
//            inst_num = argc - 2;
//            j = 2;
//            parse_match(argv[1], &(msg.match));
//        }
//        else {
//            if(msg.command == OFPFC_DELETE) {
//                inst_num = 0;
//                parse_match(argv[1], &(msg.match));
//            } else {
//                /*We copy the value because we don't know if
//                it is an instruction or match.
//                If the match is empty, the argv is modified
//                causing errors to instructions parsing*/
//                char *cpy = malloc(strlen(argv[1]));
//                memcpy(cpy, argv[1], strlen(argv[1])); 
//                parse_match(cpy, &(msg.match));
//                free(cpy);
//                if(msg.match->length <= 4){
//                    inst_num = argc - 1;
//                    j = 1;
//                }
//            }
//        }
//
//        msg.instructions_num = inst_num;
//        msg.instructions = xmalloc(sizeof(struct ofl_instruction_header *) * inst_num);
//        for (i=0; i < inst_num; i++) {
//            parse_inst(argv[j+i], &(msg.instructions[i]));
//        }
//    } else {
//        make_all_match(&(msg.match));
//    }
//    dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);
}





} // namespace ns3
#endif // NS3_OFSWITCH13
