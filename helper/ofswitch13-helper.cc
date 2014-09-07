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

#include "ofswitch13-helper.h"
#include "ns3/ofswitch13-net-device.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/application-container.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/node.h"
#include "ns3/log.h"

#include "ns3/applications-module.h"  //FIXME


NS_LOG_COMPONENT_DEFINE ("OFSwitch13Helper");

namespace ns3 {

class OFSwitch13Controller;

OFSwitch13Helper::OFSwitch13Helper ()
  : m_controller (0),
    m_app (0)
{
  NS_LOG_FUNCTION_NOARGS ();
  m_deviceFactory.SetTypeId ("ns3::OFSwitch13NetDevice");
  m_controllerFactory.SetTypeId ("ns3::OFSwitch13Controller");

  m_csmaHelper.SetChannelAttribute ("DataRate", DataRateValue (DataRate ("1Gbps")));
  m_csmaHelper.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (2)));
}

void
OFSwitch13Helper::SetDeviceAttribute (std::string n1, const AttributeValue &v1)
{
  NS_LOG_FUNCTION_NOARGS ();
  m_deviceFactory.Set (n1, v1);
}

void
OFSwitch13Helper::SetControllerAttribute (std::string n1, const AttributeValue &v1)
{
  NS_LOG_FUNCTION_NOARGS ();
  m_controllerFactory.Set (n1, v1);
}

void
OFSwitch13Helper::EnableOpenFlowPcap ()
{
  m_csmaHelper.EnablePcap ("controller-switches", m_controllerPort);
}

Ptr<OFSwitch13Controller> 
OFSwitch13Helper::InstallController (Ptr<Node> cNode)
{
  if (m_app == 0)
    {
      // Install the controller App in the cNode
      m_controller = cNode;
      m_app = m_controllerFactory.Create<OFSwitch13Controller> ();
      cNode->AddApplication (m_app);
      m_app->SetStartTime (Seconds (0));

      // Install the TCP/IP stak in the cNode and swNodes
      InternetStackHelper internet;
      internet.Install (cNode);
      internet.Install (m_switches);

      // Create a gigabit csma channel connecting all switches to the controller
      NetDeviceContainer switchControlDevs;
      switchControlDevs = m_csmaHelper.Install (NodeContainer (cNode, m_switches));
      m_controllerPort = switchControlDevs.Get (0);

      // Set IPv4 control and switch address
      Ipv4AddressHelper ipv4control;
      Ipv4InterfaceContainer controlIpIfaces;
      ipv4control.SetBase ("10.100.150.0", "255.255.255.0");
      controlIpIfaces = ipv4control.Assign (switchControlDevs);

      // Registering the application to all switches
      for (size_t i = 0; i < m_devices.size (); i++)
        {
          Ptr<Node> sw = m_switches.Get (i);
          //Ptr<OFSwitch13NetDevice> dev = dynamic_cast<OFSwitch13NetDevice *> (m_devices.Get (i));
          Ptr<OFSwitch13NetDevice> dev = m_devices.at (i);
          NS_ASSERT (dev->GetNode () == sw);
          
          NS_LOG_INFO ("**** Registering the controller to switch " << dev);
          dev->SetController (m_app);
          //dev->RegisterControllerPort (m_controllerPort);

        }

      // Just for test... FIXME
      // Create a ping application from controller to switch
      Ipv4Address switchAddr = controlIpIfaces.GetAddress (1);
      V4PingHelper pingControl = V4PingHelper (switchAddr);
      ApplicationContainer app = pingControl.Install (cNode);
      app.Start (Seconds (1.0));
    }

  return m_app;
}


NetDeviceContainer
OFSwitch13Helper::InstallSwitch (Ptr<Node> swNode, NetDeviceContainer devs)
{
  NS_ASSERT_MSG (m_app == 0, "Can't install more switches.");
  NS_LOG_DEBUG ("Install switch device on node " << swNode->GetId ());
  
  Ptr<OFSwitch13NetDevice> ofswitchNetDev = m_deviceFactory.Create<OFSwitch13NetDevice> ();
  m_switches.Add (swNode);
  m_devices.push_back (ofswitchNetDev);
  swNode->AddDevice (ofswitchNetDev);
  for (NetDeviceContainer::Iterator i = devs.Begin (); i != devs.End (); ++i)
    {
      NS_LOG_INFO ("  Add SwitchPort " << *i);
      ofswitchNetDev->AddSwitchPort (*i);
    }
  return NetDeviceContainer (ofswitchNetDev);
}

}

#endif // NS3_OFSWITCH13
