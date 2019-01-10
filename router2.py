#Appendix:
#https://github.com/qiangzheng211/-RouterExercise
#https://github.com/zhan849
#https://github.com/sriragh-karat16/router-exercise-openflow
#https://openflow.stanford.edu/display/ONL/POX+Wiki#POXWiki-POXAPIs
#http://www.cs.huji.ac.il/~yotamhc/courses/workshop/2015/ex2/
#https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html
#http://yuba.stanford.edu/cs244wiki/index.php/Learning_Switch

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pck
import pox.lib.addresses as addr

log = core.getLogger()

class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}
    #RoutingTable of S1
    self.r_table1 = {'10.0.1.2': ['10.0.1.2', 's1-eth1', '10.0.1.1/24', 1, '00:00:00:00:00:01'], '10.0.1.3': ['10.0.1.3', 's1-eth2', '10.0.1.1/24', 2, '00:00:00:00:00:02'], '10.0.2.2': ['10.0.2.2', 's2-eth1', '10.0.2.1/24', 3, '11:11:11:11:11:11']}
    #RoutingTable of S2
    self.r_table2 = {'10.0.2.2': ['10.0.2.2', 's2-eth1', '10.0.2.1/24', 1, '00:00:00:00:00:03'], '10.0.1.2': ['10.0.1.2', 's1-eth1', '10.0.1.1/24', 2, '22:22:22:22:22:22'], '10.0.1.3': ['10.0.1.3', 's1-eth2', '10.0.1.1/24', 2, '22:22:22:22:22:22']}

    self.r_table = {'10.0.1.2': ['10.0.1.2', 's1-eth1', '10.0.1.1/24', 1, '00:00:00:00:00:01'], '10.0.1.3': ['10.0.1.3', 's1-eth2', '10.0.1.1/24', 2, '00:00:00:00:00:02'], '10.0.2.2': ['10.0.2.2', 's2-eth1', '10.0.2.1/24', 1, '00:00:00:00:00:03']}

  def FlowMod(self, packetin, out_port):
    msg = of.ofp_flow_mod()
    msg.match.in_port = packetin.in_port
    msg.idle_timeout = 10
    msg.buffer_id = packetin.buffer_id
    msg.actions.append(of.ofp_action_output(port = out_port)) 
    log.debug("Flowmod Install")    
  def opflow_msg(self,packetin,et):
    msg = of.ofp_packet_out()
    msg.data = et.pack()
    action = of.ofp_action_output(port = packetin.in_port)
    msg.actions.append(action)
    self.connection.send(msg) 
  def dest_unreach(self,packet,packetin):
    unre = pck.unreach()
    unre.payload = packet.payload
    icmp_re = pck.icmp()
    icmp_re.type = pck.TYPE_DEST_UNREACH
    icmp_re.code = pck.CODE_UNREACH_HOST
    icmp_re.payload = unre
    ip_icmp = pck.ipv4(protocol = pck.ipv4.ICMP_PROTOCOL, srcip = unre.payload.dstip,dstip = unre.payload.srcip)
    ip_icmp.payload = icmp_re
    et_icmp = pck.ethernet(type = pck.ethernet.IP_TYPE,src = packet.dst,dst = packet.src)
    et_icmp.payload = ip_icmp
    self.opflow_msg(packetin,et_icmp)


  def handle_arp(self, packet, packetin):
	if packet.payload.opcode == pck.arp.REQUEST:
		log.debug("Received ARP request")
		handle_re = pck.arp()
                ############handle_re.hwsrc = addr.EthAddr("88:88:88:88:88:88")
                if str(packet.payload.protosrc) == '10.0.1.2' or str(packet.payload.protosrc) == '10.0.1.3':
                   #arp request from host of S1, mac addr of S1
                   handle_re.hwsrc = addr.EthAddr('11:11:11:11:11:11') 
                   log.debug('MACadd changed to 11:11:11:11:11:11')  
 		elif str(packet.payload.protosrc) == '10.0.2.2':
                   #arp request from host of S2, mac addr of S2
		   handle_re.hwsrc = addr.EthAddr('22:22:22:22:22:22')
                   log.debug('MACadd changed to 22:22:22:22:22:22')
		handle_re.hwdst = packet.payload.hwsrc
		handle_re.protosrc = packet.payload.protodst
		handle_re.protodst = packet.payload.protosrc
		handle_re.opcode = pck.arp.REPLY

		et = pck.ethernet(src=packet.dst,dst=packet.src,type=pck.ethernet.ARP_TYPE)
		et.payload = handle_re

		self.opflow_msg(packetin,et)
		log.debug("Sent ARP replay")

	elif packet.payload.opcode == pck.arp.REPLY:
		log.debug ("Received ARP reply" )
		self.mac_to_port[packet.src] = packetin.in_port
	else:
		log.debug( "Received other ARP optional code" )

  def handle_icmp(self, packet, packetin):
        icmp_p = packet.payload.payload
        if icmp_p.type == pck.TYPE_ECHO_REQUEST:
           log.debug("Received ICMP request")
           if str(packet.dst) == "11:11:11:11:11:11":    #packet destination s1
                i = 0
                for k in self.r_table1.keys():     
                    if packet.payload.dstip.inNetwork(k):
                                i = k
                                break
                if i!=0:
			log.debug("Sent ICMP reply")
			icmp_re = pck.icmp()
			icmp_re.type = pck.TYPE_ECHO_REPLY
			icmp_re.payload = pck.echo()
			icmp_re.payload.seq = 1 + icmp_p.payload.seq
			icmp_re.payload.id = icmp_p.payload.id

			ip_icmp = pck.ipv4(protocol = pck.ipv4.ICMP_PROTOCOL, srcip = packet.payload.dstip,dstip = packet.payload.srcip)
			ip_icmp.payload = icmp_re

			et_icmp = pck.ethernet(type = pck.ethernet.IP_TYPE,src = packet.dst,dst = packet.src)
			et_icmp.payload = ip_icmp

			self.opflow_msg(packetin,et_icmp) 
		else:
			log.debug("ICMP destination unreachable")
                        self.dest_unreach(packet,packetin)
			




           elif str(packet.dst) == "22:22:22:22:22:22":    #packet destination s2
                i = 0
		for k in self.r_table2.keys():        
			if packet.payload.dstip.inNetwork(k):
				i = k
				break
		if i!=0:
			log.debug("Sent ICMP reply")
			icmp_re = pck.icmp()
			icmp_re.type = pck.TYPE_ECHO_REPLY
			icmp_re.payload = pck.echo()
			icmp_re.payload.seq = 1 + icmp_p.payload.seq
			icmp_re.payload.id = icmp_p.payload.id

			ip_icmp = pck.ipv4(protocol = pck.ipv4.ICMP_PROTOCOL, srcip = packet.payload.dstip,dstip = packet.payload.srcip)
			ip_icmp.payload = icmp_re

			et_icmp = pck.ethernet(type = pck.ethernet.IP_TYPE,src = packet.dst,dst = packet.src)
			et_icmp.payload = ip_icmp

			self.opflow_msg(packetin,et_icmp) 
		else:
			log.debug("ICMP destination unreachable")
                        self.dest_unreach(packet,packetin) 

           else:
             log.debug("ICMP destination unreachable")
             self.dest_unreach(packet,packetin) 



  def handle_static(self, packet, packetin):
	i = 0
        if str(packet.dst) == "11:11:11:11:11:11":     #packet destination s1
              for k in self.r_table1.keys():
	           if  packet.payload.dstip.inNetwork(k):
		       i = k
		       break
              if i != 0:
		 pt = self.r_table1[i][3]
		 ethdst = addr.EthAddr(self.r_table[i][4])

        elif str(packet.dst) == "22:22:22:22:22:22":   #packet destination s2
	        for k in self.r_table.keys():
	             if  packet.payload.dstip.inNetwork(k):
                         i = k
		         break
                if i != 0:
                   pt = self.r_table2[i][3]
                   ethdst = addr.EthAddr(self.r_table[i][4])
        else:
                for k in self.r_table.keys():
                     if  packet.payload.dstip.inNetwork(k):
                         i = k
                         break
                if i != 0:
		   pt = self.r_table[i][3]
		   ethdst = addr.EthAddr(self.r_table[i][4])            
	msg = of.ofp_packet_out()
	action = of.ofp_action_output(port = pt)
	packet.src = packet.dst
	packet.dst = ethdst
	msg.data = packet.pack()
	msg.actions.append(action)
	self.connection.send(msg)
	
		
  def act_like_rt(self,packet,packetin):
	if packet.type == pck.ethernet.ARP_TYPE:
		self.handle_arp(packet, packetin)
	elif packet.type == pck.ethernet.IP_TYPE:
		if packet.payload.protocol == pck.ipv4.ICMP_PROTOCOL:
			self.handle_icmp(packet, packetin)
		else:
			self.handle_static(packet, packetin)
	self.FlowMod( packetin, packetin.in_port)

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    packet = event.parsed
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packetin = event.ofp
    self.act_like_rt(packet, packetin)




def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
