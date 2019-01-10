# Openflow_Router2
Description: Software defined network router exercise, using OpenFlow

Topology:
h3----S1----S2-----h5
      |
      h4 
      
This is the direction for testing
1. Location of file
    a. router2.py -------- /home/pox/pox/misc
    b. mytopo2.py------- /home

2. Start controller
    a. open a terminal
    b. $ cd pox
        $ ./pox.py log.level --DEBUG misc.router2 misc.full_payload

3. Create the topo
    a. open another terminal
    b. $ sudo mn --custom mytopo2.py --topo mytopo --mac --switch ovsk --controller remote

4. Test:
    a. unknow address
        mininet> h3 ping -c1 10.0.50.5
        (on the controller terminal we can see ICMP destination unreachable notice)

    b. known address
        mininet> h3 ping -c1 10.0.2.2
        (on the controller terminal we can see MACadd changed notice, also the ICMP request and reply notice)
   
    c. pingall
        mininet> pingall
    
    d. iperf
        mininet> iperf
        (then we can find out the bandwith between h3 and h5)

    e. xterm (TCP/UDP traffic test)
        mininet> xterm h3 h5
        (1) on h3
             $ iperf -s
        (2) on h5
             $ iperf -c 10.0.1.2
