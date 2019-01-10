"""Custom topology example

Two directly connected switches plus a host for each switch:

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):

    def __init__( self ):
        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        h3 = self.addHost( 'h3', ip = "10.0.1.2", defaultRoute = "via 10.0.1.1/24" )
        h4 = self.addHost( 'h4', ip = "10.0.1.3", defaultRoute = "via 10.0.1.1/24" )
        h5 = self.addHost( 'h5', ip = "10.0.2.2", defaultRoute = "via 10.0.2.1/24" )

        s1 = self.addSwitch( 's1' )
        s2 = self.addSwitch( 's2' )

        # Add links
        self.addLink( h3, s1 )
        self.addLink( h4, s1 )
        self.addLink( h5, s2 )
        self.addLink( s1, s2 )
    
topos = { 'mytopo': ( lambda: MyTopo() ) }
