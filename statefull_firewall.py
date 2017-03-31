 #########################################################################################
 # SETUP                                                                                           #
 # -------------------------------------------------------------------                             #
 # test:    1) copy firewall-policies.csv in pyretic home and statefull firewall.py in examples    #
 #          2) sudo mn  --topo single,3  --controller remote                                       #
 #          3) python pyretic.py pyretic.examples.firewal                                          #
 #          4) On h1 host run  "sudo hping3 -V -S -s 6001 -p 5001 10.0.0.3 -c 1"                   #
 #########################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from netaddr import IPNetwork, IPAddress
from types import *
import os
import csv
# Ploicy file for Firewall Rules
PolicyFile = "%s/pyretic/firewall-policies.csv" % os.environ[ 'HOME' ]


class Firewall(DynamicPolicy):
    """
    Class to add and remove Firewall rules
    """

    def __init__(self):
        """
        Initializes the Firewall class
        """
        self.firewall = {}
        super(Firewall,self).__init__(true)
        print "Enabling Firewall Module"
        self.register_rules()

    def register_rules(self):
        """
        Register Policy rules to filter traffic
        """
        with open(PolicyFile, 'rb') as f:
            reader = csv.reader(f)
            for row in reader:
                if row[1] != "srcip":
                    self.add_policy(srcip=row[0], dstip=row[1], port=int(row[2]), value=self.str_bool(row[3]))


    def str_bool(self, policy):
        """
        This method convert a list of words to either True or False (Boolean)
        @args:
            policy: yes or no argument with different possible options
        """
        if str(policy).lower() in ("yes", "y", "true", "t", "allow", "permit", "1"): 
            return True
        if str(policy).lower() in ("no", "n", "false", "f", "block", "deny", "0", ""): 
            return False

    def add_policy(self, srcip="*", dstip="*", port=0, value=True):
        """
        This method adds the policies to the dictionary and sets the value to True if it was not
        specified in the csv file.
        @args:
            srcip: Source IP address of packet
            dstip: Destination IP address of packet 
            port: Destination port of packet
            value: Boolean variable to apply the firewall rules
        """
    	if value:
            print "Adding Firewall rule to drop the packets on firewall"
    	    self.drop_rule((srcip,dstip,port))
    	else:
            print "Adding Firewall rule to forward/bypass the firewall"
    	    self.forward_rule((srcip,dstip,port))

    def drop_rule(self, match_tuple):
        """
        Add flow to drop the matching packets on firewall
        @args:
            match_tuple: (srcip, dstip, srcport, dstport) Tuple
        """
        if match_tuple in self.firewall:
            print "Firewall rule for :%s already exists" % str(match_tuple)
            return
        self.firewall[match_tuple]=True
        print "Adding firewall rule in : %s" % str(match_tuple)
        self.update_policy()
    
    def forward_rule(self, match_tuple):
        """
        Delete flow to forward the matching packets from firewall
        @args:
            match_tuple: (srcip, dstip, srcport, dstport) Tuple
        """        
        try:
            del self.firewall[match_tuple]
            print "Deleting firewall rule in : %s" % str(match_tuple)
            self.update_policy()
        except:
            pass
        try:
            del self.firewall[match_tuple]
            print "Deleting firewall rule in %s: %s" % str(match_tuple)
            self.update_policy()
        except:
            pass

    def update_policy (self):
        """
        Adds the policy flows to match the packets
        """
        self.policy = ~union([match(srcip=tup[0], dstip=tup[1], dstport=tup[2]) for tup in self.firewall.keys()])


class PacketCapture(object):
    """
    Class for Capturing Packets on switch ports
    """

    def __init__(self, firewall_obj):
        """
        Initializes the class
        @args:
            firewall_obj: Firewall class object passed for reference
        """
        self.flow_table = {}
        self.firewall_obj = firewall_obj
        self.insideNetwork = ["10.0.0.0/24"]    # Modify it according to your switch internal network. In mininet this is the default one

    def packet_capture(self):
        """
        Captures the packets and registers a callback for the captured
        packets
        """
        pkt = packets()
        pkt.register_callback(self.packet_inspection)
        return pkt

    def packet_inspection(self, pkt):
        """
        Parse the received packet to get the required fields
        @args:
            pkt = Captured packet on switch port
        """
        if pkt['ethtype'] == IP_TYPE:
            parser = PktParserFactory(self, pkt)    # Returns the TCP/UDP class handles
            tracker = parser.get_conn_track_obj()
            if tracker:
                tracker.track_network()

    def checkIPinside(self, ip):
        """
        Check if the IP is from inside the network or not.
        """
        for network in self.insideNetwork:
            if IPAddress(str(ip)) in IPNetwork(network):
                return True
        return False


class PktParserFactory(object):
    """
    Base class for parsing Ether Packets
    """

    def __init__(self, cap_obj, pkt):
        """
        Initializes the class with packet raw data
        @args:
            cap_obj: PacketCapture class object for references
            pkt: Received packet raw dump
        """
        self.cap_obj = cap_obj
        self.frwl_obj = self.cap_obj.firewall_obj        
        self.pkt = pkt
        self.raw_bytes = [ord(c) for c in self.pkt['raw']]
        self.get_ip_info()


    def get_eth_payload(self):
        """
        Returns the ether payload
        """
        self.eth_payload_bytes = self.raw_bytes[self.pkt['header_len']:]

    def get_ip_info(self):
        """
        Returns the ip fields like ip version, payload and proto
        """
        self.get_eth_payload()
        ihl = (self.eth_payload_bytes[0] & 0b00001111)
        ip_header_len = ihl * 4
        self.ip_version = (self.eth_payload_bytes[0] & 0b11110000) >> 4        
        self.ip_payload_bytes = self.eth_payload_bytes[ip_header_len:]
        self.ip_proto = self.eth_payload_bytes[9] 

    def get_conn_track_obj(self):
        """
        Returns the object of TCP or UDP conn tracking classes
        depending on the proto type
        """
        if self.ip_proto == 0x06:
            return TCPConnTrack(self)
        elif self.ip_proto == 0x11:
            return UDPConnTrack(self)
        elif self.ip_proto == 0x01:
            print "ICMP packet"
            print self.frwl_obj.policy

    def check_policy(self, srcip="", dstip="", port=0):
        """
        This method checks the src ip, dst ip, and port number of the packet against the rules and
        return the value of the corresponding policy.
        @args:
            srcip: Source IP address of packet
            dstip: Destination IP address of packet
            port: Destination Port of packet
        """
        key = (srcip, dstip, port)
        if key in self.frwl_obj.firewall:
            print "Policy From (%s) to (%s) found." % (srcip, dstip)
            return self.frwl_obj.firewall[key]
        else:
            print "No Firewall Policy from (%s) to (%s)" %(srcip, dstip)
            return False


class TCPConnTrack(object):
    """
    Class for analysing TCP connections
    """

    def __init__(self, parser_obj):
        """
        Initializes the TCP class
        @args:
            parser_obj: PktParserFactory class object for references
        """
        self.parser_obj = parser_obj
        self.cap = self.parser_obj.cap_obj
        self.set_flags()

    def set_flags(self):
        """
        Extracts and Sets the TCP flags (SYN, ACK, PSH)
        """
        flags_byte = self.parser_obj.eth_payload_bytes[33]
        decode = '{0:08b}'.format(flags_byte)
        self.SYN = decode[-2]
        self.PSH = decode[-4]
        self.ACK = decode[-5]

    def track_network(self):
        """
        Tracks inside and outside network traffic
        """
        if self.cap.checkIPinside(self.parser_obj.pkt['srcip']):
            self.track_inside_network()
        else:
            self.track_outside_network()

    def track_inside_network(self):
        """
        Filter and install the flows for inside network traffic
        """
        if self.parser_obj.check_policy(self.parser_obj.pkt['srcip'], self.parser_obj.pkt['dstip'], self.parser_obj.pkt['dstport']) == True:
            print "Packet matched the rule and dropped! "
            return True
        key = (self.parser_obj.pkt['srcip'], self.parser_obj.pkt['dstip'], self.parser_obj.pkt['srcport'], self.parser_obj.pkt['dstport'])
        if key in self.cap.flow_table:
            print self.cap.flow_table
            if self.cap.flow_table[key][:2] == [1, "out"] and self.SYN and self.ACK:
                self.cap.flow_table[key][0] += 1
                self.cap.flow_table[key][1] = "in"
                print "TCP SYN ACK packet from inside"
                return True
            elif self.cap.flow_table[key][:2] == [2,"out"] and self.ACK:
                self.cap.flow_table[key][0] += 1
                self.cap.flow_table[key][1] = "in"
                print "TCP ACK Packet from inside "
                return True
            elif self.cap.flow_table[key][0] == 3 and self.PSH:
                self.cap.flow_table[key][0] += 1
                print "TCP handshacke is done. First packet of connection from inside.MOD is done "
                return True
            elif self.cap.flow_table[key][0] == 4:
                print "TCP handshacke is done. Second packet of connection from inside.MOD is done "
                del self.flow_table[key]    # Removes the key from flow table not to get it overflow
                return True
            elif self.cap.flow_table[key][2] < 10:  # It's a check to prevent from DOS
                self.cap.flow_table[key][2] += 1
                return True
            elif self.cap.flow_table[key][2] >= 10:
                del self.cap.flow_table[key]
                print "DOS attack detected!"
                #   Adding Rule to drop the packets from this source next time
                self.cap.firewall_obj.drop_rule((str(self.parser_obj.pkt['srcip']), str(self.parser_obj.pkt['dstip']), int(self.parser_obj.pkt['dstport'])))  #drop the pkt
                print self.cap.firewall_obj.policy
                return False
        else:   #   First TCP packet of a flow
            if self.SYN:
                print self.cap.flow_table
                self.cap.flow_table[key] = [1, "in", 0]#    First is for # packets, second is for traffic direction and third to prevent DOS
                print "TCP SYN Packet from inside "
                return True

    def track_outside_network(self):
        """
        Checks and installs the flows for outside network traffic
        """
        if self.parser_obj.check_policy(self.parser_obj.pkt['srcip'], self.parser_obj.pkt['dstip'], self.parser_obj.pkt['dstport']) == True:
            print "Packet matched the role and dropped"
            return True
        key = (self.parser_obj.pkt['srcip'], self.parser_obj.pkt['dstip'], self.parser_obj.pkt['srcport'], self.parser_obj.pkt['dstport'])
        if key in self.cap.flow_table:
            if self.cap.flow_table[key][:2] == [1, "in"] and self.SYN and self.ACK:
                self.cap.flow_table[key][0] += 1
                self.cap.flow_table[key][1] = "out"
                print "TCP SYN ACK packet from outside"
                return True
            elif self.cap.flow_table[key][:2] == [2, "in"] and self.ACK:
                self.cap.flow_table[key][0] += 1
                self.cap.flow_table[key][1] = "out"
                print "TCP ACK Packet from outside"
                return True
            elif self.cap.flow_table[key][0] == 3 and self.PSH:
                self.cap.flow_table[key][0] += 1
                print "TCP handshacke is done. First packet of connection from outside."
                return True
            elif self.cap.flow_table[key][0] == 4:
                del self.cap.flow_table[key]
                return True
            elif self.cap.flow_table[key][2] < 10:
                self.cap.flow_table[key][2] += 1
                return True
            elif self.cap.flow_table[key][2] > 10:
                del self.cap.flow_table[key]
                print "DOS attack detected!"
                self.cap.firewall_obj.drop_rule((str(self.parser_obj.pkt['srcip']), str(self.parser_obj.pkt['dstip']), int(self.parser_obj.pkt['dstport'])))  #drop the pkt
                return False
        else:
            if self.SYN:
                self.cap.flow_table[key] = [1, "out", 0]   # the first parameter is a counter for the number of packets from that flow, the second is direction, third to prevent from DOS
                print "Swithc Module: TCP SYN Packet from outside "
                return True      

class UDPConnTrack(object):
    """
    Class for analysing UDP connections
    @args:
        parser_obj: PktParserFactory class object for references    
    """

    def __init__(self, parser_obj):
        """
        Initializes the UDP class
        """
        self.parser_obj = parser_obj
        self.cap = self.parser_obj.cap_obj

    def track_network(self):
        """
        Tracks inside and outside network traffic
        """
        if self.cap.checkIPinside(self.parser_obj.pkt['srcip']):
            self.track_inside_network()
        else:
            self.track_outside_network()

    def track_inside_network(self):
        """
        Checks and installs the flows for insider network traffic
        """
        if self.parser_obj.check_policy(self.parser_obj.pkt['srcip'], self.parser_obj.pkt['dstip'], self.parser_obj.pkt['dstport']) == True:
            print "Packet matched the rule and dropped"
            return True
        key = (self.parser_obj.pkt['srcip'], self.parser_obj.pkt['dstip'], self.parser_obj.pkt['srcport'], self.parser_obj.pkt['dstport'])
        if key in self.cap.flow_table:
            print self.cap.flow_table
            if self.cap.flow_table[key][:2] == [1, "out"]:
                self.cap.flow_table[key][0] += 1
                self.cap.flow_table[key][1] = "in"
                print "UDP Packet from inside. Counter is 2 now"
                return "Pktout"
            elif self.cap.flow_table[key][:2] == [2,"out"]:
                self.cap.flow_table[key][0] += 1
                self.cap.flow_table[key][1] = "in"
                print "UDP Packet from inside. Counter is 3 now"
                return "Pktout"
            elif self.cap.flow_table[key][:2] == [3, "out"]:
                self.cap.flow_table[key][0] += 1
                self.cap.flow_table[key][1] = "in"
                print "UDP Packet from inside. Counter is 4 now"
                return "Mod"
            elif self.cap.flow_table[key][:2] == [4, "out"]:
                print "UDP flow is safe. Flow is deleted from flow table"
                del self.flow_table[key]
                return "Mod"
            elif self.cap.flow_table[key][2] < 10:
                self.cap.flow_table[key][2] += 1
                return "Pktout"
            elif self.cap.flow_table[key][2] >= 10:
                del self.cap.flow_table[key]
                print "DOS attack detected"
                self.cap.firewall_obj.drop_rule((str(self.parser_obj.pkt['srcip']), str(self.parser_obj.pkt['dstip']), int(self.parser_obj.pkt['dstport'])))
                print self.cap.firewall_obj.policy
                return False
        else:
            self.cap.flow_table[key] = [1, "in", 0]
            print "First UDP Packet from inside."
            return True

    def track_outside_network(self):
        """
        Checks and installs the flows for outside network traffic
        """
        if self.parser_obj.check_policy(self.parser_obj.pkt['srcip'], self.parser_obj.pkt['dstip'], self.parser_obj.pkt['dstport']) == True:
            print "Packet matched the role and dropped"
            return True
        key = (self.parser_obj.pkt['srcip'], self.parser_obj.pkt['dstip'], self.parser_obj.pkt['srcport'], self.parser_obj.pkt['dstport'])
        if key in self.cap.flow_table:
            if self.cap.flow_table[key][:2] == [1, "in"]:
                self.cap.flow_table[key][0] += 1
                self.cap.flow_table[key][1] = "out"
                print "UDP Packet from outside. Counter is 2 now"
                return "Pktout"
            elif self.cap.flow_table[key][:2] == [2, "in"]:
                self.cap.flow_table[key][0] += 1
                self.cap.flow_table[key][1] = "out"
                print "UDP Packet from outside. Counter is 3 now"
                return "Pktout"
            elif self.cap.flow_table[key][:2] == [3, "in"]:
                self.cap.flow_table[key][0] += 1
                self.cap.flow_table[key][1] = "out"
                print "UDP Packet from outside. Counter is 4 now"
                return "Mod"
            elif self.cap.flow_table[key][0] == [4, "in"]:
                del self.cap.flow_table[key]
                print "UDP flow is safe. Flow is deleted from flow table."
                return "Mod"
            elif self.cap.flow_table[key][2] < 10:
                self.cap.flow_table[key][2] += 1
                print "UDP packets that might belong to another type of applications or retransmission."
                return "Pktout"
            elif self.cap.flow_table[key][2] > 10:
                del self.cap.flow_table[key]
                print "DOS attack detected"
                self.cap.firewall_obj.drop_rule((str(self.parser_obj.pkt['srcip']), str(self.parser_obj.pkt['dstip']), int(self.parser_obj.pkt['dstport'])))
                return False
        else:
            if self.SYN:
                self.cap.flow_table[key] = [1, "out", 0]
                print "First UDP Packet from outside."
                return "Pktout"       

def main ():
    #   Initializes the Firewall 
    policy_obj = Firewall()
    #   Initializes the Packet parsing and filtering
    pkt_cap = PacketCapture(policy_obj)
    return (policy_obj >> pkt_cap.packet_capture()) + policy_obj >> flood()
