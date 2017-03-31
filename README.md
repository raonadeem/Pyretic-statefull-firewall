# Pyretic-statefull-firewall
Pyretic statefull firewall and DDoS prevention

Pyretic is both a programmer-friendly domain-specific language embedded in Python and 
the runtime system that implements programs written in the Pyretic language on network 
switches.
This project is an implementation of stateless and statefull firewall using pyretic and 
POX controller. Firewall also incorporate to detect and prevent the DDoS attack.

Installation Steps:

1) Download the VM from the following link;
   http://sdnhub.org/tutorials/sdn-tutorial-vm/
2) Run the commad to install yappi package and some dependancies
   sudo pip install networkx bitarray netaddr ipaddr pytest ipdb sphinx pyparsing==1.5.7 yappi
3) Start the SDNtutorialVM64bit.ova in virtualbox.

Test Setup:

1) Clone the following git repository in VM.
   git clone https://github.com/raonadeem/Pyretic-statefull-firewall.git
2) Copy firewall-policies.csv in pyretic home and statefull_firewall.py in pyretic examples
   cp firewall-policies.csv /home/ubuntu/pyretic
   cp statefull_firewall.py /home/ubuntu/pyretic/pyretic/examples

Test Execution:

1) Clear the setup before every run.
   sudo mn -c
2) Run the following command to setup 3 hosts (h1, h2, h3) on single switch (s1) and a remote controller.
   sudo mn  --topo single,3 --controller remote
3) Open xterm for h1, h2, h3.
   xterm h1
   xterm h2
   xterm h3
4) (Optional) In your terminal second window run the sFlow for monitoring.
   sudo ovs-vsctl -- --id=@sflow create sflow agent=eth0  target=\"127.0.0.1:6343\" sampling=10 polling=20 -- -- set bridge s1 sflow=@sflow
   cd sflow-rt
   ./start.sh
   Open http://localhost:8008 in your VM browser for sFlow monitoring
5) In third window run our statefull firewall application on POX controller.
   python pyretic.py pyretic.examples.statefull_firewall
6) Run the hping3 tests on h1 host.
   sudo hping3 -V -S -s 6001 -p 5001 10.0.0.3 -c 1
