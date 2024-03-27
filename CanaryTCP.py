from scapy.all import *
import time
import os

class TCPHandler:
    def __init__(self, ports=[],interfaces=False):
        self.list_ports = ports
        self.all_interfaces = interfaces
        if self.all_interfaces:
            self.all_interfaces = input('Enter interface Name: ')
        self.filter = "tcp[tcpflags] & (tcp-syn) != 0"
        # Check if the rule already exists
        self.rule_exists = False
        self.check_rule_iptables()

    def check_rule_iptables(self):
        # Define the rule parameters
        rule = "-A OUTPUT -p tcp -m tcp --tcp-flags RST RST -j DROP"
        # Execute the iptables command to list the rules
        output = os.popen("iptables -S OUTPUT").read()
        # Check if the rule exists in the output
        if rule in output:
            self.rule_exists = True
        # If the rule doesn't exist, add it
        if not self.rule_exists:
            os.system("iptables " + rule)
            print("The rule has been added to the OUTPUT chain.")
        else:
            print("The rule already exists in the OUTPUT chain.")
    def handle_ack(self,ip,tcp):
        '''''
        After receiving the SYN-ACK segment, the client acknowledges the server's sequence number (ServerSeq + 1) by sending a TCP segment with the ACK flag set.
        The client also acknowledges the server's SYN flag by setting the ACK flag.
        Connection Established
        '''''
        # Connection established
        print("Connection from", ip.src, "established")

        # Build and send FIN to close connection
        ip3 = IP(src=ip.dst, dst=ip.src)
        tcp3 = TCP(sport=tcp.dport, dport=tcp.sport,flags="F", seq=tcp.seq + 1, ack=tcp.ack)
        send(ip3 / tcp3, verbose=0)
        time.sleep(1)
    def handle_syn(self, ip, tcp):
        '''''
        receiving the SYN segment, the server responds by sending a TCP segment with both the SYN and ACK (acknowledge) flags set.
        The server generates its own random sequence number (ServerSeq) and acknowledges the client's sequence number (ClientSeq + 1).
        The server also includes its own randomly generated sequence number (ServerSeq) to identify its data
        '''''
        ip2 = IP(src=ip.dst, dst=ip.src)
        tcp2 = TCP(sport=tcp.dport, dport=tcp.sport,flags="SA", seq=tcp.ack, ack=tcp.seq + 1)
        send(ip2 / tcp2, verbose=0)
        return

    def tcp_handler(self, pkt):
        '''''
        The client [hacker by scanner] initiates the connection by sending a TCP segment with the SYN (synchronize) flag set to the server.
        This segment contains a randomly generated sequence number (ClientSeq) to identify the client's data.
        Step 2: SYN-ACK (Synchronize-Acknowledge)
        '''''
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            ip = pkt[IP]
            tcp_flags = tcp.flags

            if tcp_flags == "S":
                print('Port found', ip.src, tcp.dport)
                #check the dst ports if is in the list
                if str(tcp.dport) in self.list_ports:
                    self.handle_syn(ip, tcp)

            elif tcp_flags == "A":
                self.handle_ack(ip, tcp)
        else:
            return
    def emulate_port(self):
        if self.all_interfaces:
            sniff(filter=self.filter, prn=self.tcp_handler, store=0)
        else:
            sniff(filter=self.filter, iface=self.all_interfaces, prn=self.tcp_handler, store=0)

if __name__ == "__main__":
    tcp = TCPHandler()
    #list of ports
    tcp.list_ports = ['443', '3389', '23', '21', '25', '5432', '3306', '8080', '8443', '1521', '1433', '5900', '111', '2049',
             '5631', '500', '4369', '5000', '5222', '5223', '161', '162', '123', '514', '623', '1645', '4190', '993',
             '110', '995', '143', '26', '389', '636', '631', '853', '554', '2000', '2049', '2301', '2376', '2377',
             '2379-2383', '5000', '5001', '24875']
    #if all interfaces ?
    tcp.all_interfaces = True
    #start the tcp emulator
    tcp.emulate_port()



