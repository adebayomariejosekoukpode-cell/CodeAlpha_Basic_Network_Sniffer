from scapy.all import IP, TCP, UDP, ICMP, DNS, Raw, Ether
from datetime import datetime

PROTOCOLS = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
}

PORTS_SERVICES = {
    80: 'HTTP',
    443: 'HTTPS',
    53: 'DNS',
    25: 'SMTP',
    110: 'POP3',
    143: 'IMAP',
    22: 'SSH',
    21: 'FTP',
    23: 'Telnet',
    3306: 'MySQL',
    5432: 'PostgreSQL',
}

def analyze_packet(packet):
    info= {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "mac_src": None,
        "mac_dst": None,
        "ip_src": None,
        "ip_dst": None,
        "protocol": None,
        "port_src": None,
        "port_dst": None,
        "service": None,
        "ttl": None,   
        "payload": None,
        "dns_query": None,
        "flags": None,
    }
    if packet.hasmlayer(Ether):
        info["mac_src"]= packet[Ether].src
        info["mac_dst"]= packet[Ether].dst
        
    if packet.haslayer(IP):
        info["ip_src"]= packet[IP].src
        info["ip_dst"]= packet[IP].dst
        info["ttl"]= packet[IP].ttl
        info["protocol"]= PROTOCOLS.get(packet[IP].proto, str(packet[IP].proto))
    
    if packet.haslayer(TCP):
        info["port_src"]= packet[TCP].sport
        info["port_dst"]= packet[TCP].dport
        info["flags"]= packet[TCP].flags
        info["service"]= PORTS_SERVICES.get(packet[TCP].dport, PORTS_SERVICES.get(packet[TCP].sport, 'Inconnu'))
    
    if packet.haslayer(UDP):
        info["port_src"]= packet[UDP].sport
        info["port_dst"]= packet[UDP].dport
        info["service"]= PORTS_SERVICES.get(packet[UDP].dport, PORTS_SERVICES.get(packet[UDP].sport, 'Inconnu'))

    if packet.haslayer(ICMP):
        info["service"]= "ICMP Type" + str(packet[ICMP].type) + " Code " + str(packet[ICMP].code)
        info["protocol"]= "ICMP"
    
    if packet.haslayer(DNS):
        if packet[DNS].qd:
            info["dns_query"]= packet[DNS].qd.qname.decode('utf-8')
            info["service"]= "DNS"
    
    if packet.haslayer(Raw):
        info["payload"]= str(packet[Raw].load[:50])

