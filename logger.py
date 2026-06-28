import os
from datetime import datetime

class Logger:
    def __init__(self):
        self.log_dir= "logs"
        self.log_file= None
        self._create_log_file()
    
    def _create_log_file(self):
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        filename= "session_" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".log"
        self.log_file= os.path.join(self.log_dir, filename)

    def log_packet(self, info):
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write("="*60 + "\n")
            f.write("[{}]\n".format(info["time"]))
            f.write("MAC: {} --> {}\n".format(info["mac_src"], info["mac_dst"]))
            f.write("IP: {} --> {}\n".format(info["ip_src"], info["ip_dst"]))
            f.write("Protocol: {} | TTL: {}\n".format(info["protocol"], info["ttl"]))
            if info["protocol"] == "TCP":
                f.write("Ports: {} --> {}\n".format(info["port_src"], info["port_dst"]))
                f.write("Service: {}\n".format(info["service"]))
                f.write("Flags: {}\n".format(info["flags"]))
            elif info["protocol"] == "UDP":
                f.write("Ports: {} --> {}\n".format(info["port_src"], info["port_dst"]))
                f.write("Service: {}\n".format(info["service"]))
            elif info["protocol"] == "ICMP":
                f.write("Service: {}\n".format(info["service"]))
            if info["dns_query"]:
                f.write("DNS Query: {}\n".format(info["dns_query"]))
            if info["payload"]:
                f.write("Payload (first 50 bytes): {}\n".format(info["payload"]))
            f.write("="*60 + "\n\n")

    def get_log_file(self):
        return self.log_file
