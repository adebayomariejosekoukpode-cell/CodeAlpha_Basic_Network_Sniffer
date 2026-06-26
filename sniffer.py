from scapy.all import sniff, get_if_list
import threading
from analyzer import analyze_packet
from logger import Logger

class Sniffer:
    def __init__(self, interface, callback, logging_enabled=False):
        self.interface = interface
        self.callback = callback
        self.logging_enabled = logging_enabled
        self.running = False
        self.thread = None
        self.logger = Logger() if logging_enabled else None

    def _process_packet(self, packet):
        info=analyze_packet(packet)
        self.callback(info)
        if self.logging_enabled and self.logger:
            self.logger.log_packet(info)
    
    def start(self):
        if not self.running:
            self.running=True
            self.thread= threading.Thread(
                target=self._capture,
                daemon=True
            )
            self.thread.start()

    def _capture(self):
        sniff(
            iface=self.interface,
            prn=self._process_packet,
            store=False,
            stop_filter=lambda p: not self.running
        )
    
    def stop(self):
        if self.running:
            self.running = False
            if self.thread:
                self.thread.join(timeout=2)

def get_interfaces():
    return get_if_list()