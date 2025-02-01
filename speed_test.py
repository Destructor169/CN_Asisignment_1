import time
from scapy.all import sniff

interface = "bridge100"
capture_limit = 805996

class LivePacketCounter:
    def __init__(self):
        self.packet_count = 0
        self.start_time = None
        self.total_bytes = 0
        self.peak_pps = 0
        self.peak_mbps = 0

    def packet_handler(self, pkt):
        if self.start_time is None:
            self.start_time = time.time()

        self.packet_count += 1
        
        # Calculate packet size in bytes
        packet_length = len(pkt)
        self.total_bytes += packet_length
        
        # Calculate current metrics
        duration = time.time() - self.start_time
        pps = self.packet_count / duration
        mbps = (self.total_bytes * 8 / (1024 * 1024)) / duration
        
        # Track peak values
        self.peak_pps = max(self.peak_pps, pps)
        self.peak_mbps = max(self.peak_mbps, mbps)

        # Print live packet count, PPS, and Mbps
        print(f"\rCaptured Packets: {self.packet_count} | PPS: {pps:.2f} | Mbps: {mbps:.2f}", end='', flush=True)

        # Stop sniffing when capture limit is reached
        if self.packet_count >= capture_limit:
            print("\nCapture complete.")
            sniffing_process.stop()

    def print_stats(self):
        if self.start_time:
            total_duration = time.time() - self.start_time
            print(f"\n\nCapture Statistics:")
            print(f"Total Packets: {self.packet_count}")
            print(f"Peak PPS: {self.peak_pps:.2f}")
            print(f"Peak Mbps: {self.peak_mbps:.2f}")
            print(f"Duration: {total_duration:.2f} seconds")

# Create an instance of LivePacketCounter
live_counter = LivePacketCounter()

print(f"Starting capture on {interface}... (Only `tcpreplay` packets will be captured)")
sniffing_process = sniff(iface=interface, prn=live_counter.packet_handler, store=False)

# After capture, print total packets and time taken, along with peak statistics
live_counter.print_stats()