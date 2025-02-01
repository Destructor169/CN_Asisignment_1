import scapy.all as scapy
import re

TARGET_IP = "192.168.10.50"
SUCCESS_PASSWORD = "securepassword"

def process_packet(packet, login_attempts, successful_credentials, total_content_length):
    # Check if the packet has IP and TCP layers
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
        ip_header = packet[scapy.IP]
        tcp_header = packet[scapy.TCP]

        # Ensure the packet is from the target IP
        if ip_header.src == TARGET_IP:
            # Check for HTTP POST request (simplified)
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load.decode(errors='ignore')

                # Check if the payload contains HTTP POST
                if "POST" in payload:
                    # Increment the login attempt count
                    login_attempts[0] += 1

                    # Add the content length of the payload (this is the length of the POST data)
                    total_content_length[0] += len(payload)

                    # Check for successful password
                    if SUCCESS_PASSWORD in payload:
                        print("Found successful login attempt!")

                        # Extract username and password (assuming the format: username=xxx&password=yyy)
                        username_match = re.search(r'username=([^&]+)', payload)
                        password_match = re.search(r'password=([^&]+)', payload)

                        if username_match and password_match:
                            username = username_match.group(1)
                            password = password_match.group(1)

                            # Output the credentials for the successful login attempt
                            successful_credentials[0] = (username, password)

                        # Extract the client's source port (TCP source port)
                        source_port = tcp_header.sport
                        print(f"Q3. Client's source port: {source_port}")

                        # Stop further processing once successful login is found
                        return

def capture_packets(pcap_file):
    login_attempts = [0]  # Use a list to modify the count in process_packet
    successful_credentials = [None]  # To store successful credentials (username, password)
    total_content_length = [0]  # To store total content length of payloads
    packets = scapy.rdpcap(pcap_file)

    for packet in packets:
        process_packet(packet, login_attempts, successful_credentials, total_content_length)

    return login_attempts[0], successful_credentials[0], total_content_length[0]

if __name__ == "__main__":
    pcap_file = "3.pcap"  # Path to your pcap file

    # Capture packets and extract information
    login_attempts, successful_credentials, total_content_length = capture_packets(pcap_file)

    # Print the answers to the questions
    print(f"Q1. Number of login attempts: {login_attempts}")

    # Check if successful credentials were found
    if successful_credentials:
        username, password = successful_credentials
        print("Q2. Successful login credentials:")
        print(f"Username: {username}")
        print(f"Password: {password}")
    else:
        print("Q2. No successful login found.")

    print(f"Q4. Total content length of all login attempt payloads: {total_content_length} bytes")
