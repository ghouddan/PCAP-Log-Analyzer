from pyshark import FileCapture
from datetime import datetime
import json
from pprint import pprint

def parser_pcap(file_path):
    """
    Enhanced parser that preserves layer information and timestamps correctly.
    """
    capture = FileCapture(file_path)
    pcap_parsed = []
    
    for packet in capture:
        try:
            packet_info = {
                "src_ip": packet.ip.src if hasattr(packet, 'ip') else None,
                "dst_ip": packet.ip.dst if hasattr(packet, 'ip') else None,
                "protocol": packet.transport_layer if hasattr(packet, 'transport_layer') else None,
                "dest_port": int(packet.tcp.dstport) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'dstport') else None,
                "length": packet.length,
                "timestamp": packet.sniff_time,  # ✅ datetime object
                "timestamp_str": packet.sniff_time.isoformat(),  # For display/logging

                # Layer-specific fields
                "ssh_message_code": packet.ssh.message_code if hasattr(packet, 'ssh') and hasattr(packet.ssh, 'message_code') else None,
                "http_method": packet.http.request_method if hasattr(packet, 'http') and hasattr(packet.http, 'request_method') else None,
                "http_response_code": packet.http.response_code if hasattr(packet, 'http') and hasattr(packet.http, 'response_code') else None,
                "http_uri": packet.http.request_uri if hasattr(packet, 'http') and hasattr(packet.http, 'request_uri') else None,
                "ftp_response_code": packet.ftp.response_code if hasattr(packet, 'ftp') and hasattr(packet.ftp, 'response_code') else None,
                "layers": packet.layers
            }
            pcap_parsed.append(packet_info)

        except Exception as e:
            continue

    capture.close()
    return pcap_parsed




"""if __name__ == "__main__" :
    parsed_pcap = parser_pcap("/home/mo/Downloads/port_scan2.pcapng")
    pprint(parsed_pcap)"""
        #print(parsed_pcap)  # Display first 5 packets for verification

"""with open("result.json", 'w') as f :
    json.dump(parsed_pcap, f, indent=4)
    #print("PCAP file parsed and saved to result.json")"""