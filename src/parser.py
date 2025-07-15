from pyshark import FileCapture
import json



def parser(file_path):
    """"
    take a file path that point to a pcap file and parse it to extract the
    information of the packets in the file.
    Args:
        file_path (str): The path to the pcap file to be parsed.
    """
    # Create a FileCapture object to read the pcap file
    capture = FileCapture(file_path)
    pcap_parsed = []
    for packet in capture:
        packet_info= { 
            "src_ip" : packet['ip'].src,
            "dst_ip" :packet['ip'].dst,
            "protocol" : packet.transport_layer if hasattr(packet, 'transport_layer') else None,
            "dest_port" : packet['tcp'].dstport if 'tcp' in packet else None,
            "length" :packet.length, 
            "timestamp" : packet.sniff_time.isoformat(),
            "info" : packet.info if hasattr(packet, 'info') else None
        }
        pcap_parsed.append(packet_info)
    return pcap_parsed
    



if __name__ == "__main__" :
    parsed_pcap = parser("/home/mo/Desktop/PCAP-log-analyzer/samples/200722_win_scale_examples_anon.pcapng")
with open("result.json", 'w') as f :
    json.dump(parsed_pcap, f, indent=4)
    print("PCAP file parsed and saved to result.json")
