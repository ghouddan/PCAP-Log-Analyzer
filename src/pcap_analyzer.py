import argparse
from parser import parsed_pcap
def main():

    parser = argparse.ArgumentParser(description="Parse PCAP file from the input and scan it for relevant information that can be used for further analysis")
    parser.add_argument("--f" , type=str , help="Path to the PCAP file to analyse")
    parser.add_argument("--output", type=str, help="path to the direction where the result will be saved")
    parser.add_argument("--brute_threshold", type=int, help="threshold for the brute force attempt", default=10)
    parser.add_argument("--scan_threshold", type=int, help="threshold for the scan attempt 'Port count per IP to trigger scan alert '", default=10)
    parser.add_argument("--file-threshold", type=int, help="Transfer size (in MB) to flag large download/upload")
    args = parser.parse_args()

    packet_list = parsed_pcap(args.f)
    report= {}
    
    