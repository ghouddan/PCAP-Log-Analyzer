import argparse
import os
import json
from colorama import Fore, init
from parser import parser_pcap
from detectors import (
    detect_brute_force_with_timing,
    detect_port_scanning,
    detect_data_exfiltration
)

init()

def main():
    parser = argparse.ArgumentParser(
        description="PCAP Analyzer: Detect brute-force, port scans, and data exfiltration from a PCAP file."
    )

    parser.add_argument("--file", "-f", type=str, required=True, help="Path to the PCAP file to analyze")
    parser.add_argument("--output", "-o", type=str, required=True, help="Path to the JSON file for saving results")

    parser.add_argument("--brute-threshold", type=int, default=10,required=False,  help="Max failed logins before brute-force alert (default: 10)")
    parser.add_argument("--window", "-w", type=int, default=5, required=False, help="Time window in seconds for brute-force detection (default: 5)")

    parser.add_argument("--scan-threshold", type=int, default=10,required=False, help="Ports accessed per IP before scan is flagged (default: 10)")
    parser.add_argument("--scan-window", type=int, default=10, required=False, help="Time window in seconds for port scan detection (default: 10)")

    parser.add_argument("--file-threshold", type=int,required=False, help="Transfer size in MB to trigger data exfiltration alert")
    parser.add_argument("--whitelisted_ips", type=str, nargs='*', default=[], help="List of IPs to ignore for data exfiltration detection")


    args = parser.parse_args()

    # Validate file
    if not os.path.isfile(args.file):
        print(Fore.RED + f" Error: PCAP file '{args.file}' not found.")
        return

    # Parse PCAP
    try:
        packets = parser_pcap(args.file)
    except Exception as e:
        print(Fore.RED + f" Failed to parse PCAP: {e}")
        return

    report = {}

    try:
        if args.brute_threshold:
            report["brute_force_alerts"] = detect_brute_force_with_timing(packets, args.brute_threshold)
        if args.scan_threshold:
         report["port_scan_alerts"] = detect_port_scanning(packets, args.scan_threshold, args.scan_window)
        if args.file_threshold:
            report["exfiltration_alerts"] = detect_data_exfiltration(packets, args.file_threshold)
    except Exception as e:
        print(Fore.RED + f" Detection failed: {e}")
        return
    # Save report
    try:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=4)
        print(Fore.GREEN + f" Analysis complete. Report saved to '{args.output}'.")
    except Exception as e:
        print(Fore.RED + f" Failed to save report: {e}")


if __name__ == "__main__":
    main()
