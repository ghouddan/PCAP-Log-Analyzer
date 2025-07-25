from parser import parser_pcap
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import List, Dict, Any
import json

def detect_brute_force_with_timing(
    packets: List[Dict[str, Any]], threshold: int = 10, time_window: int = 60
) -> List[Dict[str, Any]]:
    """
    Detect brute force attacks using parsed packets with timing analysis.

    Args:
        packets: List of parsed packet dictionaries.
        threshold: Max failed attempts allowed in time window.
        time_window: Time window in seconds.
    Returns:
        List of alerts for detected brute force attacks.
    """
    failed_attempts = defaultdict(list)

    for packet in packets:
        try:
            # Normalize port
            dest_port = int(packet.get('dest_port', 0))

            # SSH brute force
            is_failed_ssh_login = (
                dest_port == 22 #and packet.get('ssh_message_code') == '51'
            )

            # HTTP brute force
            is_failed_http_login = (
                packet.get('http_method') == 'POST'
                and packet.get('http_response_code') == '401'
                and 'login' in (packet.get('http_uri') or '')
            )

            # FTP brute force
            is_failed_ftp_login = (
                dest_port == 21 and packet.get('ftp_response_code') == '530'
            )

            if is_failed_ssh_login or is_failed_http_login or is_failed_ftp_login:
                ip = packet.get('src_ip')
                timestamp = packet.get('timestamp')  # datetime object

                if ip and isinstance(timestamp, datetime):
                    failed_attempts[ip].append({
                        'timestamp': timestamp,
                        'type': 'ssh' if is_failed_ssh_login else 'http' if is_failed_http_login else 'ftp',
                        'dest_port': dest_port
                    })

        except (KeyError, ValueError, TypeError):
            continue  # Skip malformed packet

    alerts = []

    for ip, attempts in failed_attempts.items():
        if len(attempts) < 2:
            continue

        attempts.sort(key=lambda x: x['timestamp'])
        time_diffs = [
            (attempts[i]['timestamp'] - attempts[i - 1]['timestamp']).total_seconds()
            for i in range(1, len(attempts))
        ]

        # Sliding window using deque for better performance
        suspicious_windows = []
        window = deque()

        for attempt in attempts:
            current_time = attempt['timestamp']
            window.append(attempt)

            # Remove old attempts outside the window
            while (current_time - window[0]['timestamp']).total_seconds() > time_window:
                window.popleft()

            if len(window) >= threshold:
                window_time_diffs = [
                    (window[i]['timestamp'] - window[i - 1]['timestamp']).total_seconds()
                    for i in range(1, len(window))
                ]
                suspicious_windows.append({
                    'window_start': window[0]['timestamp'].isoformat(),
                    'window_end': window[-1]['timestamp'].isoformat(),
                    'attempts_count': len(window),
                    'avg_interval': round(sum(window_time_diffs) / len(window_time_diffs), 2) if window_time_diffs else 0,
                    'min_interval': round(min(window_time_diffs), 2) if window_time_diffs else 0,
                    'max_interval': round(max(window_time_diffs), 2) if window_time_diffs else 0
                })

        if suspicious_windows or len(attempts) >= threshold:
            total_duration = (attempts[-1]['timestamp'] - attempts[0]['timestamp']).total_seconds()
            alert = {
                'ip': ip,
                'total_attempts': len(attempts),
                'total_duration_seconds': round(total_duration, 2),
                'avg_time_between_attempts': round(sum(time_diffs) / len(time_diffs), 2) if time_diffs else 0,
                'min_time_between_attempts': round(min(time_diffs), 2) if time_diffs else 0,
                'max_time_between_attempts': round(max(time_diffs), 2) if time_diffs else 0,
                'suspicious_windows': len(suspicious_windows),
                'first_attempt': attempts[0]['timestamp'].isoformat(),
                'last_attempt': attempts[-1]['timestamp'].isoformat(),
                'attack_types': list({a['type'] for a in attempts}),
                'target_ports': list({a['dest_port'] for a in attempts}),
                'message': "Potential brute force attack detected",
                'severity': calculate_severity(len(attempts), total_duration, time_diffs),
                #'windows_details': suspicious_windows
            }
            alerts.append(alert)

    return alerts


def calculate_severity(attempt_count: int, duration: float, time_diffs: List[float]) -> str:
    """
    Calculate severity based on attempt patterns.
    """
    if not time_diffs:
        return "LOW"

    avg_interval = sum(time_diffs) / len(time_diffs)

    if attempt_count >= 50 and avg_interval < 5:
        return "HIGH"
    elif attempt_count >= 20 and avg_interval < 10:
        return "MEDIUM"
    elif attempt_count >= 10 and avg_interval < 30:
        return "MEDIUM"
    else:
        return "LOW"


def detect_rapid_attempts(packets: List[Dict[str, Any]], max_interval: int = 10) -> List[Dict[str, Any]]:
    """
    Simple detection of rapid successive authentication attempts.
    """
    attempts_by_ip = defaultdict(list)

    for packet in packets:
        try:
            dest_port = int(packet.get('dest_port', 0))

            is_auth_related = (
                dest_port in [22, 21, 80, 443, 3389]
                or packet.get('http_method') == 'POST'
                or packet.get('ssh_message_code') is not None
                or packet.get('ftp_response_code') is not None
            )

            if is_auth_related and packet.get('src_ip') and isinstance(packet.get('timestamp'), datetime):
                attempts_by_ip[packet['src_ip']].append(packet['timestamp'])

        except (KeyError, ValueError, TypeError):
            continue

    rapid_attempts = []

    for ip, timestamps in attempts_by_ip.items():
        if len(timestamps) < 2:
            continue

        timestamps.sort()

        for i in range(1, len(timestamps)):
            time_diff = (timestamps[i] - timestamps[i - 1]).total_seconds()
            if time_diff <= max_interval:
                rapid_attempts.append({
                    'ip': ip,
                    'time_between_attempts': round(time_diff, 2),
                    'timestamp1': timestamps[i - 1].isoformat(),
                    'timestamp2': timestamps[i].isoformat(),
                    'message': f"Rapid attempts detected - {time_diff:.2f} seconds apart"
                })

    return rapid_attempts

def detect_port_scanning(packets: List[Dict[str, Any]], threshold: int = 10, window_minutes: int = 1) -> List[Dict[str, Any]]:
    """
    Detect vertical and horizontal port scanning within a specified time window.
    Args:
        packets: List of parsed packet dictionaries.
        threshold: Minimum number of unique ports or destination IPs to trigger an alert.
        window_minutes: Time window in minutes to consider for scanning detection.
    Returns:
        List of alerts for detected port scanning activities.
        """

    port_scans = defaultdict(set)          
    horizontal_scans = defaultdict(set)    
    timestamps = defaultdict(list)         

    now = datetime.now()
    window = timedelta(minutes=window_minutes)

    for packet in packets:
        try:
            src_ip = packet.get('src_ip')
            dest_ip = packet.get('dst_ip')
            dest_port = int(packet.get('dest_port', 0))
            ts_raw = packet.get('timestamp')
            #print(f"{src_ip} → {dest_ip}:{dest_port} @ {ts_raw}")


            if not (src_ip and dest_ip and dest_port and ts_raw):
                continue

            # Parse timestamp to datetime object
            timestamp = datetime.fromisoformat(ts_raw) if isinstance(ts_raw, str) else ts_raw

            # Apply time window filter
            if now - timestamp > window:
              continue

            # Populate scan tracking structures
            port_scans[src_ip].add(dest_port)
            horizontal_scans[(src_ip, dest_port)].add(dest_ip)
            timestamps[src_ip].append(timestamp)

        except (ValueError, TypeError, KeyError):
            continue

    alerts = {}

    # Detect horizontal scans
    for (ip, port), dest_ips in horizontal_scans.items():
        if len(dest_ips) >= threshold:
            if ip not in alerts:
                alerts[ip] = {
                    'ip': ip,
                    'horizontal_ports': set(),
                    'vertical_ports': set(),
                    'message': "Potential port scanning detected",
                    'severity': "HIGH" if len(dest_ips) > 50 else "MEDIUM",
                    'type': [],
                    'first_seen': min(timestamps[ip]).isoformat() if timestamps[ip] else None,
                    'last_seen': max(timestamps[ip]).isoformat() if timestamps[ip] else None
                }
            alerts[ip]['horizontal_ports'].add(port)
            if 'horizontal' not in alerts[ip]['type']:
                alerts[ip]['type'].append('horizontal')

    # Detect vertical scans
    for ip, ports in port_scans.items():
        if len(ports) >= threshold:
            if ip not in alerts:
                alerts[ip] = {
                    'ip': ip,
                    'horizontal_ports': set(),
                    'vertical_ports': set(),
                    'message': "Potential port scanning detected",
                    'severity': "HIGH" if len(ports) > 50 else "MEDIUM",
                    'type': [],
                    'first_seen': min(timestamps[ip]).isoformat() if timestamps[ip] else None,
                    'last_seen': max(timestamps[ip]).isoformat() if timestamps[ip] else None
                }
            alerts[ip]['vertical_ports'] = alerts[ip]['vertical_ports'].union(ports)
            if 'vertical' not in alerts[ip]['type']:
                alerts[ip]['type'].append('vertical')

    # Final formatting
    final_alerts = []
    for alert in alerts.values():
        alert['vertical_ports'] = list(alert['vertical_ports'])
        alert['horizontal_ports'] = list(alert['horizontal_ports'])
        final_alerts.append(alert)

    return final_alerts


def detect_data_exfiltration(packets: List[Dict[str, Any]], threshold: int = 1000000, whitelisted_ips=None) -> List[Dict[str, Any]]:
    """
    Detect potential data exfiltration based on packet sizes from internal to external IPs.
    Args:
        packets: List of parsed packet dictionaries.
        threshold: Size threshold in bytes to trigger an alert.
    Returns:
        List of alerts for detected data exfiltration activities.
    """
    if whitelisted_ips is None:
        whitelisted_ips = set()

    def is_internal(ip):
        return ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.")

    exfiltration_alerts = defaultdict(lambda: {'size': 0, 'packets': []})

    for packet in packets:
        src_ip = packet.get('src_ip')
        dst_ip = packet.get('dst_ip')
        size = int(packet.get('size', 0))
        timestamp = packet.get('timestamp')  # Optional enhancement

        if not src_ip or not dst_ip or size <= 0:
            continue

        if dst_ip in whitelisted_ips:
            continue

        if is_internal(src_ip) and not is_internal(dst_ip):
            key = (src_ip, dst_ip)
            exfiltration_alerts[key]['size'] += size
            exfiltration_alerts[key]['packets'].append(packet)

    alerts = []
    for (src_ip, dst_ip), data in exfiltration_alerts.items():
        if data['size'] >= threshold:
            alerts.append({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'total_size': data['size'],
                'packet_count': len(data['packets']),
                'message': f"Potential data exfiltration: {data['size'] / 1024 / 1024:.2f} MB sent from {src_ip} to {dst_ip}",
                'severity': "HIGH" if data['size'] > 10_000_000 else "MEDIUM"
            })

    return alerts




if __name__ == "__main__":
    test_packets = [
    {"src_ip": "192.168.1.10", "dst_ip": "8.8.8.8", "size": 500000},
    {"src_ip": "192.168.1.10", "dst_ip": "8.8.8.8", "size": 600000},  # total = 1.1MB
    {"src_ip": "192.168.1.15", "dst_ip": "8.8.4.4", "size": 10000},
        ]
    alerts = detect_data_exfiltration(test_packets, 100000)
    # Print results
    for alert in alerts:
        print(alert)

   
""" parsed_pcap = parser("/home/mo/Downloads/port_scan3.pcapng")
    print(f"Parsed {len(parsed_pcap)} packets")

    alerts = detect_port_scanning(parsed_pcap,5,5)
    print(alerts)"""

""" with open ("result.json", 'w') as f:
        json.dump(alerts, f, indent=4)
    print("Alerts saved to result.json")"""

"""   if alerts:
        print("Brute force attack alerts:")
        for alert in alerts:
            print(alert)
    else:
        print("No brute force attacks detected.")
"""