from parser import parser
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
                'windows_details': suspicious_windows
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

def detect_port_scanning(packets: List[Dict[str, Any]], threshold: int = 10) -> List[Dict[str, Any]]:
    """
    Detect port scanning based on the number of unique ports accessed by an IP.
    """
    port_scans = defaultdict(set)
    horizontal_scans = defaultdict(set)

    for packet in packets:
        try:
            src_ip = packet.get('src_ip')
            dest_port = int(packet.get('dest_port', 0))
            dest_ip = packet.get('dest_ip')

            if src_ip and dest_port and dest_ip:
                port_scans[src_ip].add(dest_port)
                horizontal_scans[(src_ip, dest_port)].add(dest_ip)

        except (KeyError, ValueError, TypeError):
            continue

    alerts = []

    for (ip, port), dest_ips in horizontal_scans.items():
        if len(dest_ips) >= threshold:
            alert = {
                'ip': ip,
                'port': port,
                'unique_destinations': len(dest_ips),
                'message': "Potential horizontal port scanning detected",
                'severity': "HIGH" if len(dest_ips) > 50 else "MEDIUM"
            }
            alerts.append(alert)

    for ip, ports in port_scans.items():
        if len(ports) >= threshold:
            alert = {
                'ip': ip,
                'unique_ports': len(ports),
                'message': "Potential port scanning detected",
                'severity': "HIGH" if len(ports) > 50 else "MEDIUM"
            }
            alerts.append(alert)

    return alerts



if __name__ == "__main__":
    parsed_pcap = parser("/home/mo/Downloads/second_capture.pcapng")
    alerts = detect_brute_force_with_timing(parsed_pcap, threshold=10, time_window=60)
    with open ("result.json", 'w') as f:
        json.dump(alerts, f, indent=4)
    print("Alerts saved to result.json")

"""   if alerts:
        print("Brute force attack alerts:")
        for alert in alerts:
            print(alert)
    else:
        print("No brute force attacks detected.")
"""