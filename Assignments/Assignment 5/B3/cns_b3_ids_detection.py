# B3 - Signature-Based and Anomaly-Based IDS
from collections import defaultdict

SIGNATURES = [
    {"id": "SIG-HTTP", "protocol": "TCP", "ports": [80, 8080], "direction": "IN", "pattern": "WEB_MALWARE"},
    {"id": "SIG-DNS", "protocol": "UDP", "ports": [53], "direction": "OUT", "pattern": "DNS_TUNNEL"},
    {"id": "SIG-SMB", "protocol": "TCP", "ports": [445], "direction": "IN", "pattern": "SMB_EXPLOIT"},
    {"id": "SIG-TCP", "protocol": "TCP", "ports": ["*"], "direction": "*", "pattern": "SUSPICIOUS_TCP"},
    {"id": "SIG-EICAR", "protocol": "*", "ports": ["*"], "direction": "*", "pattern": "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"},
]

def signature_inspect(packet, signatures=SIGNATURES):
    alerts = []
    payload_checks = 0
    rejected_protocol_port = 0
    rejected_direction = 0
    for sig in signatures:
        # Stage 1: protocol/port filter
        if sig["protocol"] != "*" and packet["protocol"] != sig["protocol"]:
            rejected_protocol_port += 1
            continue
        if "*" not in sig["ports"] and packet["dst_port"] not in sig["ports"]:
            rejected_protocol_port += 1
            continue
        # Stage 2: direction filter
        if sig["direction"] != "*" and packet["direction"] != sig["direction"]:
            rejected_direction += 1
            continue
        # Stage 3: payload match
        payload_checks += 1
        if sig["pattern"] in packet["payload"]:
            alerts.append(sig["id"])
    return alerts, payload_checks, rejected_protocol_port, rejected_direction

class ScanDetector:
    def __init__(self, threshold=5, window=10):
        self.threshold = threshold
        self.window = window
        self.records = defaultdict(lambda: {"window_start": None, "destinations": set()})
        self.alerts = []

    def inspect(self, packet):
        src, dst, now = packet["src"], packet["dst"], packet["time"]
        record = self.records[src]
        if record["window_start"] is None or now - record["window_start"] >= self.window:
            record["window_start"] = now
            record["destinations"].clear()
        record["destinations"].add(dst)
        count = len(record["destinations"])
        if count > self.threshold:
            message = f"SCAN ALERT: {src} contacted {count} distinct destinations"
            if message not in self.alerts:
                self.alerts.append(message)
                print(message, "-> LOG AND BLOCK")
            return "ALERT"
        return "NORMAL"

def run():
    print("B3 - SIGNATURE DETECTOR")
    traces = [
        {"name": "Normal HTTP", "protocol": "TCP", "dst_port": 80,
         "direction": "IN", "payload": "GET /index.html"},
        {"name": "Harmless marker", "protocol": "TCP", "dst_port": 80,
         "direction": "IN", "payload": "WEB_MALWARE demo marker"},
        {"name": "EICAR test string", "protocol": "TCP", "dst_port": 8080,
         "direction": "IN", "payload": "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"},
        {"name": "DNS normal", "protocol": "UDP", "dst_port": 53,
         "direction": "OUT", "payload": "example.com"},
    ]
    total_payload_checks = 0
    for p in traces:
        alerts, checks, reject_pp, reject_dir = signature_inspect(p)
        total_payload_checks += checks
        print(f'{p["name"]}: alerts={alerts or "None"}, payload_checks={checks}, '
              f'protocol/port_rejects={reject_pp}, direction_rejects={reject_dir}')
    print("Total payload inspections:", total_payload_checks)

    print("\nB3 - ANOMALY SCAN DETECTOR")
    detector = ScanDetector(threshold=5, window=10)
    scan_trace = [{"src": "192.168.1.20", "dst": f"10.0.0.{i}", "time": i}
                  for i in range(1, 9)]
    for p in scan_trace:
        decision = detector.inspect(p)
        print(f'{p["src"]} -> {p["dst"]} at t={p["time"]}: {decision}')

    print("\nB3 - EVASION TEST: SPLIT MARKER")
    part1 = {"protocol": "TCP", "dst_port": 80, "direction": "IN", "payload": "WEB_MAL"}
    part2 = {"protocol": "TCP", "dst_port": 80, "direction": "IN", "payload": "WARE"}
    for index, p in enumerate([part1, part2], start=1):
        alerts, checks, _, _ = signature_inspect(p)
        print(f"Fragment {index}: payload={p['payload']}, alerts={alerts or 'None'}")
    print("Result: marker split across packets is missed without stream reassembly.")

    print("\nB3 - SCALABILITY TEST")
    volume = 500
    payload_inspections = 0
    for i in range(volume):
        p = {"protocol": "TCP", "dst_port": 80 if i % 2 == 0 else 22,
             "direction": "IN", "payload": "ordinary traffic"}
        _, checks, _, _ = signature_inspect(p)
        payload_inspections += checks
    print("Packets processed:", volume)
    print("Signatures configured:", len(SIGNATURES))
    print("Payload inspections:", payload_inspections)

if __name__ == "__main__":
    run()
