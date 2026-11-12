# B1 - Stateful Firewall Implementation and Instrumentation
from collections import Counter
from copy import deepcopy

RULES = [
    {"id": "R1", "src": "*", "dst": "10.0.0.0/24", "protocol": "TCP", "port": 23, "direction": "IN", "action": "DENY"},
    {"id": "R2", "src": "10.0.0.0/24", "dst": "*", "protocol": "TCP", "port": 80, "direction": "OUT", "action": "ALLOW"},
    {"id": "R3", "src": "10.0.0.0/24", "dst": "*", "protocol": "TCP", "port": 443, "direction": "OUT", "action": "ALLOW"},
    {"id": "R4", "src": "10.0.0.0/24", "dst": "*", "protocol": "UDP", "port": 53, "direction": "OUT", "action": "ALLOW"},
    {"id": "R5", "src": "*", "dst": "10.0.0.0/24", "protocol": "*", "port": "*", "direction": "IN", "action": "DENY"},
]
DEFAULT_ACTION = "DROP"
STATE_TIMEOUT = 30
TABLE_LIMIT = 50

def ip_match(pattern, address):
    if pattern == "*":
        return True
    if "/" in pattern:
        import ipaddress
        return ipaddress.ip_address(address) in ipaddress.ip_network(pattern)
    return pattern == address

def reverse_tuple(packet):
    return (packet["dst_ip"], packet["src_ip"],
            packet["dst_port"], packet["src_port"], packet["protocol"])

def forward_tuple(packet):
    return (packet["src_ip"], packet["dst_ip"],
            packet["src_port"], packet["dst_port"], packet["protocol"])

def rule_matches(rule, packet):
    return (
        rule["direction"] == packet["direction"]
        and ip_match(rule["src"], packet["src_ip"])
        and ip_match(rule["dst"], packet["dst_ip"])
        and (rule["protocol"] == "*" or rule["protocol"] == packet["protocol"])
        and (rule["port"] == "*" or rule["port"] == packet["dst_port"])
    )

class Firewall:
    def __init__(self, rules, table_limit=TABLE_LIMIT):
        self.rules = deepcopy(rules)
        self.table_limit = table_limit
        self.connections = {}
        self.packet_count = 0
        self.allow_count = 0
        self.drop_count = 0
        self.total_rule_checks = 0
        self.entries_created = 0
        self.entries_expired = 0
        self.table_history = []

    def expire_entries(self, now):
        expired = [key for key, value in self.connections.items()
                   if now - value["last_seen"] > STATE_TIMEOUT]
        for key in expired:
            del self.connections[key]
            self.entries_expired += 1
        return len(expired)

    def process(self, packet):
        self.packet_count += 1
        now = packet["time"]
        expired_now = self.expire_entries(now)
        state_key = reverse_tuple(packet) if packet["direction"] == "IN" else forward_tuple(packet)

        if packet["direction"] == "IN" and state_key in self.connections:
            self.connections[state_key]["last_seen"] = now
            decision, matched, checks, reason = "ALLOW", "STATE", 0, "Returning traffic"
        else:
            decision, matched, checks, reason = DEFAULT_ACTION, "DEFAULT", 0, "No rule matched"
            for rule in self.rules:
                checks += 1
                if rule_matches(rule, packet):
                    decision = "ALLOW" if rule["action"] == "ALLOW" else "DROP"
                    matched = rule["id"]
                    reason = "First matching rule"
                    break
            self.total_rule_checks += checks

            if decision == "ALLOW" and packet["direction"] == "OUT" and packet["protocol"] == "TCP":
                key = forward_tuple(packet)
                if key in self.connections:
                    self.connections[key]["last_seen"] = now
                elif len(self.connections) < self.table_limit:
                    self.connections[key] = {"created": now, "last_seen": now}
                    self.entries_created += 1
                else:
                    decision, matched, reason = "DROP", "TABLE_LIMIT", "Connection table full (fail-closed)"
        if decision == "ALLOW":
            self.allow_count += 1
        else:
            self.drop_count += 1

        self.table_history.append(len(self.connections))
        print(f'{self.packet_count:03d} | {packet["label"]:<18} | checks={checks} | '
              f'match={matched:<11} | {decision:<5} | table={len(self.connections)} '
              f'| expired={expired_now}')
        return decision

    def summary(self):
        print("\nFIREWALL SUMMARY")
        print("Packets processed:", self.packet_count)
        print("Rules evaluated:", self.total_rule_checks)
        print("ALLOW decisions:", self.allow_count)
        print("DROP decisions:", self.drop_count)
        print("Entries created:", self.entries_created)
        print("Entries expired:", self.entries_expired)
        print("Final connection-table size:", len(self.connections))
        print("Connection-table sizes:", self.table_history)

def packet(label, direction, src, dst, sport, dport, protocol="TCP", time=0):
    return {"label": label, "direction": direction, "src_ip": src, "dst_ip": dst,
            "src_port": sport, "dst_port": dport, "protocol": protocol, "time": time}

def run_validation():
    print("B1 - FIREWALL VALIDATION")
    fw = Firewall(RULES)
    tests = [
        packet("Outbound HTTPS", "OUT", "10.0.0.10", "8.8.8.8", 50001, 443, time=1),
        packet("HTTPS reply", "IN", "8.8.8.8", "10.0.0.10", 443, 50001, time=2),
        packet("Unsolicited SSH", "IN", "9.9.9.9", "10.0.0.10", 40000, 22, time=3),
        packet("Outbound HTTP", "OUT", "10.0.0.11", "1.1.1.1", 50002, 80, time=4),
        packet("Outbound DNS", "OUT", "10.0.0.12", "8.8.4.4", 53000, 53, "UDP", 5),
        packet("Expired reply", "IN", "8.8.8.8", "10.0.0.10", 443, 50001, time=40),
        packet("Table boundary", "OUT", "10.0.0.13", "4.2.2.2", 50003, 443, time=41),
    ]
    for p in tests:
        fw.process(p)
    fw.summary()

def compare_rule_orders():
    print("\nB1.3 - RULE ORDER COMPARISON")
    # Reorder only the disjoint outbound ALLOW rules by expected frequency.
    original = RULES
    optimized = [RULES[2], RULES[1], RULES[3], RULES[0], RULES[4]]
    traffic = []
    for i in range(60):
        port = 443 if i < 40 else (80 if i < 55 else 53)
        proto = "UDP" if port == 53 else "TCP"
        traffic.append(packet(f"flow-{i+1}", "OUT", f"10.0.0.{(i % 200)+1}",
                              "8.8.8.8", 40000+i, port, proto, i))
    for name, rules in [("Version 1 - Original", original),
                        ("Version 2 - Optimized", optimized)]:
        fw = Firewall(rules, table_limit=100)
        for p in traffic:
            fw.process(p)
        print(name, "=> total rule evaluations:", fw.total_rule_checks)

if __name__ == "__main__":
    run_validation()
    compare_rule_orders()
