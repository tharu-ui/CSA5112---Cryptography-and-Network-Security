# B2 - Adversarial Traffic Generation and Workload Comparison
from cns_b1_firewall import Firewall, RULES, packet

def make_traffic_a(count=100):
    # Easy traffic: common outbound HTTPS requests match an early ALLOW rule.
    return [packet(f"A-{i}", "OUT", "10.0.0.10", "8.8.8.8",
                   45000, 443, "TCP", i) for i in range(count)]

def make_traffic_b(count=100):
    # Hard traffic: inbound packets reach the final broad DENY rule;
    # every fourth packet is a new outbound flow that consumes state-table space.
    traffic = []
    for i in range(count):
        if i % 4 == 0:
            traffic.append(packet(f"B-new-{i}", "OUT", f"10.0.0.{(i % 200)+1}",
                                  "9.9.9.9", 50000+i, 443, "TCP", 0))
        else:
            traffic.append(packet(f"B-last-{i}", "IN", "9.9.9.9",
                                  "10.0.0.10", 60000+i, 22, "TCP", 0))
    return traffic

def run():
    print("B2 - SAME PACKET COUNT, DIFFERENT WORKLOAD")
    for name, traffic in [("Traffic A", make_traffic_a()),
                          ("Traffic B", make_traffic_b())]:
        fw = Firewall(RULES, table_limit=15)
        print("\n", name)
        for p in traffic:
            fw.process(p)
        fw.summary()

if __name__ == "__main__":
    run()
