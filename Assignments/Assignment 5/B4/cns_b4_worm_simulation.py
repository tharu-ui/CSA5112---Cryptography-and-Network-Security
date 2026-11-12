# B4 - Abstract Worm Outbreak and Containment Simulation
import random

HOSTS = 200
SEED = 42
ATTEMPTS_PER_HOST = 4
INFECTION_PROBABILITY = 0.35
MAX_STEPS = 30

def simulate(name, strategy="none", detect_step=2, seed=SEED):
    random.seed(seed)
    infected = {0}
    history = [len(infected)]
    first_50 = 0 if len(infected) >= HOSTS/2 else None
    first_100 = 0 if len(infected) == HOSTS else None

    for step in range(1, MAX_STEPS + 1):
        newly_infected = set()
        for source in list(infected):
            attempts = ATTEMPTS_PER_HOST
            if strategy == "rate_limit":
                attempts = 1
            if strategy == "late_block" and step >= detect_step:
                attempts = 0
            for _ in range(attempts):
                target = random.randrange(HOSTS)
                if target in infected:
                    continue
                # Segmentation: only contacts within the same 50-host segment pass.
                if strategy == "segmentation" and source // 50 != target // 50:
                    continue
                # Port blocking after detection stops the worm's vulnerable service.
                if strategy == "block_port" and step >= detect_step:
                    continue
                if random.random() < INFECTION_PROBABILITY:
                    newly_infected.add(target)
        infected.update(newly_infected)
        history.append(len(infected))
        if first_50 is None and len(infected) >= HOSTS * 0.5:
            first_50 = step
        if first_100 is None and len(infected) == HOSTS:
            first_100 = step
        if len(infected) == HOSTS:
            break

    print(f"\n{name}")
    print("Infected hosts by time step:", history)
    print("Time to infect 50%:", first_50 if first_50 is not None else "Not reached")
    print("Time to infect 100%:", first_100 if first_100 is not None else "Not reached")
    print("Final infected hosts:", len(infected), "out of", HOSTS)
    return history, infected

def run():
    print("B4 - WORM OUTBREAK SIMULATION")
    print("Network:", HOSTS, "hosts | Seed:", SEED,
          "| Attempts per infected host:", ATTEMPTS_PER_HOST,
          "| Infection probability:", INFECTION_PROBABILITY)
    simulate("Uncontrolled outbreak", "none")
    simulate("Strategy 1 - Four-segment network", "segmentation")
    simulate("Strategy 2 - Block vulnerable port at step 2", "block_port", detect_step=2)
    simulate("Strategy 3 - Per-host rate limit", "rate_limit")
    simulate("Challenge - Port block delayed until step 6", "late_block", detect_step=6)

if __name__ == "__main__":
    run()
