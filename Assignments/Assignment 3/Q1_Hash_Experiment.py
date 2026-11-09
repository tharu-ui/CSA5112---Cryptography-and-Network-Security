
import hashlib
import os
import time


# PART A: HASH FUNCTIONS

def sha256_hash(data):
    return hashlib.sha256(data).digest()


def toy_sum_hash(data):
    value = sum(data) % (2 ** 32)
    return value.to_bytes(4, "big")


def toy_xor_hash(data):
    result = 0

    for i in range(0, len(data), 4):
        block = data[i:i + 4]
        value = int.from_bytes(block, "big")
        result ^= value

    return result.to_bytes(4, "big")


def count_changed_bits(hash1, hash2):
    value = int.from_bytes(hash1, "big") ^ int.from_bytes(hash2, "big")
    return bin(value).count("1")


def flip_random_bit(data):
    modified = bytearray(data)
    position = int.from_bytes(os.urandom(4), "big") % len(modified)
    bit = int.from_bytes(os.urandom(1), "big") % 8
    modified[position] ^= (1 << bit)
    return bytes(modified)


def avalanche_experiment():
    sizes = [16, 64, 256]
    trials = 100

    hash_functions = {
        "Toy Sum": toy_sum_hash,
        "Toy XOR": toy_xor_hash,
        "SHA-256": sha256_hash
    }

    print("\nPART A: AVALANCHE EFFECT EXPERIMENT")
    print("=" * 75)
    print(f"{'Hash Function':<15} {'Message Size':<15} {'Trials':<10} {'Avg Changed Bits':<20}")
    print("-" * 75)

    for name, hash_function in hash_functions.items():
        for size in sizes:
            total_changed = 0

            for _ in range(trials):
                message = os.urandom(size)
                modified = flip_random_bit(message)

                hash1 = hash_function(message)
                hash2 = hash_function(modified)

                total_changed += count_changed_bits(hash1, hash2)

            average = total_changed / trials

            print(f"{name:<15} {size:<15} {trials:<10} {average:<20.2f}")


# PART B: COLLISION SEARCH

def collision_search(k, trial):
    seen = {}
    counter = 0
    start_time = time.time()

    while True:
        message = f"Q1-Collision-{trial}-{counter}".encode()

        digest = hashlib.sha256(message).digest()

        value = int.from_bytes(digest, "big") >> (256 - k)

        if value in seen:
            elapsed = time.time() - start_time

            return counter + 1, seen[value], message, elapsed

        seen[value] = message
        counter += 1


def collision_experiment():
    values = [16, 20, 24, 28, 32]
    repetitions = 3

    results = {}

    print("\nPART B: BIRTHDAY COLLISION EXPERIMENT")
    print("=" * 85)
    print(f"{'k bits':<10} {'Trial':<10} {'Hashes':<15} {'Expected Effort':<20} {'Time (s)':<15}")
    print("-" * 85)

    for k in values:
        results[k] = []

        for trial in range(1, repetitions + 1):
            count, msg1, msg2, elapsed = collision_search(k, trial)

            results[k].append(count)

            expected = 2 ** (k / 2)

            print(
                f"{k:<10} {trial:<10} {count:<15} "
                f"{expected:<20.0f} {elapsed:<15.4f}"
            )

            if trial == 1:
                print("  First message:", msg1.decode())
                print("  Second message:", msg2.decode())

    print("\nAVERAGE COLLISION RESULTS")
    print("-" * 50)
    print(f"{'k bits':<15} {'Average Hashes':<20} {'Birthday Bound':<15}")

    averages = {}

    for k in values:
        average = sum(results[k]) / repetitions
        averages[k] = average

        print(f"{k:<15} {average:<20.2f} {2 ** (k / 2):<15.0f}")

    try:
        import matplotlib.pyplot as plt

        plt.figure(figsize=(9, 5))

        plt.plot(
            values,
            [averages[k] for k in values],
            marker="o",
            label="Experimental Average"
        )

        plt.plot(
            values,
            [2 ** (k / 2) for k in values],
            marker="s",
            linestyle="--",
            label="Theoretical Birthday Bound"
        )

        plt.yscale("log", base=2)
        plt.xlabel("Truncated Hash Length (k bits)")
        plt.ylabel("Number of Hash Computations")
        plt.title("Collision Search and Birthday Bound")
        plt.xticks(values)
        plt.grid(True)
        plt.legend()
        plt.tight_layout()

        plt.savefig("Q1_Collision_Graph.png")
        plt.show()

        print("\nGraph saved as Q1_Collision_Graph.png")

    except ImportError:
        print("\nMatplotlib is not installed. Graph was not generated.")


# MAIN PROGRAM

if __name__ == "__main__":
    print("CRYPTOGRAPHIC HASH ANALYSIS")
    print("=" * 75)

    avalanche_experiment()
    collision_experiment()

    print("\nALL EXPERIMENTS COMPLETED")
