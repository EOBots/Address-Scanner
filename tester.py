import frida
import time
import json
import math
import random

PROCESS_NAME = "Endless.exe"

# Hard addresses you provided (absolute for this run)
DOWN_ADDR  = "0x265c811"
LEFT_ADDR  = "0x265c812"
UP_ADDR    = "0x265c813"
RIGHT_ADDR = "0x265c814"

TEST_DURATION_SECONDS = 4 * 60     # 4 minutes
STEP_INTERVAL_SECONDS = 0.2        # how often we rewrite flags during test
SAMPLES_PER_STATE     = 40         # how many samples to grab per direction


def attach_frida():
    print(f"[*] Attaching to {PROCESS_NAME} with Frida...")
    session = frida.attach(PROCESS_NAME)

    js = f"""
    var downAddr  = ptr("{DOWN_ADDR}");
    var leftAddr  = ptr("{LEFT_ADDR}");
    var upAddr    = ptr("{UP_ADDR}");
    var rightAddr = ptr("{RIGHT_ADDR}");

    rpc.exports = {{
      readflags: function() {{
        try {{
          var d = Memory.readU8(downAddr);
          var l = Memory.readU8(leftAddr);
          var u = Memory.readU8(upAddr);
          var r = Memory.readU8(rightAddr);
          return [d, l, u, r];
        }} catch (e) {{
          send({{ error: "readflags: " + e.toString() }});
          return [-1, -1, -1, -1];
        }}
      }},
      writeflags: function(d, l, u, r) {{
        try {{
          Memory.writeU8(downAddr,  d & 0xFF);
          Memory.writeU8(leftAddr,  l & 0xFF);
          Memory.writeU8(upAddr,    u & 0xFF);
          Memory.writeU8(rightAddr, r & 0xFF);
        }} catch (e) {{
          send({{ error: "writeflags: " + e.toString() }});
        }}
      }}
    }};
    """

    script = session.create_script(js)

    def on_msg(message, data):
        if message["type"] == "send":
            print("[JS]", message["payload"])
        elif message["type"] == "error":
            print("[JS-ERROR]", message)

    script.on("message", on_msg)
    script.load()
    print("[*] Frida script loaded (hard addresses wired).")
    return session, script


def sample_flags(script, duration_sec: float, label: str):
    """
    Sample [down,left,up,right] repeatedly for `duration_sec` seconds.
    Returns a list of samples (each is [d,l,u,r]).
    """
    print(f"    [sample] Sampling flags for ~{duration_sec:.1f}s during {label}...")
    samples = []
    end = time.time() + duration_sec
    while time.time() < end:
        vals = script.exports.readflags()
        if vals and isinstance(vals, list) and len(vals) == 4:
            samples.append([int(x) for x in vals])
        time.sleep(duration_sec / SAMPLES_PER_STATE)
    print(f"    [sample] Collected {len(samples)} samples for {label}.")
    return samples


def avg_vector(vecs):
    if not vecs:
        return [0, 0, 0, 0]
    n = len(vecs)
    sums = [0.0, 0.0, 0.0, 0.0]
    for v in vecs:
        for i in range(4):
            sums[i] += v[i]
    return [s / n for s in sums]


def dist(a, b):
    # Euclidean distance between two 4D vectors
    return math.sqrt(sum((a[i] - b[i]) ** 2 for i in range(4)))


def pick_representative(samples, idle_avg):
    """
    From a list of samples, pick the one that differs most from idle_avg.
    """
    if not samples:
        return [0, 0, 0, 0]
    best = samples[0]
    best_d = -1.0
    for s in samples:
        d = dist(s, idle_avg)
        if d > best_d:
            best_d = d
            best = s
    return best


def main():
    print("=== EO Flag Tester (Hard Addresses, 4-min Random, Unfocused Test) ===")
    print("Hard-coded addresses for this test run:")
    print(f"  down  = {DOWN_ADDR}")
    print(f"  left  = {LEFT_ADDR}")
    print(f"  up    = {UP_ADDR}")
    print(f"  right = {RIGHT_ADDR}")
    print("\nMake sure Endless.exe is running and your character is in-game.")
    input("Press Enter here, then bring EO to the foreground and stand still...")

    session, script = attach_frida()

    # 1) Idle baseline
    print("\n[PHASE 1] Learning flag patterns")
    print("  Step 1: Idle baseline (no keys pressed)")
    time.sleep(1.0)
    idle_samples = sample_flags(script, 2.0, "IDLE (no movement)")
    idle_avg = avg_vector(idle_samples)
    print(f"    [idle] Average flags = {[round(x,2) for x in idle_avg]}")

    # 2) Learn per-direction patterns
    patterns = {}

    directions_order = [
        ("up", "UP arrow"),
        ("right", "RIGHT arrow"),
        ("down", "DOWN arrow"),
        ("left", "LEFT arrow"),
    ]

    for dir_name, prompt in directions_order:
        print(f"\n  Step 2: Hold {prompt} for about 2 seconds when prompted.")
        input(f"    -> When ready, press Enter here and THEN immediately hold {prompt} in EO...")

        # Give you a tiny moment to switch windows
        time.sleep(0.5)
        samples = sample_flags(script, 2.0, dir_name.upper())

        # Give time to release key
        time.sleep(0.5)

        rep = pick_representative(samples, idle_avg)
        patterns[dir_name] = rep
        print(f"    [{dir_name}] representative flags = {rep}")

    print("\n[LEARNED PATTERNS]")
    print(json.dumps(patterns, indent=4))

    # 3) Begin 4-minute random test (EO can be unfocused now)
    print("\n[PHASE 2] 4-minute random write test")
    print("  You can now ALT+TAB away from EO if you want.")
    print(f"  For the next {TEST_DURATION_SECONDS} seconds, I'll randomly write these patterns")
    print("  into the four flag addresses and log the chosen direction.")

    start = time.time()
    end = start + TEST_DURATION_SECONDS
    step_count = 0

    dir_sequence = ["up", "right", "down", "left"]

    while time.time() < end:
        step_count += 1
        dir_name = random.choice(dir_sequence)
        vals = patterns.get(dir_name, [0, 0, 0, 0])
        d, l, u, r = [int(x) & 0xFF for x in vals]

        # Write them
        script.exports.writeflags(d, l, u, r)
        print(f"[STEP {step_count}] DIR={dir_name.upper()} -> flags=[{d},{l},{u},{r}]")

        time.sleep(STEP_INTERVAL_SECONDS)

    print("\n[done] Random write test finished.")
    print(f"Total steps: {step_count}")

    try:
        session.detach()
    except Exception:
        pass


if __name__ == "__main__":
    main()
