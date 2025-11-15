import frida
import time
import json
import collections

PROCESS_NAME = "Endless.exe"

# Region covering:
#   down  = 0x265c811
#   left  = 0x265c812
#   up    = 0x265c813
#   right = 0x265c814
#   dir   = 0x265c821
WATCH_START = 0x265c800
WATCH_SIZE = 0x40   # 0x265c800 .. 0x265c83F

RECORD_SECONDS = 30  # how long to move around


def main():
    print("=== EO Direction Write Tracer (Frida 16 / MemoryAccessMonitor) ===")
    print("Monitoring writes around:")
    print(f"  0x{WATCH_START:08X} - 0x{WATCH_START + WATCH_SIZE - 1:08X}")
    print("Known bytes inside this window:")
    print("  down  = 0x265c811")
    print("  left  = 0x265c812")
    print("  up    = 0x265c813")
    print("  right = 0x265c814")
    print("  dir   = 0x265c821\n")
    print("Make sure Endless.exe is running and you're in-game.")
    input(f"Press Enter here, then alt-tab to EO and move around for ~{RECORD_SECONDS} seconds...\n")

    session = frida.attach(PROCESS_NAME)
    all_records = []

    js = f"""
    var range = {{ base: ptr("0x{WATCH_START:X}"), size: {WATCH_SIZE} }};
    var records = [];

    MemoryAccessMonitor.enable(range, {{
      onAccess: function(details) {{
        var mod = Process.findModuleByAddress(details.from);
        var modName = mod ? mod.name : null;
        var modBase = mod ? mod.base : ptr("0");
        var rva = mod ? details.from.sub(mod.base).toUInt32() : 0;

        records.push({{
          from: details.from.toString(),
          addr: details.address.toString(),
          operation: details.operation,
          module: modName,
          moduleBase: modBase.toString(),
          rva: "0x" + rva.toString(16)
        }});

        if (records.length >= 200) {{
          send({{ type: "chunk", records: records }});
          records = [];
        }}
      }}
    }});

    rpc.exports = {{
      stop: function() {{
        MemoryAccessMonitor.disable();
        send({{ type: "chunk", records: records, done: true }});
        records = [];
      }}
    }};
    """

    def on_message(message, data):
        nonlocal all_records
        if message["type"] == "send":
            payload = message["payload"]
            if isinstance(payload, dict) and payload.get("type") == "chunk":
                all_records.extend(payload.get("records", []))
            else:
                print("[JS]", payload)
        elif message["type"] == "error":
            print("[JS-ERROR]", message)

    script = session.create_script(js)
    script.on("message", on_message)
    script.load()

    print(f"[*] Monitor enabled on 0x{WATCH_START:08X} .. 0x{WATCH_START + WATCH_SIZE - 1:08X}")
    print(f"[*] Move UP / DOWN / LEFT / RIGHT in EO for about {RECORD_SECONDS} seconds now.")
    time.sleep(RECORD_SECONDS)

    print("[*] Stopping monitor and flushing records...")
    script.exports.stop()
    time.sleep(1.0)

    try:
        session.detach()
    except Exception:
        pass

    out_file = "eo_direction_writes.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(all_records, f, indent=4)

    print(f"\n[done] Saved {len(all_records)} access records to {out_file}")

    writer_counts = collections.Counter()
    for rec in all_records:
        if rec.get("operation") != "write":
            continue
        key = (rec.get("module"), rec.get("rva"))
        writer_counts[key] += 1

    if not writer_counts:
        print("\n[summary] No writes captured in this region. Either the addresses shifted this run,")
        print("          or EO isn't touching them like before. Double-check them if this happens.")
        return

    print("\n[summary] Top writer instructions (module, RVA -> write count):")
    for (mod, rva), count in writer_counts.most_common(15):
        print(f"  {mod or '??'} @ {rva} -> {count} writes")

    print("\nThose RVAs are the code locations that actually UPDATE your direction bytes.")
    print("Next step is to hook one of those and turn it into a callable movement routine.")


if __name__ == "__main__":
    main()
