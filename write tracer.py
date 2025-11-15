import frida
import time
import json
import collections

PROCESS_NAME = "Endless.exe"

# Your current run's direction byte:
TARGET_ADDR = 0x265c821    # dir = 0/1/2/3


def main():
    print("=== EO Direction Byte Write Tracer (0x265c821, Frida 16) ===")
    print(f"Watching exactly this byte: 0x{TARGET_ADDR:08X}")
    print("This is the 'dir' byte you saw updating when you pressed movement keys.")
    print("\nMake sure Endless.exe is running and your character is in-game.")
    input("Press Enter here, then alt-tab to EO and move around (all directions) "
          "for ~20–30 seconds...\n")

    session = frida.attach(PROCESS_NAME)
    all_records = []

    js = f"""
    var range = {{
      base: ptr("0x{TARGET_ADDR:X}"),
      size: 1
    }};

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
          operation: details.operation,  // 'read' or 'write'
          module: modName,
          moduleBase: modBase.toString(),
          rva: "0x" + rva.toString(16)
        }});

        // periodically flush to Python
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

    print(f"[*] MemoryAccessMonitor enabled on 0x{TARGET_ADDR:08X}")
    print("[*] Now move UP / DOWN / LEFT / RIGHT in EO for about 20–30 seconds.")
    time.sleep(25)  # give you time to move

    print("[*] Stopping monitor and flushing remaining records...")
    script.exports.stop()
    time.sleep(1.0)

    try:
        session.detach()
    except Exception:
        pass

    out_file = "eo_dir821_writes.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(all_records, f, indent=4)

    print(f"\n[done] Saved {len(all_records)} access records to {out_file}")

    # Summarize *writers* to 0x265c821
    writer_counts = collections.Counter()
    for rec in all_records:
        if rec.get("operation") != "write":
            continue
        key = (rec.get("module"), rec.get("rva"))
        writer_counts[key] += 1

    if not writer_counts:
        print("\n[summary] No writes captured to 0x265c821 during this run.")
        print("          If you definitely saw direction change, this probably means")
        print("          the address shifted; 0x265c821 was from a previous run.")
        return

    print("\n[summary] Writers to dir byte (module, RVA -> write count):")
    for (mod, rva), count in writer_counts.most_common(15):
        print(f"  {mod or '??'} @ {rva} -> {count} writes")

    print("\nThese RVAs are the exact instructions that update the direction byte.")
    print("Next step after this: hook the top RVA with Interceptor.attach,")
    print("log its context (registers/args), and turn it into a callable 'move(dir)'.")


if __name__ == "__main__":
    main()
