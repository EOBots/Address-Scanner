import frida
import time
import json
import collections

PROCESS_NAME = "Endless.exe"

# Range to monitor: covers 0x265c811, 0x265c812, 0x265c813, 0x265c814, 0x265c821
WATCH_START = 0x265c800
WATCH_SIZE = 0x40  # 0x265c800 .. 0x265c83F

RECORD_SECONDS = 30  # how long to let you move around


def main():
    print("=== EO Direction Write Tracer (Frida 16, MemoryAccessMonitor) ===")
    print("Monitoring writes around:")
    print(f"  0x{WATCH_START:08X} - 0x{WATCH_START + WATCH_SIZE - 1:08X}")
    print("This covers your known addresses:")
    print("  down  = 0x265c811")
    print("  left  = 0x265c812")
    print("  up    = 0x265c813")
    print("  right = 0x265c814")
    print("  dir   = 0x265c821")
    print("\nMake sure Endless.exe is running and you're in-game.")
    input("Press Enter here, then alt-tab to EO and move around for about "
          f"{RECORD_SECONDS} seconds...")

    session = frida.attach(PROCESS_NAME)
    all_records = []

    js = f"""
    var range = {{ base: ptr("0x{WATCH_START:X}"), size: {WATCH_SIZE} }};
    var records = [];

    MemoryAccessMonitor.enable(
      range,
      {{
        onAccess: function(details) {{
          // details.operation: 'read' or 'write'
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

          // flush chunks to Python to avoid giant arrays
          if (records.length >= 200) {{
            send({{ type: "chunk", records: records }});
            records = [];
          }}
        }}
      }}
    );

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
                recs = payload.get("records", [])
                all_records.extend(recs)
            else:
                print("[JS]", payload)
        elif message["type"] == "error":
            print("[JS-ERROR]", message)

    script = session.create_script(js)
    script.on("message", on_message)
    script.load()

    print(f"[*] MemoryAccessMonitor enabled on 0x{WATCH_START:08X} .. 0x{WATCH_START + WATCH_SIZE - 1:08X}")
    print(f"[*] Now move around in EO (all directions) for ~{RECORD_SECONDS} seconds...")
    time.sleep(RECORD_SECONDS)

    print("[*] Stopping monitor and flushing remaining records...")
    script.exports.stop()
    time.sleep(1.0)

    try:
        session.detach()
    except Exception:
        pass

    # Save raw records
    out_file = "eo_direction_writes.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(all_records, f, indent=4)

    print(f"\n[done] Saved {len(all_records)} access records to {out_file}")

    # Summary: which instructions wrote most often to this region?
    # Only count WRITE operations.
    writer_counter = collections.Counter()
    for rec in all_records:
        if rec.get("operation") != "write":
            continue
        key = (rec.get("module"), rec.get("rva"))
        writer_counter[key] += 1

    if not writer_counter:
        print("\n[summary] No write operations captured in the region. "
              "Either the addresses changed this run, or EO isn't touching them like before.")
        return

    print("\n[summary] Top writers (module, RVA) by write count:")
    for (mod, rva), count in writer_counter.most_common(15):
        print(f"  {mod or '??'} @ {rva} -> {count} writes")

    print("\nUse these RVAs as hook points to find the real movement logic. "
          "We can hook the top 1–2 and build a movement function that works unfocused.")


if __name__ == "__main__":
    main()
