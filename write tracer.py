import frida
import time
import json
import collections

PROCESS_NAME = "Endless.exe"

# Use the real addresses YOU found
WATCH_START = 0x824200     # start of cluster
WATCH_SIZE  = 0x80         # cover the whole region 0x824200–0x824280
RECORD_SECONDS = 30        # how long you move around


def main():
    print("=== EO REAL MOVEMENT INPUT TRACER (Frida 16) ===")
    print("Monitoring writes in region:")
    print(f"  0x{WATCH_START:08X} – 0x{WATCH_START + WATCH_SIZE - 1:08X}")
    print("These addresses change uniquely per direction, this is REAL INPUT.")
    print("\nMake sure Endless.exe is running and in-game.")
    input(f"Press Enter here, then move around in EO for {RECORD_SECONDS} seconds...")

    session = frida.attach(PROCESS_NAME)
    all_records = []

    js = f"""
    var range = {{
      base: ptr("0x{WATCH_START:X}"),
      size: {WATCH_SIZE}
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
          operation: details.operation,
          module: modName,
          moduleBase: modBase.toString(),
          rva: "0x" + rva.toString(16)
        }});

        if (records.length >= 100) {{
          send({{type: "chunk", records: records}});
          records = [];
        }}
      }}
    }});

    rpc.exports = {{
      stop: function() {{
        MemoryAccessMonitor.disable();
        send({{type: "chunk", records: records, done: true}});
      }}
    }};
    """

    def on_msg(message, data):
        nonlocal all_records
        if message["type"] == "send":
            payload = message["payload"]
            if isinstance(payload, dict) and payload.get("type") == "chunk":
                all_records.extend(payload["records"])
        elif message["type"] == "error":
            print("[JS-ERROR]", message)

    script = session.create_script(js)
    script.on("message", on_msg)
    script.load()

    print("[*] Monitoring REAL movement input region...")
    time.sleep(RECORD_SECONDS)

    print("[*] Stopping monitor...")
    script.exports.stop()
    session.detach()

    fname = "eo_real_input_writes.json"
    with open(fname, "w") as f:
        json.dump(all_records, f, indent=4)

    print(f"\n[done] Saved {len(all_records)} writes to {fname}")

    # Summarize real writers
    writers = collections.Counter(
        (rec["module"], rec["rva"])
        for rec in all_records
        if rec["operation"] == "write"
    )

    print("\n[SUMMARY] REAL INPUT WRITERS:")
    for (mod, rva), cnt in writers.most_common(10):
        print(f"  {mod} @ {rva}  -> {cnt} writes")


if __name__ == "__main__":
    main()
