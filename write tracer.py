import frida
import time
import json
import collections

PROCESS_NAME = "Endless.exe"
DIRECTIONAL_RVA = 0x6DACA   # from your CeraBot v12.2
RECORD_SECONDS = 30         # how long to move around while tracing


def main():
    print("=== EO Dynamic Direction Writer Tracer (Frida 16) ===")
    print("This will:")
    print("  1) Hook 0x6DACA (directional RVA) to find the live directional address.")
    print("  2) Derive the 4 flag bytes at directional-0x10.")
    print("  3) Monitor a small region around those bytes for writes.")
    print("  4) Let you move around and log which instructions actually write there.\n")

    print("Make sure Endless.exe is running and you are in-game.")
    input("Press Enter here, then be ready to press a movement key once in EO...\n")

    session = frida.attach(PROCESS_NAME)
    all_records = []

    js = f"""
    var mod = null;
    try {{
      mod = Process.getModuleByName("{PROCESS_NAME}");
    }} catch (e) {{
      var mods = Process.enumerateModules();
      mod = mods.length ? mods[0] : null;
    }}
    if (!mod) {{
      throw new Error("Could not find module base for {PROCESS_NAME}");
    }}

    var base = mod.base;
    var dirRva  = ptr({DIRECTIONAL_RVA});
    var dirInst = base.add(dirRva);

    var directionalAddress = null;
    var flagBase = null;
    var monitorStarted = false;

    function startMonitorIfReady() {{
      if (!directionalAddress || monitorStarted) return;

      // from your scan: flag_base = dirAddr - 0x10
      flagBase = directionalAddress.sub(0x10);

      var range = {{
        base: flagBase.sub(0x10), // watch a bit before as well
        size: 0x40                 // 64 bytes total
      }};

      send({{
        type: "monitor_start",
        directional: directionalAddress.toString(),
        flagBase: flagBase.toString(),
        rangeBase: range.base.toString()
      }});

      MemoryAccessMonitor.enable(range, {{
        onAccess: function(details) {{
          var mod = Process.findModuleByAddress(details.from);
          var modName = mod ? mod.name : null;
          var modBase = mod ? mod.base : ptr("0");
          var rva = mod ? details.from.sub(mod.base).toUInt32() : 0;

          send({{
            type: "access",
            from: details.from.toString(),
            addr: details.address.toString(),
            operation: details.operation,
            module: modName,
            moduleBase: modBase.toString(),
            rva: "0x" + rva.toString(16)
          }});
        }}
      }});

      monitorStarted = true;
    }}

    Interceptor.attach(dirInst, {{
      onEnter: function(args) {{
        var ebx = this.context.ebx || this.context.rbx;
        if (!ebx) {{
          send({{ type: "error", message: "No EBX/RBX in context" }});
          return;
        }}
        var dirAddr = ebx.add(0x55);
        directionalAddress = dirAddr;

        // Let Python know we have the live address
        var val = dirAddr.readU8();
        send({{
          type: "directional_resolved",
          directional: dirAddr.toString(),
          value: val.toString()
        }});

        startMonitorIfReady();
      }}
    }});

    rpc.exports = {{
      stopmonitor: function() {{
        if (monitorStarted) {{
          MemoryAccessMonitor.disable();
          monitorStarted = false;
        }}
      }}
    }};
    """

    def on_message(message, data):
        nonlocal all_records
        if message["type"] == "send":
            payload = message["payload"]
            if not isinstance(payload, dict):
                print("[JS]", payload)
                return

            mtype = payload.get("type")
            if mtype == "directional_resolved":
                print(f"[JS] directional_address = {payload.get('directional')} value={payload.get('value')}")
                print("[JS] Once you see this, you can move around; monitor will start automatically.")
            elif mtype == "monitor_start":
                print("[JS] Monitor started with:")
                print(f"     directional = {payload.get('directional')}")
                print(f"     flagBase    = {payload.get('flagBase')}")
                print(f"     rangeBase   = {payload.get('rangeBase')}")
            elif mtype == "access":
                # Log every access record for later analysis
                all_records.append(payload)
            else:
                print("[JS]", payload)
        elif message["type"] == "error":
            print("[JS-ERROR]", message)

    script = session.create_script(js)
    script.on("message", on_message)
    script.load()

    print("[*] Hook installed on directional RVA 0x%X." % DIRECTIONAL_RVA)
    print("[*] Now go to EO and press ANY movement key once.")
    print("    That first movement will resolve directional_address and start monitoring.")
    print("    After that, keep moving in all directions for ~%d seconds.\n" % RECORD_SECONDS)

    # Give time for user movement + monitoring
    time.sleep(RECORD_SECONDS)

    print("[*] Stopping monitor...")
    script.exports.stopmonitor()
    time.sleep(1.0)

    try:
        session.detach()
    except Exception:
        pass

    # Save raw records
    out_file = "eo_direction_dynamic_writes.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(all_records, f, indent=4)

    print(f"\n[done] Saved {len(all_records)} access records to {out_file}")

    # Summarize writers (only WRITE operations)
    writer_counts = collections.Counter()
    for rec in all_records:
        if rec.get("operation") != "write":
            continue
        key = (rec.get("module"), rec.get("rva"))
        writer_counts[key] += 1

    if not writer_counts:
        print("\n[summary] No writes captured in the dynamic region.")
        print("          That would be strange if you definitely saw those bytes change.")
        print("          If this happens, we should double-check the RVA (0x6DACA) in this client build.")
        return

    print("\n[summary] Top writer instructions (module, RVA -> write count):")
    for (mod, rva), count in writer_counts.most_common(15):
        print(f"  {mod or '??'} @ {rva} -> {count} writes")

    print("\nThose RVAs are the REAL code paths updating your direction/flag bytes.")
    print("From here, the next step is to hook the top writer and turn it into a callable movement routine.")


if __name__ == "__main__":
    main()
