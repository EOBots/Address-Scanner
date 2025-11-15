import frida
import time
import json
import collections

PROCESS_NAME = "Endless.exe"
# From your screenshot: moduleBase = 0x400000, rva = 0x1c9f67
READ_RVA = 0x1C9F67

RECORD_SECONDS = 30  # how long we trace while you move


def main():
    print("=== EO Movement Upstream Tracer (Frida 16) ===")
    print("Hooking the READ instruction you found:")
    print(f"  Endless.exe + 0x{READ_RVA:X}")
    print("\nThis will:")
    print("  - Intercept the instruction that reads the 0x8242xx region")
    print("  - For each hit, capture the caller (return address) and registers")
    print("  - Summarize which caller RVA is hit the most (likely movement logic)\n")

    print("Make sure Endless.exe is running and your character is in-game.")
    input(f"Press Enter here, then alt-tab to EO and move around for about {RECORD_SECONDS} seconds...\n")

    session = frida.attach(PROCESS_NAME)
    all_calls = []

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
    var target = base.add({READ_RVA});  // Endless.exe + 0x1C9F67

    send({{
      type: "info",
      message: "Hooking at " + target.toString()
    }});

    Interceptor.attach(target, {{
      onEnter: function(args) {{
        var ctx = this.context;

        // Get return address from stack (32-bit vs 64-bit)
        var sp = ctx.esp || ctx.rsp;
        var ret = ptr(0);
        try {{
          ret = Memory.readPointer(sp);
        }} catch (e) {{}}

        var callerMod = Process.findModuleByAddress(ret);
        var callerName = callerMod ? callerMod.name : null;
        var callerBase = callerMod ? callerMod.base : ptr("0");
        var callerRva = callerMod ? ret.sub(callerBase).toUInt32() : 0;

        // Capture some registers that might be interesting
        var rec = {{
          type: "call",
          instr: target.toString(),
          ret: ret.toString(),
          callerModule: callerName,
          callerRva: "0x" + callerRva.toString(16),
          // Registers (32-bit style but we also check 64-bit)
          eax: ctx.eax ? ctx.eax.toString() : null,
          ebx: ctx.ebx ? ctx.ebx.toString() : null,
          ecx: ctx.ecx ? ctx.ecx.toString() : null,
          edx: ctx.edx ? ctx.edx.toString() : null,
          esi: ctx.esi ? ctx.esi.toString() : null,
          edi: ctx.edi ? ctx.edi.toString() : null,
          rsp: ctx.rsp ? ctx.rsp.toString() : null,
          esp: ctx.esp ? ctx.esp.toString() : null
        }};

        send(rec);
      }}
    }});

    rpc.exports = {{
      nop: function() {{}}
    }};
    """

    def on_message(message, data):
        nonlocal all_calls
        if message["type"] == "send":
            payload = message["payload"]
            if isinstance(payload, dict):
                if payload.get("type") == "info":
                    print("[JS]", payload.get("message"))
                elif payload.get("type") == "call":
                    all_calls.append(payload)
            else:
                print("[JS]", payload)
        elif message["type"] == "error":
            print("[JS-ERROR]", message)

    script = session.create_script(js)
    script.on("message", on_message)
    script.load()

    print("[*] Hook installed. Now MOVE around (all directions) in EO.")
    print(f"[*] Tracing for {RECORD_SECONDS} seconds...\n")

    # Simple countdown
    for remaining in range(RECORD_SECONDS, 0, -1):
        print(f"  ... {remaining:2d}s remaining", end="\r")
        time.sleep(1)
    print("\n[*] Trace window finished.")

    # No explicit detach needed for Interceptor, but we'll detach session
    try:
        session.detach()
    except Exception:
        pass

    # Save raw data
    out_file = "eo_movement_upstream_calls.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(all_calls, f, indent=4)

    print(f"\n[done] Saved {len(all_calls)} call records to {out_file}")

    # Summarize callers: which function(s) are actually hitting this read
    caller_counts = collections.Counter()
    for rec in all_calls:
        mod = rec.get("callerModule")
        rva = rec.get("callerRva")
        caller_counts[(mod, rva)] += 1

    if not caller_counts:
        print("\n[summary] No calls captured. That would be weird if you were moving.")
        print("          If this happens, double-check the RVA (0x1C9F67) and that EO build matches.")
        return

    print("\n[summary] Top callers of the 0x1C9F67 read (module, RVA -> call count):")
    for (mod, rva), count in caller_counts.most_common(15):
        print(f"  {mod or '??'} @ {rva} -> {count} calls")

    print("\nThe top 1–2 RVAs here are your REAL upstream movement logic.")
    print("Next step: we hook that caller RVA directly and turn it into a callable move(dir).")


if __name__ == "__main__":
    main()
