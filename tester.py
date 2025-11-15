import frida
import time
import json

PROCESS_NAME = "Endless.exe"
DIRECTIONAL_RVA = 0x6DACA  # from CeraBot v12.2

directional_addr = None
direction_value = None
session = None
resolved = False


def on_message(message, data):
    global directional_addr, direction_value, resolved, session

    if message["type"] == "send":
        payload = message["payload"]
        if "error" in payload:
            print("[frida][dir] error:", payload["error"])
            return

        addr_str = payload.get("directional_address")
        val_str = payload.get("character_direction")
        if not addr_str:
            print("[frida][dir] unexpected payload:", payload)
            return

        directional_addr = int(addr_str, 16)
        direction_value = int(val_str) if val_str is not None else None

        print(f"[frida][dir] directional_address = {hex(directional_addr)}, value = {direction_value}")
        resolved = True

        try:
            session.detach()
        except Exception:
            pass

    elif message["type"] == "error":
        print("[frida][dir] script error:", message)


def resolve_directional():
    global session, resolved

    print("[*] Attaching to Endless.exe...")
    session = frida.attach(PROCESS_NAME)
    print("[*] Hooking directional RVA 0x%X..." % DIRECTIONAL_RVA)

    js = f"""
    var mod = null;
    try {{
      mod = Process.getModuleByName("{PROCESS_NAME}");
    }} catch (e) {{
      var mods = Process.enumerateModules();
      mod = mods.length ? mods[0] : null;
    }}
    if (!mod) throw new Error("Could not find module base for {PROCESS_NAME}");

    var base = mod.base;
    var rel  = ptr({DIRECTIONAL_RVA});
    var target = base.add(rel);

    Interceptor.attach(target, {{
      onEnter: function(args) {{
        var ebx = this.context.ebx || this.context.rbx;
        if (!ebx) {{
          send({{ error: "No EBX/RBX in context" }});
          return;
        }}
        var characterDirectionAddress = ebx.add(0x55);
        var characterDirection = characterDirectionAddress.readU8();
        send({{
          directional_address: characterDirectionAddress.toString(),
          character_direction: characterDirection.toString()
        }});
      }}
    }});
    """

    script = session.create_script(js)
    script.on("message", on_message)
    script.load()

    print("[*] Directional hook armed. Move once in EO to trigger it...")
    while not resolved:
        time.sleep(0.05)
    print("[*] Directional address resolved.")


def main():
    print("=== EO Direction & Flag Resolver (Frida 16) ===")
    print("Make sure Endless.exe is running and you are in-game.")
    input("Press Enter here, then move once in EO...")

    resolve_directional()

    # Now compute the flag addresses based on your scan:
    # flag_base = directional_addr - 0x10
    flag_base = directional_addr - 0x10

    down_flag  = flag_base + 0  # down
    left_flag  = flag_base + 1  # left
    up_flag    = flag_base + 2  # up
    right_flag = flag_base + 3  # right

    result = {
        "directional_address": hex(directional_addr),
        "direction_value_mapping": {
            "down": 0,
            "left": 1,
            "up": 2,
            "right": 3
        },
        "flag_base": hex(flag_base),
        "direction_flags": {
            "down":  hex(down_flag),
            "left":  hex(left_flag),
            "up":    hex(up_flag),
            "right": hex(right_flag)
        }
    }

    outfile = "eo_direction_resolved.json"
    with open(outfile, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4)

    print("\n[done] Saved resolved addresses to", outfile)
    print(json.dumps(result, indent=4))


if __name__ == "__main__":
    main()
