import frida
import time
import random

PROCESS_NAME = "Endless.exe"
DIRECTIONAL_RVA = 0x6DACA  # from your CeraBot v12.2

TEST_DURATION_SECONDS = 4 * 60   # 4 minutes
STEP_INTERVAL_SECONDS = 0.35     # time between direction changes


def main():
    print("=== EO Random Walk Tester (Frida 16, memory-based, unfocused OK) ===")
    print("Make sure Endless.exe is running and your character is in-game.")
    input("Press Enter here, then go to EO and be ready to move ONCE...")

    session = frida.attach(PROCESS_NAME)

    js_code = f"""
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
    var rel  = ptr({DIRECTIONAL_RVA});
    var target = base.add(rel);

    var dirAddr = null;
    var ready = false;

    // 0 = down, 1 = left, 2 = up, 3 = right (from your scan)
    var DIR_DOWN  = 0;
    var DIR_LEFT  = 1;
    var DIR_UP    = 2;
    var DIR_RIGHT = 3;

    Interceptor.attach(target, {{
      onEnter: function(args) {{
        var ebx = this.context.ebx || this.context.rbx;
        if (!ebx) {{
          send({{ error: "No EBX/RBX in context" }});
          return;
        }}
        var characterDirectionAddress = ebx.add(0x55);
        dirAddr = characterDirectionAddress;
        ready = true;

        var currentDir = characterDirectionAddress.readU8();
        send({{
          directional_address: characterDirectionAddress.toString(),
          current_direction: currentDir.toString()
        }});
      }}
    }});

    function setFlagsForDir(dir) {{
      if (!dirAddr) return;
      // From your scan:
      // flag_base = directional_address - 0x10
      var flagBase = dirAddr.sub(0x10);

      // order: 0 = down, 1 = left, 2 = up, 3 = right
      // we'll use 1 for active, 0 for inactive
      flagBase.writeU8(dir === DIR_DOWN  ? 1 : 0);        // down
      flagBase.add(1).writeU8(dir === DIR_LEFT  ? 1 : 0); // left
      flagBase.add(2).writeU8(dir === DIR_UP    ? 1 : 0); // up
      flagBase.add(3).writeU8(dir === DIR_RIGHT ? 1 : 0); // right
    }}

    rpc.exports = {{
      isready: function() {{
        return ready;
      }},
      getdirectionaddr: function() {{
        if (!dirAddr) return "0x0";
        return dirAddr.toString();
      }},
      getdir: function() {{
        if (!dirAddr) return -1;
        return dirAddr.readU8();
      }},
      setdir: function(dir) {{
        // dir: 0=down,1=left,2=up,3=right
        if (!dirAddr) return;
        dirAddr.writeU8(dir);
        setFlagsForDir(dir);
      }}
    }};
    """

    script = session.create_script(js_code)

    def on_message(message, data):
        if message["type"] == "send":
            print("[JS]", message["payload"])
        elif message["type"] == "error":
            print("[JS-ERROR]", message)

    script.on("message", on_message)
    script.load()

    print("[*] Directional hook armed.")
    print("[*] Now, in EO, press ANY movement key once (up/left/down/right) to trigger it...")

    # Wait for dirAddr to be discovered
    while not script.exports.isready():
        time.sleep(0.05)

    dir_addr_str = script.exports.getdirectionaddr()
    print(f"[*] directional_address resolved to {dir_addr_str}")
    print("[*] You can now ALT+TAB away from EO if you want.")
    print(f"[*] Starting random walk test for {TEST_DURATION_SECONDS} seconds...")

    start = time.time()
    end = start + TEST_DURATION_SECONDS
    step_count = 0

    DIR_DOWN  = 0
    DIR_LEFT  = 1
    DIR_UP    = 2
    DIR_RIGHT = 3

    directions = [DIR_DOWN, DIR_LEFT, DIR_UP, DIR_RIGHT]
    names = {DIR_DOWN: "DOWN", DIR_LEFT: "LEFT", DIR_UP: "UP", DIR_RIGHT: "RIGHT"}

    while time.time() < end:
        step_count += 1
        dir_choice = random.choice(directions)
        script.exports.setdir(dir_choice)
        print(f"[STEP {step_count}] Set direction = {names[dir_choice]} ({dir_choice})")
        time.sleep(STEP_INTERVAL_SECONDS)

    print("\n[done] Random walk test completed.")
    print(f"Ran for ~{TEST_DURATION_SECONDS} seconds, {step_count} steps.")

    try:
        session.detach()
    except Exception:
        pass


if __name__ == "__main__":
    main()

