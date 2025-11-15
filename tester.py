import frida
import time
import random

PROCESS_NAME = "Endless.exe"

# Movement function start:
#   0046D9D9 (module base 00400000) → RVA = 0x6D9D9
MOVEMENT_FUNC_RVA = 0x6D9D9

TEST_DURATION_SECONDS = 3 * 60    # 3-minute test
STEP_INTERVAL_SECONDS = 0.4       # time between direction changes


def main():
    print("=== EO Forced Movement Tester (Frida 16, movement function hook) ===")
    print("This will:")
    print("  - Hook Endless.exe+0x6D9D9 (movement handler)")
    print("  - On each call, overwrite dir byte [ebx+0x55] if a forced direction is set")
    print("  - Run a random-walk test for %d seconds" % TEST_DURATION_SECONDS)
    print("\nRequirements:")
    print("  - Endless.exe running, character logged in and free to move.")
    print("  - You can ALT+TAB away after the hook arms.")
    input("Press Enter to attach to Endless.exe...\n")

    session = frida.attach(PROCESS_NAME)

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
    var func = base.add({MOVEMENT_FUNC_RVA});  // 0046D9D9

    // Forced direction: -1 = none, otherwise 0=down,1=left,2=up,3=right
    var forcedDir = -1;

    // Small helper for debug logging (can be muted)
    function dbg(msg) {{
      // send(msg);  // uncomment if you want spam logs
    }}

    send({{
      type: "info",
      message: "Hooking movement function at " + func.toString()
    }});

    Interceptor.attach(func, {{
      onEnter: function (args) {{
        var ctx = this.context;
        var ebx = ctx.ebx || ctx.rbx;
        if (!ebx) {{
          return;
        }}

        // Player struct fields:
        //   [ebx+0x55] = direction byte (0,1,2,3)
        //   [ebx+0x56] = movement / step state (dl in 0046DACA write)
        var dirAddr  = ebx.add(0x55);
        var stepAddr = ebx.add(0x56);

        if (forcedDir >= 0 && forcedDir <= 3) {{
          try {{
            dirAddr.writeU8(forcedDir);
            // Optional: also bump step/movement state.
            // This might not be exact, but keeps the engine "active".
            // If it causes jitter, you can comment it out.
            stepAddr.writeU8(forcedDir & 0xFF);

            dbg("Forced dir=" + forcedDir + " at " + dirAddr.toString());
          }} catch (e) {{
            send({{ type: "error", message: "write error: " + e.toString() }});
          }}
        }}
      }}
    }});

    rpc.exports = {{
      setdir: function (d) {{
        forcedDir = d | 0;
        return forcedDir;
      }},
      cleardir: function () {{
        forcedDir = -1;
        return forcedDir;
      }}
    }};
    """

    def on_message(message, data):
        if message["type"] == "send":
            payload = message["payload"]
            if isinstance(payload, dict):
                if payload.get("type") == "info":
                    print("[JS]", payload.get("message"))
                elif payload.get("type") == "error":
                    print("[JS-ERROR]", payload.get("message"))
                else:
                    print("[JS]", payload)
            else:
                print("[JS]", payload)
        elif message["type"] == "error":
            print("[JS-ERROR]", message)

    script = session.create_script(js)
    script.on("message", on_message)
    script.load()

    print("[*] Movement hook installed.")
    print("[*] You can now ALT+TAB away from EO; the game does not need focus.")
    print("[*] Starting random-walk forced-direction test for %d seconds...\n" %
          TEST_DURATION_SECONDS)

    # Direction mapping:
    #   0 = down, 1 = left, 2 = up, 3 = right
    DIR_DOWN  = 0
    DIR_LEFT  = 1
    DIR_UP    = 2
    DIR_RIGHT = 3

    dirs = [DIR_DOWN, DIR_LEFT, DIR_UP, DIR_RIGHT]
    names = {
        DIR_DOWN:  "DOWN",
        DIR_LEFT:  "LEFT",
        DIR_UP:    "UP",
        DIR_RIGHT: "RIGHT",
    }

    start = time.time()
    end = start + TEST_DURATION_SECONDS
    step = 0

    try:
        while time.time() < end:
            step += 1
            d = random.choice(dirs)
            script.exports.setdir(int(d))
            print(f"[STEP {step}] Forcing direction = {names[d]} ({d})")
            time.sleep(STEP_INTERVAL_SECONDS)

        print("\n[done] Test duration reached. Clearing forced direction.")
        script.exports.cleardir()
    finally:
        try:
            session.detach()
        except Exception:
            pass

    print("Session detached. If your character moved while EO was unfocused,")
    print("then the internal movement function can be driven without focus.")


if __name__ == "__main__":
    main()
