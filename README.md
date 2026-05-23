# p2jb-y2jb

**PlayStation 5 jailbreak (firmware 9.00 – 12.40, tested on 11.60)**
— a port of Gezine / cheburek3000's
[p2jb](https://github.com/Gezine/Luac0re) kernel exploit (cr_ref
overflow via `kqueueex`) from the luac0re (lua-loader) host to
[Y2JB](https://github.com/Gezine/Y2JB) (YouTube / V8 JavaScript host).

Confirmed working: jailbreak end-to-end + debug menu + ELF loader
(`elfldr_1320`, loaded via the Y2JB 1.4 `kexp` shellcode) + persistent
unpatcher delivery.

> ⚠️ **Status — work in progress.** The in-memory jailbreak completes
> reliably, but **closing the YouTube host app after `=== p2jb complete ===`
> currently kernel-panics the console**. The
> [post-jailbreak stability work](#known-limitations) is ongoing.
> In practice this is not a blocker if you apply
> [BD-UN-JB](https://github.com/Gezine/BD-UN-JB) right after the
> jailbreak completes.

> **Firmware support:** confirmed on **11.60**. The bundled offsets
> table covers firmwares **9.00 – 12.40** (luac0re-sourced values),
> but only 11.60 has been tested on hardware — other versions should
> work in theory but are untested.

---

## How it works

The payload triggers a 32-bit `cr_ref` overflow in the PS5 kernel
(via ~2³² `kqueueex` syscalls, ~50 minutes), uses the resulting
use-after-free to build a kernel read/write primitive, escalates the
host process to root, enables the debug menu, and hands off to the
Y2JB 1.4 `kexp` shellcode — which loads `elfldr_1320` and exposes a
remote ELF loader on TCP `:9021`.

---

## Requirements

### PS5 setup (Y2JB)

This payload runs **inside** the Y2JB userland framework on the PS5
(the YouTube TV app modded to run arbitrary JavaScript). Before you
can send anything to the console, you must restore Gezine's Y2JB
system backup on the PS5 — see [Gezine/Y2JB](https://github.com/Gezine/Y2JB)
for the backup file and the restore procedure. Without Y2JB
restored and the YouTube TV app launched, the PS5 has no listener
for the payload and nothing will happen.

**Y2JB 1.4 or newer is required.** The ELF-loader handoff uses the
`kexp` shellcode (and `elfldr_1320`), both shipped inside Y2JB as of
version 1.4. On an older Y2JB the jailbreak still completes but the
ELF-loader stage is skipped.

### Hardware

- PlayStation 5 console running firmware **9.00 – 12.40** (tested on 11.60).
- A PC on the same LAN as the PS5.

No USB drive is needed — `kexp` and `elfldr_1320` are loaded from the
Y2JB framework's own files on the console.

### Software (on PC)

- The `payload_sender.py` delivery tool from
  [Gezine/Y2JB](https://github.com/Gezine/Y2JB) (not included here).
- [Al-Azif/hermes-link](https://github.com/Al-Azif/hermes-link) (or any
  equivalent tool) for delivering ELFs to the loader on `:9021`.

### Files

- `p2jb.js` — the jailbreak payload (this repo).

---

## Usage

### 1. Send the payload

From the PC:

```sh
python payload_sender.py <ps5-ip> p2jb.js
```

The payload streams its log back to `payload_sender.py`'s console.

The first number (`master`) is a fingerprint of how busy YouTube is at
that moment: lower means the app has fewer fds open and the host is
quieter. **The rest of the run is much more likely to complete when
`master` is 34 or less**; higher values empirically correlate with
kernel panics later on. If `master` is above 34, close YouTube
(Options → Close application), reopen it, wait longer this time, and
retry from step 1.

### 2. Wait ~50 minutes

The cr_ref leak dominates the runtime. The payload sender will stay
silent for the whole leak — no per-percentage progress is printed.
Don't assume it has crashed; the worker is internally checked for
liveness and a stall would surface as a `FATAL` log line. Do not
interact with the PS5 while it runs.

### 3. Look for completion

```
[p2jb] stage_elfldr: daemon should be listening on :9021
[p2jb] === p2jb complete ===
```

At this point you have an in-memory jailbreak and a generic ELF loader.
Any ELF you send to `:9021` will run on the jailbroken PS5.

> ⚠️ Do **not** close the YouTube app or let the console go idle for
> too long without doing something — see
> [Known limitations](#known-limitations).

### Sending an ELF to `:9021`

A convenient tool for delivering ELFs to the loader is
[Al-Azif/hermes-link](https://github.com/Al-Azif/hermes-link). It takes
care of the TCP handshake the loader expects, so you don't have to
write the byte protocol yourself.

### Next step (recommended): apply BD-UN-JB

Applying [BD-UN-JB](https://github.com/Gezine/BD-UN-JB) is recommended.
Send its unpatcher ELF to `:9021` (e.g. via the hermes-link tool above)
and refer to BD-UN-JB's own documentation for the rest.

---

## Tuning: leak speed vs. stability

The `cr_ref` leak runs across multiple pinned worker threads in
parallel. The default is **4 cores** (cores 0–3; core 4 stays free for
the orchestrator):

```js
// p2jb.js
const LEAK_CORES = [0, 1, 2, 3];   // ~48 min, default
```

On hardware that's unstable at 4 cores (kernel panics during the leak
phase, or runs that never reach `Stage 0`), dropping to fewer cores
trades wall-clock time for stability — fewer parallel workers means
less contention on the kernel `kqueueex` allocator and a markedly
higher chance of completing.

| `LEAK_CORES`     | wall time   | notes                              |
|------------------|-------------|------------------------------------|
| `[0, 1, 2, 3]`   | ~50 min     | default — fastest, less stable     |
| `[0, 1, 2]`      | ~1h         | three-core (slightly more stable)  |
| `[0, 1]`         | ~1h 30 min  | middle ground                      |
| `[0]`            | ~2h         | single-core — slowest, most stable |

To change it: open `p2jb.js`, search for `LEAK_CORES`, edit the array,
save the file, and run `payload_sender.py` as usual. Try the default
first; only fall back to fewer cores if you see kernel panics during
the leak or if `Stage 0` doesn't appear after well over an hour.

---

## Known limitations

- ⚠️ **Closing the YouTube host app kernel-panics the console (WIP).**
  After `=== p2jb complete ===`, exiting YouTube from the PS5 menu
  triggers an improper shutdown. The post-jailbreak kernel-state
  cleanup is not yet bulletproof. **Mitigation:** apply a persistent
  jailbreak (e.g. [BD-UN-JB](https://github.com/Gezine/BD-UN-JB)) before
  closing — its effect survives the panic-on-close.
- **One run per boot.** A `p2jb.fail` marker is dropped at stage 0 entry
  to refuse re-runs without a reboot — the triple-free is a point of
  no return.
- **YouTube app must stay open** until your persistent payload (if any)
  has applied.

---

## A note from the author

I don't normally work on PS5 exploits or low-level reverse engineering.
This repository is the result of a personal attempt to understand how
the scene's techniques work — not a contribution from a scene developer.
I'm publishing it in case it's useful to someone on firmware 11.60 who
is stuck, but please don't read it as me claiming expertise on the
topic. The real work is by the people credited below; I just tried to
glue their primitives into a working flow on the Y2JB host and learn
along the way.

---

## Credits

- **`p2jb` kernel exploit (cr_ref overflow via `kqueueex`)** —
  Gezine / cheburek3000.
  [Luac0re](https://github.com/Gezine/Luac0re).
- **Y2JB userland framework** — Gezine.
  [Y2JB](https://github.com/Gezine/Y2JB).
- **`elfldr_1320`** — ELF loader binary by Gezine, shipped inside Y2JB.
- **`kexp` post-jailbreak all-in-one shellcode** — ufm42
  ([kexp](https://github.com/ufm42/kexp)), merged into Y2JB 1.4.
- **`notmaj0r` remote_lua_loader p2jb port** — used as a secondary
  reference during the port.
- **`BD-UN-JB` persistent unpatcher** — Gezine.
  [BD-UN-JB](https://github.com/Gezine/BD-UN-JB).
- **lapse (Y2JB)** — referenced for the `gpu.js` debug-menu apply
  flow; not the exploit itself (lapse exploits AIO, not `kqueueex`).
- **Edigax** — help with the multi-core leak implementation, bringing
  the `cr_ref` leak down from ~2 hours to ~48 minutes.
- **Claude (Anthropic)** — AI assistant used throughout the port:
  iterative debugging across the worker / Stage 0 saga, D-fix
  identification, host-noise gate, public release packaging.

---

## License

MIT — see [LICENSE](LICENSE).
