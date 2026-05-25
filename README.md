# p2jb-y2jb

**PlayStation 5 jailbreak (firmware 9.00 – 12.40)**
— a port of Gezine / cheburek3000's
[p2jb](https://github.com/Gezine/Luac0re) kernel exploit (cr_ref
overflow via `kqueueex`) from the luac0re (lua-loader) host to
[Y2JB](https://github.com/Gezine/Y2JB) (YouTube / V8 JavaScript host).

Confirmed working: jailbreak end-to-end + GPU-DMA debug menu + ELF
loader (started automatically from the Y2JB sandbox) + persistent
unpatcher delivery. Closing the YouTube host app after completion no
longer kernel-panics the console.

> **Firmware support:** works on **9.00 – 12.40**.

---

## How it works

The payload triggers a 32-bit `cr_ref` overflow in the PS5 kernel
(via ~2³² `kqueueex` syscalls, ~50 minutes), uses the resulting
use-after-free to build a kernel read/write primitive, escalates the
host process to root, enables the Debug Settings menu via GPU DMA
writes on the read-only kernel `.data` segment, then reads
`elfldr_1320_v5.elf` from the Y2JB sandbox and spawns it as a new
thread — exposing a remote ELF loader on TCP `:9021`.

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

**Y2JB 1.3 or newer.** The ELF loader is delivered differently
depending on Y2JB version:

- **Y2JB 1.4+**: the payload reads `elfldr_1320_v5.elf` directly from
  the Y2JB sandbox slot — no USB needed.
- **Y2JB 1.3**: Y2JB 1.3 bundles an outdated `elfldr.elf` that does
  not work on the current kernels, so the payload reads
  `elfldr_1320.elf` from a USB stick plugged into the PS5
  (`/mnt/usb0` ... `/mnt/usb7`). Grab `elfldr_1320_v5.elf` from this
  repo, put it on the root of a FAT32/exFAT USB (you can rename it
  to `elfldr_1320.elf` or `elfldr.elf` if you prefer — all three are
  probed), and plug the USB in **before** launching the payload.

At the very start the payload checks the framework helpers it needs
are in scope: if anything is missing it aborts before touching the
kernel (no leak, no stage 0).

### Hardware

- PlayStation 5 console running firmware **9.00 – 12.40**.
- A PC on the same LAN as the PS5.
- **(Y2JB 1.3 only)** A FAT32/exFAT USB stick with `elfldr_1320.elf`
  on its root. On Y2JB 1.4+ no USB is needed.

### Software (on PC)

- The `payload_sender.py` delivery tool from
  [Gezine/Y2JB](https://github.com/Gezine/Y2JB) (not included here).
- [Al-Azif/hermes-link](https://github.com/Al-Azif/hermes-link) (or any
  equivalent tool) for delivering ELFs to the loader on `:9021`.

### Files

- `p2jb.js` — the jailbreak payload (this repo).
- `elfldr_1320_v5.elf` — Gezine's ELF loader binary, included here
  for Y2JB 1.3 users who need to provide it via USB. On Y2JB 1.4+ the
  same file is already bundled inside the framework, so you can ignore
  this one.

---

## Usage

### 1. Send the payload

From the PC:

```sh
python payload_sender.py <ps5-ip> p2jb.js
```

The payload streams its log back to `payload_sender.py`'s console.

### 2. Wait ~50 minutes

The cr_ref leak dominates the runtime. The payload sender will stay
silent for the whole leak — no per-percentage progress is printed.
Don't assume it has crashed; the worker is internally checked for
liveness and a stall would surface as a `FATAL` log line. Do not
interact with the PS5 while it runs.

### 3. Look for completion

```
[p2jb] stage_elfldr: elfldr launched - listening on :9021
[p2jb] === p2jb complete ===
```

At this point you have an in-memory jailbreak and a generic ELF loader.
Any ELF you send to `:9021` will run on the jailbroken PS5.

### Sending an ELF to `:9021`

A convenient tool for delivering ELFs to the loader is
[Al-Azif/hermes-link](https://github.com/Al-Azif/hermes-link). It takes
care of the TCP handshake the loader expects, so you don't have to
write the byte protocol yourself.

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

- **One run per boot.** A `p2jb.fail` marker is dropped at stage 0 entry
  to refuse re-runs without a reboot — the triple-free is a point of
  no return.
- **The ELF loader lives inside the YouTube process.** Closing the
  app is safe for the kernel, but it tears down the loader and any
  ELF you sent to `:9021`. Keep YouTube open until your persistent
  payload (e.g. [BD-UN-JB](https://github.com/Gezine/BD-UN-JB)) has
  applied; afterwards you can close the app normally.

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
- **`kexp` post-jailbreak all-in-one shellcode** — ufm42
  ([kexp](https://github.com/ufm42/kexp)), merged into Y2JB 1.4.
- **`notmaj0r` remote_lua_loader p2jb port** — used as a secondary
  reference during the port.
- **lapse (Y2JB)** — referenced for the `gpu.js` debug-menu apply
  flow; not the exploit itself (lapse exploits AIO, not `kqueueex`).
- **Edigax** — help with the multi-core leak implementation, bringing
  the `cr_ref` leak down from ~2 hours to ~48 minutes.
- **Rviju** and **Dr.Yenyen** — help running test builds on real
  hardware during the close-KP investigation.
- **Claude (Anthropic)** — AI assistant used throughout the port.

---

## License

MIT — see [LICENSE](LICENSE).
