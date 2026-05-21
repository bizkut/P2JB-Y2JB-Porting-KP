# p2jb-y2jb

**PlayStation 5 jailbreak (firmware 9.00 – 12.40, tested on 11.60)**
— a port of Gezine / cheburek3000's
[p2jb](https://github.com/Gezine/Luac0re) kernel exploit (cr_ref
overflow via `kqueueex`) from the luac0re (lua-loader) host to
[Y2JB](https://github.com/Gezine/Y2JB) (YouTube / V8 JavaScript host).

Confirmed working: jailbreak end-to-end + debug menu + USB-loaded
`elfldr_1320` + persistent unpatcher delivery.

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
(via ~2³² `kqueueex` syscalls, ~2 hours), uses the resulting
use-after-free to build a kernel read/write primitive, escalates the
host process to root, enables the debug menu, and loads
`elfldr_1320` from USB — exposing a remote ELF loader on TCP `:9021`.

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

### Hardware

- PlayStation 5 console running firmware **9.00 – 12.40** (tested on 11.60).
- A USB flash drive formatted FAT32 or exFAT.
- A PC on the same LAN as the PS5.

### Software (on PC)

- The `payload_sender.py` delivery tool from
  [Gezine/Y2JB](https://github.com/Gezine/Y2JB) (not included here).
- [Al-Azif/hermes-link](https://github.com/Al-Azif/hermes-link) (or any
  equivalent tool) for delivering ELFs to the loader on `:9021`.

### Files

- `p2jb.js` — the jailbreak payload (this repo).
- `elfldr_1320.elf` — included in this repo for convenience. Binary by
  Gezine.

---

## Usage

### 1. Prepare the USB drive

Copy `elfldr_1320.elf` to the root of your USB drive, exactly as
`/elfldr_1320.elf`. Plug it into the PS5 before launching the payload.

### 2. Launch the YouTube app on the PS5 and wait

When the YouTube UI loads, **dismiss any popups / prompts** that appear
(sign-in invites, banners, cookies, etc.). Then **wait at least 60
seconds** before sending the payload — preferably more. This payload
reads kernel fd numbers as a host-noise signal and aborts cleanly if
the YouTube host is still busy with startup work or with a popup
keeping the UI active. Waiting longer = quieter host = a higher chance
of passing the pre-flight gate.

### 3. Send the payload

From the PC:

```sh
python payload_sender.py <ps5-ip> p2jb.js
```

The payload streams its log back to `payload_sender.py`'s console.

### 4. Watch for the pre-flight gate

Early in the run, you will see a log line like:

```
[p2jb] pipes master=X,Y victim=Z,W
```

If `master ≤ 34`, the run proceeds. Otherwise the payload aborts with a
`FATAL: pipe shift detected` message **without** touching the kernel,
so no console reboot or storage repair is needed. Close YouTube
(Options → Close application), reopen it, wait longer than before, and
retry from step 2.

### 5. Wait ~2 hours

The cr_ref leak dominates the runtime. The payload sender will stay
silent for the whole leak — no per-percentage progress is printed.
Don't assume it has crashed; the worker is internally checked for
liveness and a stall would surface as a `FATAL` log line. Do not
interact with the PS5 while it runs.

### 6. Look for completion

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

## Known limitations

- ⚠️ **Closing the YouTube host app kernel-panics the console (WIP).**
  After `=== p2jb complete ===`, exiting YouTube from the PS5 menu
  triggers an improper shutdown. The post-jailbreak kernel-state
  cleanup is not yet bulletproof. **Mitigation:** apply a persistent
  jailbreak (e.g. [BD-UN-JB](https://github.com/Gezine/BD-UN-JB)) before
  closing — its effect survives the panic-on-close.
- **`master_rfd > 34` aborts the run.** Restart YouTube and retry. This
  is intentional: a noisier host correlates with kernel-panics at the
  stage 0 → stage 1 transition.
- **One run per boot.** A `p2jb.fail` marker is dropped at stage 0 entry
  to refuse re-runs without a reboot — the triple-free is a point of
  no return.
- **YouTube app must stay open** until your persistent payload (if any)
  has applied. `elfldr` is a daemon thread inside the YouTube process.

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
- **`elfldr_1320`** — Gezine (ELF loader binary).
- **`notmaj0r` remote_lua_loader p2jb port** — used as a secondary
  reference during the port.
- **`BD-UN-JB` persistent unpatcher** — Gezine.
  [BD-UN-JB](https://github.com/Gezine/BD-UN-JB).
- **lapse (Y2JB)** — referenced for the `gpu.js` debug-menu apply
  flow; not the exploit itself (lapse exploits AIO, not `kqueueex`).
- **Claude (Anthropic)** — AI assistant used throughout the port:
  iterative debugging across the worker / Stage 0 saga, D-fix
  identification, host-noise gate, public release packaging.

---

## License

MIT — see [LICENSE](LICENSE).
