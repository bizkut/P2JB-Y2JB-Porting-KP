# p2jb-y2jb

**PlayStation 5 jailbreak (firmware 9.00 – 12.40, tested on 11.60)**
— a port of Gezine / cheburek3000's
[p2jb](https://github.com/Gezine/Luac0re) kernel exploit (cr_ref
overflow via `kqueueex`) from the luac0re (lua-loader) host to
[Y2JB](https://github.com/Gezine/Y2JB) (YouTube / V8 JavaScript host).

Confirmed working: jailbreak end-to-end + debug menu + ELF loader
(`elfldr_1320`, via Y2JB 1.4 `kexp` shellcode or USB fallback) +
persistent unpatcher delivery.

**Compatible with both Y2JB 1.3 and Y2JB 1.4.** The payload
automatically detects the framework version and uses the appropriate
ELF-loader delivery method (kexp handoff on 1.4+, USB fallback on 1.3).

> **Status:** The in-memory jailbreak completes reliably. The
> `elfldr` ELF loader is intentionally spawned as a **daemon thread
> inside the YouTube process** (this is how both the legacy USB path
> and the Y2JB 1.4 `kexp` shellcode launch it). Because of this,
> **closing YouTube also terminates `elfldr`.**
>
> The post-jailbreak cleanup neutralizes the known panic-on-close
> hazards: corrupted `ipv6_kernel_rw` socket `pktinfo` pointers,
> forged pipe-buffer state, and restored process credentials/root
> directory on both the normal completion path and late-failure path.
> Treat close stability as **improved but hardware-test pending** and
> apply [BD-UN-JB](https://github.com/Gezine/BD-UN-JB) as usual after
> the jailbreak completes.

> **Firmware support:** confirmed on **11.60**. The bundled offsets
> table covers firmwares **9.00 – 12.40** (luac0re-sourced values),
> but only 11.60 has been tested on hardware — other versions should
> work in theory but are untested.

---

## How it works

The payload triggers a 32-bit `cr_ref` overflow in the PS5 kernel
(via ~2³² `kqueueex` syscalls, ~50 minutes), uses the resulting
use-after-free to build a kernel read/write primitive, escalates the
host process to root, enables the debug menu, and then loads
`elfldr_1320` — exposing a remote ELF loader on TCP `:9021`.

On **Y2JB 1.4+** this uses the built-in `kexp` shellcode handoff
(no USB required). If that framework handoff is unavailable, the
payload falls back to loading an ELF binary from a USB drive.

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

**Y2JB 1.4 or newer is recommended.** The ELF-loader stage prefers
the built-in `kexp` shellcode handoff (no USB needed). If you are on
an older Y2JB the payload automatically falls back to loading the ELF
binary from a USB drive.

### Hardware

- PlayStation 5 console running firmware **9.00 – 12.40** (tested on 11.60).
- A PC on the same LAN as the PS5.

A USB drive is normally only needed when running on an older Y2JB
version (< 1.4), or when intentionally using the manual USB ELF-loader
fallback. On Y2JB 1.4+ the built-in `kexp` shellcode loads `elfldr_1320`
from the framework's own files on the console.

### Software (on PC)

- The `payload_sender.py` delivery tool from
  [Gezine/Y2JB](https://github.com/Gezine/Y2JB) (not included here).
- [Al-Azif/hermes-link](https://github.com/Al-Azif/hermes-link) (or any
  equivalent tool) for delivering ELFs to the loader on `:9021`.

### Files

- `p2jb.js` — the jailbreak payload (this repo).
- `elfldr_1320.elf` — ELF loader for **firmware ≥ 11.00**. Binary by Gezine.
- `elfldr.elf` — ELF loader for **firmware < 11.00**. Use this one on
  older FWs (it's the legacy binary that predates the `_1320` build).
  Both files are bundled here for convenience.

---

## Usage

### 1. Prepare the USB drive (optional on Y2JB 1.4+)

If your PS5 is running Y2JB 1.4 or newer, skip this step — the
payload will automatically use the built-in `kexp` shellcode first.
USB remains available as a fallback.

For the automatic USB fallback on older Y2JB versions, pick the right
loader for your firmware and copy it to the **root** of your USB drive
(FAT32 or exFAT):

- **Firmware ≥ 11.00** → copy `elfldr_1320.elf` as `/elfldr_1320.elf`
- **Firmware < 11.00**  → copy `elfldr.elf` as `/elfldr.elf`

Then plug the USB into the PS5 before launching the payload. The
payload scans `/mnt/usb0`..`/mnt/usb7` and accepts either filename.

### 2. Launch the YouTube app on the PS5 and wait

When the YouTube UI loads, **dismiss any popups / prompts** that appear.
Then **wait at least 60
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

### 5. Wait ~50 minutes

The cr_ref leak dominates the runtime. The payload may print coarse
burn progress milestones, but long quiet stretches are normal. Don't
assume it has crashed; the worker is internally checked for liveness
and a stall would surface as a `FATAL` log line. Do not interact with
the PS5 while it runs.

### 6. Look for completion

```
[p2jb] stage_elfldr: daemon should be listening on :9021
[p2jb] === p2jb complete ===
```

At this point you have an in-memory jailbreak and a generic ELF loader.
Any ELF you send to `:9021` will run on the jailbroken PS5.

> ⚠️ Do **not** close the YouTube app.** `elfldr` is a daemon thread
> inside YouTube; closing the app kills the loader and may kernel-panic
> the console due to corrupted kernel state left by the jailbreak.
> Apply a persistent payload (e.g. BD-UN-JB) while YouTube is still
> open — see [Known limitations](#known-limitations).

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

- **Closing YouTube may kernel-panic the console.** The panic is caused
  by corrupted kernel state left behind from the jailbreak (forged pipe
  buffers, dangling socket `pktinfo` pointers, altered credentials), not
  by `elfldr` itself. Cleanup code attempts to restore the original
  state on both the success path and the late-failure path, but this
  has not been fully verified on hardware. **Keep applying a persistent
  jailbreak** (e.g. [BD-UN-JB](https://github.com/Gezine/BD-UN-JB))
  before closing YouTube until the cleanup is confirmed stable.
- **`master_rfd > 34` aborts the run.** Restart YouTube and retry. This
  is intentional: a noisier host correlates with kernel-panics at the
  stage 0 → stage 1 transition.
- **One run per boot.** A `p2jb.fail` marker is dropped at stage 0 entry
  to refuse re-runs without a reboot — the triple-free is a point of
  no return.
- **`elfldr` is a daemon thread inside the YouTube process.** Whether it
  is launched via the Y2JB 1.4 `kexp` shellcode or the legacy USB path,
  it lives inside the YouTube process. Closing the YouTube app kills
  `elfldr` and — because of the corrupted kernel state noted above —
  may also trigger a kernel panic. Apply your persistent payload
  (e.g. BD-UN-JB) while YouTube is still open.

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
- **Claude (Anthropic)** — AI assistant used throughout the port:
  iterative debugging across the worker / Stage 0 saga, D-fix
  identification, host-noise gate, public release packaging.

---

## License

MIT — see [LICENSE](LICENSE).
