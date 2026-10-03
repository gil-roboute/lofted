# Loading the Loftie firmware into Ghidra (correct settings)

This is the reproducible recipe for importing the Loftie app image so it disassembles and the
strings/data resolve at the right addresses. It targets **`may-firmware-dump/ota_0.bin`** — the
carved *active* app slot — not the 16 MB full dump.

> **First, fix the current project.** The `lofted` Ghidra project presently has the raw 16 MB
> `loftie_full_dump.bin` loaded as a single flat block at `0x0`, unanalyzed. That is the wrong
> target (see `writeup-blog.md`, "Don't load the raw 16 MB blob"). Import `ota_0.bin` instead and
> map its segments as below. You can leave the old program in the project or delete it.

## 1. Processor / language

| Setting   | Value                  |
| --------- | ---------------------- |
| Language  | **`Xtensa:LE:32:default`** |
| Endian    | little                 |
| Size      | 32-bit                 |
| Compiler  | default                |

The ESP32 core is a Tensilica **Xtensa LX6** (little-endian, 32-bit).

> **Use the Xtensa module built into Ghidra — do NOT install a third-party one.** Ghidra **≥ 11.0**
> ships official Xtensa support (this machine runs **Ghidra 12.0.4**, module v4.1), so
> `Xtensa:LE:32:default` already appears in the language picker. Verified on this install: the
> built-in SLEIGH models the **windowed ABI** ESP-IDF actually uses — `ENTRY` / `RETW` / `RETW.N` /
> `MOVSP` / `ROTW` and `CALL4/8/12` + `CALLX4/8/12` — and the compiler spec defines both a windowed
> `__stdcall` convention (with `rotateRegWindow` / `restoreRegWindow` fixups) and a `__call0`
> convention. That register-window modeling is what makes the decompiler readable.
>
> **Avoid the old community forks.** `yath/ghidra-xtensa` (2019, Ghidra 9.1) and `Ebiroll/ghidra-xtensa`
> (Ghidra 10.3) predate the in-tree module, **do not implement windowed registers**, and won't load
> on Ghidra 12. Ebiroll's own README now says *"Ghidra Version 11.0 now includes Xtensa support, so
> this repo is not needed."*
>
> The built-in module is the processor only — it does **not** auto-parse the ESP32 `0xE9` header, so
> do the memory map in §3 by hand (an optional third-party "ESP32 flash loader" exists, but the
> manual map is version-proof and is what's documented here).

## 2. Import as Raw Binary — load the WHOLE file

`File → Import File…` → select `may-firmware-dump/ota_0.bin`.
- **Format:** *Raw Binary*
- **Language:** `Xtensa:LE:32:default` (use the "..." picker)
- Click *Options…* and **leave File Offset = 0 and the Length field blank/0** so Ghidra ingests
  the entire 4,194,304-byte file. Base Address `0` is fine; name the initial block something
  throwaway like `raw`.

> ⚠ **Pitfall — do NOT put a segment's length in the import Options.** The import Length determines
> how many bytes Ghidra keeps as the *File Bytes* source. If you set it to a segment size (e.g.
> `0xcb738`), the File Bytes source is truncated to that many bytes and you later get
> *"Please enter a valid file bytes offset (0 - 833335)"* when adding `irom`/`iram` — their bytes
> were never imported. Load the **whole file** here; size the individual segments in §3.

When prompted to analyze after import, **decline for now** — finish the memory map first.

## 3. Memory map — replace the flat block with five segment blocks

Open *Window → Memory Map*.

1. **Delete the throwaway `raw` block** (select it → trash/delete icon). Deleting the *block* does
   **not** delete the *File Bytes* source — the full file stays available in the dropdown.
2. **Add five blocks** (the `+` "Add Memory Block" button). For each: set Block Name, Start Address
   (the vaddr), Length, **Block Type = *File Bytes*** (source `ota_0.bin`), the File Offset, and the
   R/W/X permissions. The `0xE9` image header defines these five segments:

| Block name | Start (vaddr) | Length     | File Offset (`ota_0.bin` @) | R | W | X | Region                              |
| ---------- | ------------- | ---------- | --------------------------- | - | - | - | ----------------------------------- |
| `drom`     | `0x3f400020`  | `0x0cb738` | `0x000020`                  | ✔ |   |   | rodata / strings / **LVGL C arrays** |
| `dram0`    | `0x3ffbdb60`  | `0x0048b8` | `0x0cb760`                  | ✔ | ✔ |   | `.data`                             |
| `irom`     | `0x400d0020`  | `0x1be914` | `0x0d0020`                  | ✔ |   | ✔ | flash `.text` (**main code**)       |
| `dram1`    | `0x3ffc2418`  | `0x001a8c` | `0x28e93c`                  | ✔ | ✔ |   | `.data`                             |
| `iram`     | `0x40080000`  | `0x01ee40` | `0x2903d0`                  | ✔ |   | ✔ | RAM-resident `.text`                |

Then set the entry point:
- **Entry point: `0x400818e0`** (in the `iram` block). *Navigate to it, right-click →
  Disassemble*, or add it as an entry-point label so analysis seeds from there.

> **Hex vs decimal — the two dialogs differ.** The *Add Memory Block* dialog (Memory Map) accepts
> `0x`-prefixed hex in its Length and File Offset fields, so the values above can be typed as-is.
> The *raw-binary import Options* dialog's Length/File Offset are **decimal-only** — there,
> `0xcb738` must be entered as `833336`, `0x20` as `32`, etc. (Start Address is a hex address field
> in both.)
>
> **Self-check each block:** each segment has its own `Start − FileOffset` (they're placed
> independently — `0x3f400000` for `drom`, `0x40000000` for `irom`, different values for the DRAM
> blocks), so there's no single shared constant to verify against. The reliable end-to-end checks
> are in §5: the broker string must land **exactly** at `0x3f416f10` (validates `drom`), and the
> entry point `0x400818e0` must disassemble into real code (validates `irom`/`iram`). If the broker
> string is off by N bytes, `drom`'s File Offset is off by N — e.g. entering `20` instead of `32`
> shifts it by 12 bytes (`0x20 − 0x14`).

> Use *File Bytes* (not "Initialized from file" copy) so blocks reference the imported bytes
> directly. Blocks with no file backing (none here) would be "Uninitialized".

## 4. Analyze

`Analysis → Auto Analyze`. Accept the defaults plus *ASCII Strings* and *Decompiler Parameter ID*.
Expect: strings in `drom` resolve, and `irom`/`iram` disassemble into functions.

## 5. Cross-checks (confirm the map is right)

- **Same table from esptool:** `esptool --chip esp32 image_info ota_0.bin` prints the identical
  segment list (load addr + length) — a sanity check against the table above.
- **Re-derive the header yourself** (zero-dependency, matches what produced this table):

  ```python
  import struct
  d = open("ota_0.bin", "rb").read()
  assert d[0] == 0xE9
  off = 0x18                       # 8-byte header + 16-byte ESP32 extended header
  for i in range(d[1]):            # d[1] = segment count (5)
      load, length = struct.unpack_from("<I I", d, off)
      print(f"seg{i}: file=0x{off+8:06x} vaddr=0x{load:08x} size=0x{length:06x}")
      off += 8 + length
  print("entry =", hex(struct.unpack_from("<I", d, 4)[0]))   # 0x400818e0
  ```

- **Spot-check a known string:** the broker URI is at file `0x16f10`. With the map above it lands
  at **vaddr `0x3f416f10`** in `drom` and reads
  `mqtts://[REDACTED]-ats.iot.us-east-1.amazonaws.com:8883`. If it does, the DROM mapping is
  correct. (Translation rule: any DROM string `vaddr = file_offset + 0x3f400000`; any IROM code
  `vaddr = file_offset + 0x40000000` for file `0xd0020`–`0x28e933`.)

## 6. Notes

- `factory.bin` and `ota_1.bin` are the other two app slots and import with the **same recipe**
  (re-parse their own `0xE9` headers — segment sizes differ per build).
- The 16 MB `loftie_full_dump.bin` is only useful as a flat container to carve partitions from; do
  not analyze it as code.
- Good first decompile targets once analyzed: `lvgl_spi_driver_init` /
  `disp_spi_add_device_with_speed` (recover the panel resolution + GPIO — see
  `display-graphics-feasibility.md`) and the MQTT JSON handlers `AWS_receive_config_cb` /
  `IOTGW_Json2State` (confirm the command schema — see `mqtt-command-reference.md`).
