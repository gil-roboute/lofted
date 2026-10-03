# Custom display graphics — feasibility

**Question:** can we put custom graphics / new functionality on the Loftie's display panel while
staying on the project's "patch the stock binary" path?

**Short answer:** the display stack is **LVGL with all images and fonts compiled *into the app
binary*** as C arrays. There is **no asset-swap path** — you cannot drop a PNG on the SD card and
have it appear. Changing graphics therefore means either (A) rebuilding the firmware from source,
or (B) in-place binary patching of the compiled image arrays. Neither is started this session;
this doc records what was found and the tradeoffs so the direction can be chosen later.

## The stack (confirmed from `ota_0.bin`)

| Property        | Finding                                                              | Evidence (file offset) |
| --------------- | ------------------------------------------------------------------- | ---------------------- |
| GUI library     | **LVGL v7** (`lv_roller`, `lv_page`, `lv_cont` — pre-v8 widget set) | `lv_*` symbols ~`0x83f00`–`0x84008` |
| Driver layer    | Espressif `lv_port_esp32` / `lvgl_esp32_drivers`                    | `lvgl_helpers.c` path `0x840d8`, `disp_spi.c` `0x84693` |
| Panel controller| **Sitronix ST7789**, SPI bus                                        | `st7789` `0x84374`, `ST7789 initialization.` `0x8462c` |
| Color depth     | **RGB565 (16-bit)**                                                 | "only supported bit width is 16 bits" `0x7d391` |
| Backlight       | PWM (LEDC), auto-brightness, levels 0–12                            | `LCD_Backlight_Level` `0x10814`, `isLCDBacklightAuto` `0x136ee` |
| QR codes        | LVGL QR add-on compiled in (pairing screen)                        | `qrcodegen.c` `0x1ebba` |
| SDK             | ESP-IDF **v5.1.1**, app `Loftie_EVT 0010_2.4.0`                    | app descriptor `0x20` |

### Why there's no asset-swap path
- A signature scan of `ota_0.bin` finds **0 PNG, 0 JPEG, 0 GIF, 0 QOI** payloads and **no font
  engine** (no freetype / libpng / tjpgd / lodepng / `.ttf`). All UI bitmaps and glyphs are
  baked in as LVGL `lv_img_dsc_t` (RGB565) and `lv_font_t` arrays in `.rodata` — they carry no
  strings, which is why a string scan doesn't see them.
- The SD card holds **audio only** (`/sdcard/alarms/*.mp3`, `/sdcard/phoebe/*.mp3`,
  mounted via `ESP_LittleFSonSD` `0x137c0`). There is **no SPIFFS/LittleFS graphics partition in
  flash** — the flash partition table is just `nvs / otadata / phy_init / app_cfg / factory /
  ota_0 / ota_1`. So graphics live nowhere except inside the app binary.

## Two honest paths

### A. Rebuild from source (most capable; departs from patch-only)
Adds new screens, widgets, fonts, behaviour — anything LVGL can do.
- Reconstruct an **ESP-IDF v5.1.1 + LVGL v7 + `lvgl_esp32_drivers`** project targeting an
  **ST7789 SPI panel at RGB565**. The Loftie app source is not available, so this is a
  *from-scratch* clock app, not a recompile of the stock firmware — you keep the hardware, not
  the stock UI.
- Generate assets with LVGL's converters: `lv_img_conv` (images → `lv_img_dsc_t` C arrays at
  `CF_TRUE_COLOR` / RGB565) and `lv_font_conv` (fonts → `lv_font_t`).
- Flash the new app into an **OTA slot** (`0x420000`) with esptool; the golden full dump restores
  the stock image if needed.
- **Cost:** highest. You reimplement the clock UI. **Benefit:** unlimited; this is the only path
  that adds *functionality* (new screens, new widgets), not just reskins.

### B. In-place binary patch (stays patch-only; limited)
Reskin within the existing image, no new screens.
- Locate a target `lv_img_dsc_t` array in `.rodata` (DROM block in Ghidra) and overwrite its
  RGB565 pixel data **in place, same size**. You can recolor or swap a bitmap for one of identical
  dimensions/format; you **cannot** resize, add images, or add screens (the descriptor's
  width/height/size and all the `gui_*` layout code are fixed).
- Must preserve the image's integrity: re-run **`patch_this.py`'s `resign()`** (checksum byte +
  appended SHA-256) so the bootloader accepts the modified image — same mechanism the broker patch
  already uses.
- **Cost:** fiddly per-asset reverse engineering (find the descriptor, confirm geometry).
  **Benefit:** stays fully within the established patch workflow; good for e.g. recoloring the
  clock face or swapping an icon for a same-size one.

## UI map (recovered screen inventory)

The UI is a hand-written **screen state machine** (not a data-described layout). Each screen has
`_init` / `_enter` / `_exit` / `_rollerupdate` handlers; the **roller** widget is the dominant
input metaphor (rotary-knob selection). Symbols cluster ~`0x1fbbc`–`0x2044c`:

- `GUI_init`, `GUI_update_process` (top-level)
- `gui_main_menu`, `gui_setting_menu`
- `gui_setting_brightness(_menu)`, `gui_setting_vol`, `gui_setting_nightlight`,
  `gui_setting_bedsignal_menu`, `gui_setting_sleep_timer`, `gui_setting_offline_mode`
- `gui_alarm_*` (edit / list / schedule / repeat / settings_light / mute / snoozetime)
- `gui_bedsignal_*_edit`, `gui_date_edit`, `gui_playlist_menu`, `gui_loftieplus_menu`
- `gui_ota(_menu)`, `gui_pair`, `gui_debug_menu`, `Weather`

To add or alter behaviour (path A) these are the functions to reimplement; to find where a screen
draws a given bitmap (path B) decompile the matching `gui_*_init`/`_enter`.

## Recovering exact resolution + GPIO (do this before either path)

Resolution and pin numbers are **printed at boot via format strings**, not stored as ASCII
literals, so a string scan can't read them. Decompile these in Ghidra (see `ghidra-import.md`) and
read the integer args feeding the log calls:

| What you get          | Anchor format string                                            | File offset |
| --------------------- | --------------------------------------------------------------- | ----------- |
| panel hor/ver size    | `Display hor size: %d, ver size: %d`                            | `0x842c6`   |
| display buffer size   | `Display buffer size: %d`                                       | `0x84302`   |
| SPI data pins         | `MISO pin: %d, MOSI pin: %d, SCLK pin: %d, IO2/WP pin: %d, ...` | `0x841ce`   |
| SPI clock / mode / CS | `Clock speed: %dHz, mode: %d, CS pin: %d`                       | `0x846ea`   |
| MADCTL / rotation     | ST7789 `0x36` command value (orientation enum)                 | `0x843ad`   |

Best targets: `lvgl_spi_driver_init` and `disp_spi_add_device_with_speed`. Typical Loftie panels
are **240×240 ST7789** — treat that as *unconfirmed* until you read the actual values, or capture
them live from the serial boot log (the clock prints all of the above on startup).

> **Recovery attempt this session (2026-06).** The format strings above were located at the listed
> offsets (e.g. `Display hor size: %d, ver size: %d` confirmed at file `0x842c6` → vaddr
> `0x3f4842c6`), and the panel is confirmed **ST7789 / SPI / RGB565**. However the display-init
> function did **not** cleanly cross-reference to these strings in this Ghidra auto-analysis pass
> (the literal-pool pointer wasn't recovered via xref or byte-pattern search), so the integer pin
> and resolution constants were **not** statically extracted. Since graphics is deferred, the
> **recommended recovery is the serial boot log** — zero RE effort and 100% accurate (the clock
> prints resolution, buffer size, all SPI pins, clock speed, and rotation on every startup). Revisit
> the static route (manual disassembly seeding at the LVGL init, or a fuller analysis pass) only if
> you later need the values without hardware access.

## Recommendation

If the goal is genuinely *new functionality* on the display, only **path A** delivers it, at the
cost of leaving the patch-only guardrail (it becomes your own clock app on Loftie hardware). If
the goal is cosmetic (recolor / swap a same-size icon) and staying patch-only matters more,
**path B** fits the existing workflow. Either way, **recover the resolution + GPIO first** — both
paths need the exact panel geometry and pinout.
