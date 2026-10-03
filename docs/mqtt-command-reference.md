# Loftie MQTT command & config reference

How to drive the clock from a local broker / Home Assistant once `patch_this.py` has repointed it
at your Mosquitto instance (see `README.md` for broker + cert setup, and `patch_this.py` for the
firmware redirect). All examples assume mutual TLS with your own client cert/key.

## Topic model

The firmware builds three topics at runtime from the device id (`%s` = the AWS-IoT thing name,
MAC-derived; it prints `client_id=%s` in the serial boot log — that's your `<id>`):

| Direction        | Topic                      | Source offset | Purpose                          |
| ---------------- | -------------------------- | ------------- | -------------------------------- |
| device → broker  | `/devices/<id>/state`      | `0x1d4a4`     | telemetry / state report         |
| broker → device  | `/devices/<id>/config`     | `0x1d4b8`     | configuration (alarms, settings) |
| broker → device  | `/devices/<id>/commands/#` | `0x1d4cc`     | commands (wildcard subscription) |

**Proven by decompilation** (`mqtt_event_handler` `FUN_400f3c70` → `AWS_receive_config_cb`
`FUN_400f3a84`): on connect the device subscribes to **both** `/config` and `/commands/#`, and
inbound data on **either** is passed to the **same** flat-JSON parser. The **subtopic is ignored** —
the verb must be a **key inside the JSON body**, not the topic suffix. So `{"volume":7}` works
published to `/config` *or* `/commands/anything`. (We publish to `/commands/<verb>` only for human
readability.)

In the examples below set — note the broker is reached by **IP** (Mosquitto on your Portainer host),
matching the IP baked into the firmware and into `server.crt`'s SAN:

```bash
ID=lXXXXXXXXXXXX          # from the boot log client_id / your device MAC
H=192.168.1.50            # your broker host IP (the patched mqtts:// target)
TLS="--cafile certs/ca.crt --cert certs/ha.crt --key certs/ha.key -p 8883"   # HA identity (see mosquitto/acl)
```

## Config topic — alarms (PROVEN)

This is the path already verified end-to-end (see `README.md`). One `alarms` array; each object
is one alarm. After publishing, re-dump `app_cfg` and run `nvs_parse.py --alarms` to confirm it
persisted into the `key_alarm` NVS blob.

```bash
mosquitto_pub -h $H -t "/devices/$ID/config" $TLS -m '{"alarms":[{
  "alarmLight":false,"daysOfWeek":127,"getUpToneFileIdx":0,"isSet":true,
  "time":"10:00am","toneFolderIdx":0,"type":"alarm","volume":3,
  "wakeUpToneFileIdx":0,"getUpToneFolderIdx":0,"wakeUpToneFolderIdx":0}]}'
```

`daysOfWeek` is a bitmask, **bit0=Sun … bit6=Sat** (127 = every day, 62 = Mon–Fri). Matches the
decoded `key_alarm` layout in `nvs_parse.py`. Other config-topic keys present in the image:
`isSet`, `routines`, `folderIndex`/`fileIndex`, `alarmSettings`, `alarmLight`, `snoozeTime`,
`wakeUpToneFolderIdx`/`wakeUpToneFileIdx`, `getUpToneFolderIdx`/`getUpToneFileIdx`,
`sleepTimerMins`, `screenBrightness`, `24HourMode`, `isAlarmMute`.

## Commands / config verbs (PROVEN by decompilation)

All verbs are **top-level keys in one flat JSON object**, parsed by `AWS_receive_config_cb`
(`FUN_400f3a84`) → `IOTGW_Json2State` (`FUN_400fa850`). The scalar setters `nightLight`,
`nightLightOn`, `volume` are handled **inline** in `AWS_receive_config_cb` (via a handler table:
nightLight→cmd0, nightLightOn→cmd1, volume→cmd2); every other key is dispatched in
`IOTGW_Json2State`. You can combine multiple keys in a single published object. Send to `/config`
or `/commands/<anything>` — identical effect.

| Verb / key         | Payload (confirmed shape)                              | Notes |
| ------------------ | ----------------------------------------------------- | ----- |
| `volume`           | `{"volume": 3}`                                        | scalar, inline; number (else logs "vol is not a number!") |
| `nightLight`       | `{"nightLight": 6}`                                    | scalar, inline; brightness level |
| `nightLightOn`     | `{"nightLightOn": true}`                              | scalar, inline; bool |
| `alarmControl`     | `{"alarmControl":"snooze"}`                            | **string value**: `snooze` / `dismiss` / `mute` / `unmute` (matched by `strncmp`) |
| `remoteAudios`     | `{"remoteAudios":{"folderIdx":0,"fileIdx":0,"<op>":"play"\|"stop"}}` | nested object; select + play/stop asset |
| `setTime`          | `{"setTime":"...-...-%4d ..."}`                        | string; parsed by `sscanf` (year−1900, month−1 internally) |
| `setTimeZone`      | `{"setTimeZone":"<POSIX TZ>"}`                         | string; e.g. `CET-1CEST,M3.5.0,M10.5.0/3` |
| `timeZone`         | `{"timeZone":"<3 bytes>"}`                             | string; raw TZ id bytes |
| `24HourMode`       | `{"24HourMode": true}`                                | bool |
| `sleepTimerMins`   | `{"sleepTimerMins": 30}`                              | number |
| `guiColorIdx`      | `{"guiColorIdx": 0}`                                   | 0,1 or `255`(=custom → then `guiColorCutomHex0..3`) |
| `restart`          | `{"restart":1}`                                        | reboot (value must be `1`) |
| `restoreToDefault` | `{"restoreToDefault":1}`                               | ⚠ factory reset (value 1–3) — destructive |
| `alarms`           | `{"alarms":[ {…} ]}`                                   | array; see Config section below |
| `alarmSettings`    | `{"alarmSettings":{"volume":..,"alarmLight":..,"snoozeTime":..,"wakeUpTone*":..,"getUpTone*":..}}` | nested |
| `bedSignals`       | `{"bedSignals":[ {"time":..,"isSet":..,"routines":[ {"folderIndex":..,"fileIndex":..} ]} ]}` | array |

> Correction vs earlier catalogue: `snooze`/`dismiss`/`mute`/`unmute` are **string *values* of
> `alarmControl`**, not standalone keys; `volume`/`nightLight` are top-level keys (no `play`/`stop`
> top-level key — playback is via `remoteAudios`).

**Excluded on purpose** (do not wire these to automations): `otaURL` (`0x1dc14`) + `md5sum`
(`0x1dc00`) and `remotelog` (`0x1dc08`) — these are the remote-OTA / log-exfil control surface
that makes the stock cloud path dangerous (see `security-gaps.md`). With the firmware repointed at
your own broker only *you* can publish them, but there is no reason to expose them to HA.

Example (after confirming the shape on your device):

```bash
mosquitto_pub -h $H -t "/devices/$ID/commands/volume" $TLS -m '{"volume":3}'
mosquitto_pub -h $H -t "/devices/$ID/commands/alarmControl" $TLS -m '{"alarmControl":"dismiss"}'
```

> Subscribe to `/devices/$ID/state` while testing — the device reports back there, and the serial
> boot log echoes each parsed command, so you can confirm what landed.

## State topic — telemetry you can read in HA

`/devices/<id>/state` carries these keys (confirmed from `IOTGW_State2Json` `FUN_400f9b7c`):
`upTime`, `Ver`, `pluggedIn`, `BattCharge`, `battery`, `volume`, `nightLight`, `nightLightOn`,
`screenBrightness`, `24HourMode`, `sleepTimerMins`, `AP_MAC`, `MAC`, `serialNumber`, `certVer`,
`timeZone`/`timeZoneString`, `guiColorIdx`/`guiColorCutomHex0..3`, `isAlarmMute`,
`SDCardError`/`SDCardFail`, `SDBlockSectorRatio`, `pairingCode`/`pairingCodeTime`,
`beaconMajor`/`beaconMinor`/`beaconTxPower`, `playlistInfos{isDefault,ver,id,state}`,
`audioPlayer{isMusicPlaying,path}` (path `Bluetooth` when on BT), `bedSignals[]`, `alarms[]`,
`alarmSettings{}`, `alarmLogs[]`, plus the `feature*` flags.

> **There is no `rssi` field** — the firmware does not publish WiFi signal strength, so don't build
> an RSSI sensor (it would never populate). Good HA sensors: `battery`, `BattCharge`, `pluggedIn`,
> `volume`, `nightLight`, `nightLightOn` (all wired up in `../home-assistant/loftie.yaml`).

## Home Assistant

A ready-to-load MQTT package generalizing the README automation to the full command set lives at
[`../home-assistant/loftie.yaml`](../home-assistant/loftie.yaml). Set your `<id>` and broker there.
It deliberately omits `otaURL`/`remotelog`/`restoreToDefault` from the exposed controls.
