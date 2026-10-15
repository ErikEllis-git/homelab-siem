# hpHDD worker — files that live on the laptop

hpHDD is the HP Pavilion 14 swarm worker (added 2026-10-14). These are the files this repo
authors for it; they are copied here exactly as deployed. Rosee-side counterparts live in
`scripts/` (`thermal_check.py`, `hdd_health.py`). Operational notes: vault `Cluster/Topology.md`.

| File | Installed at | Purpose |
|------|--------------|---------|
| `hphdd-thermal-sample.py` | `/usr/local/bin/` | writes one JSON thermal sample every 30 s (CPU package/cores, HDD, throttle counters, load, AC/battery) to `/var/log/hphdd-thermal.jsonl` |
| `hphdd-thermal.service` | `/etc/systemd/system/` | oneshot that runs the sampler (as root, so it can load `drivetemp`) |
| `hphdd-thermal.timer` | `/etc/systemd/system/` | fires the service every 30 s |
| `drivetemp.conf` | `/etc/modules-load.d/` | loads the `drivetemp` kernel module at boot (HDD temperature as a hwmon sensor) |
| `zz-server-wifi-powersave-off.conf` | `/etc/NetworkManager/conf.d/` | Wi-Fi power-save off; the `zz-` name must sort AFTER Ubuntu's `default-wifi-powersave-on.conf` (last file wins) |

## Install (as a user with sudo)

```bash
sudo cp hphdd-thermal-sample.py /usr/local/bin/
sudo cp hphdd-thermal.service hphdd-thermal.timer /etc/systemd/system/
sudo cp drivetemp.conf /etc/modules-load.d/
sudo cp zz-server-wifi-powersave-off.conf /etc/NetworkManager/conf.d/
sudo systemctl daemon-reload
sudo systemctl enable --now hphdd-thermal.timer
sudo systemctl reload NetworkManager
```

The unit runs the script through `python3` on purpose, so the file needs no executable bit
(this node's sudo allowlist has `tee` but not `chmod`).

## What the thermal pipeline can and cannot see

- Sampling is every 30 s. A heat spike shorter than that can fall between samples (measured:
  an 86 C, 12 s burst was recorded as 64 C). Sustained heat (the dangerous kind) is resolved
  fine, and the throttle counters in each sample are cumulative, so a real "CPU hit its limit"
  event is caught regardless of timing.
- The laptop exposes **no fan speed**. A failing fan or clogged airflow is inferred from
  "hot while idle" and from the idle-temperature **drift** check (needs ~2 days of history).
- Alerting and the 5-minute evaluation window live in `scripts/thermal_check.py` on rosee, not
  here, so a hot or hung laptop cannot silence its own alarm.
