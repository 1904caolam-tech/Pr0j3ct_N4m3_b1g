# Lab Guide — three VMs on VMware Workstation

> Status: approved · Date: 2026-11-13
> Target host: Windows, VMware Workstation, 16 GB RAM, 6 cores / 12 threads, 284 GB free on `D:`

This is the physical layout that the M4 milestone assumes. M1/M2/M3 run fine on a
single laptop with fixtures — the lab adds real sensors and real alerts.

## 1. Why three VMs

Each layer must be a separate machine for the data to be meaningful:

- The **sensor** must see traffic that is not its own.
- The **SIEM** must run agents on hosts other than itself.
- **P4B** must consume both without being either.

One VM would work technically and teaches nothing. Three is the smallest split that
matches `docs/ARCHITECTURE.md` §3.

## 2. Budget

| Resource | Total | Lab allocation | Host remaining |
|---|---|---|---|
| RAM | 15.7 GB | 7.5 GB (3 + 2 + 2.5) | ~8 GB |
| vCPU | 12 threads | 6 (2 per VM) | 6 |
| Disk (D:) | 284 GB free | 140 GB thin-provisioned | ~144 GB |

Hard rule: **never allocate more than 8 GB total to VMs.** Windows plus a browser
and an IDE already uses 5–6 GB; oversubscribing turns every demo into swap thrash.

## 3. Topology

```
                    Internet
                       │  NAT  (vmnet8)
                 ┌─────┴──────┐
                 │  Windows   │  192.168.56.1
                 └─────┬──────┘
   ────────────────────┼──────────────────────  192.168.56.0/24  (vmnet1, host-only)
        │              │                │
     .10            .20              .30
   [p4b]         [sensor]         [siem]
   P4B +          Zeek +          Wazuh
   scanners       Suricata        manager
```

| Host | IP (host-only) | NAT | Purpose |
|---|---|---|---|
| `p4b` | 192.168.56.10 | DHCP | P4B api/worker, scanner binaries, database |
| `sensor` | 192.168.56.20 | DHCP | Zeek + Suricata, writes logs to `/data` |
| `siem` | 192.168.56.30 | DHCP | Wazuh manager only, `/var/ossec/logs/alerts/alerts.json` |

Both NICs are needed: NAT for `apt`, host-only for lab traffic and machine-to-machine
transfer.

> **If the VMs are already on `VMnet8` (NAT) only.** That works, at two costs: DHCP
> changes addresses after a reboot, and the subnet (`192.168.x.0/24`) is chosen by
> VMware per host, so no address can be hardcoded. Two ways out:
>
> 1. **Add `VMnet1` as a second NIC** (recommended, ~2 min per VM): keep NAT for
>    packages, put every service on `192.168.56.x`.
> 2. **Stay single-NIC** and pin static addresses outside the NAT DHCP pool
>    (VMware's NAT pool is usually `.128`–`.254`, so `.10`/`.20`/`.30` are safe),
>    then replace `192.168.56.x` references below with your actual subnet.
>
> With option 2, add an egress block on the sensor (`ufw default deny outgoing`)
> so a replay cannot leak to the internet.
>
> **Host-to-VM access:** VMs reach each other over `192.168.56.x` even without a host
> adapter, but **the host cannot** — it has no address on that subnet until you tick
> *Connect a host virtual adapter to this network* for `VMnet1` in the Virtual Network
> Editor. Do that before M3, when you open the UI at `http://192.168.56.10:8080`.

## 4. VM specifications

| VM | OS | vCPU | RAM | Disk | Notes |
|---|---|---|---|---|---|
| `p4b` | Ubuntu Server 24.04 LTS | 2 | 3 GB | 60 GB | Docker Engine + compose |
| `sensor` | Ubuntu Server 24.04 LTS | 2 | 2 GB | 40 GB | Zeek + Suricata |
| `siem` | Ubuntu Server 24.04 LTS | 2 | 2.5 GB | 40 GB | Wazuh **manager only** |

Deliberate omission: **no Wazuh indexer and no Wazuh dashboard.** They cost 6–8 GB
and add nothing that P4B needs. The manager alone writes `alerts.json`, which is the
only contract P4B cares about. If you later want the dashboard, run it on demand in a
separate VM and shut it down afterwards.

## 5. Host preparation

1. **Decide on Hyper-V.** It is currently enabled. VMware then runs through WHPX and
   is roughly 20–30% slower. If you do not need Docker Desktop or WSL2 on the host:
   ```powershell
   bcdedit /set hypervisorlaunchtype off
   # reboot; re-enable with: bcdedit /set hypervisorlaunchtype auto
   ```
2. **Virtual Network Editor** (`vmnetcfg.exe`, run as administrator):
   - `VMnet1` → host-only → subnet `192.168.56.0/24` → **disable local DHCP**
     (static IPs avoid the classic "my lab IP changed" afternoon).
   - `VMnet8` → NAT (default settings are fine).
   - Already using NAT only? See the note in §3 before adding a second NIC.
3. **Folder layout** on `D:`:
   ```
   D:\lab\vm\p4b\      D:\lab\vm\sensor\      D:\lab\vm\siem\
   D:\lab\iso\         D:\lab\snapshots\
   ```
4. **Base image once.** Install Ubuntu Server 24.04 minimal into `p4b`, then:
   ```bash
   sudo apt update && sudo apt install -y openssh-server open-vm-tools htop rsync curl
   sudo useradd -m -s /bin/bash lab && sudo usermod -aG sudo lab
   # copy your SSH public key
   ssh-copy-id lab@192.168.56.10
   ```
   Snapshot this clean state as `base`. Clone it twice for `sensor` and `siem`, then
   change hostname/IP on each clone (that is faster than three installs).

## 6. Build order

```
phase 0  host prep (networks, folders, base image)          ~30 min
phase 1  p4b VM: docker, repo, p4b init, fixtures ingest    ~30 min
phase 2  sensor VM: zeek, suricata, tcpreplay               ~45 min
phase 3  siem VM: wazuh manager, one agent                  ~45 min
phase 4  wiring: rsync pull into p4b, end-to-end check      ~20 min
```

Phases 1–3 can be executed by hand (commands below) or by the scripts in
`deploy/lab/`, which do the same thing with preflight checks:

```bash
sudo PROJECT_DIR=/home/lab/p4b bash deploy/lab/bootstrap-p4b.sh
sudo bash deploy/lab/bootstrap-sensor.sh
sudo WAZUH_TAG=4.9.2 bash deploy/lab/bootstrap-siem.sh
sudo install -m 0755 deploy/lab/pull-logs.sh /usr/local/bin/p4b-pull-logs
```

The scripts are **untested until you run them on a real VM** — they are written to
fail loudly (`set -euo pipefail`, explicit checks) rather than half-succeed.

### Phase 1 — `p4b` VM

```bash
# docker
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker lab

# project (copy or clone; the repo has no remote yet, so tar/scp is fine)
scp -r D:\Pr0j3ct_N4m3__b1g\* lab@192.168.56.10:~/p4b/
cd ~/p4b
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

p4b init
p4b doctor
p4b ingest wazuh demo/fixtures/wazuh/alerts.json
p4b findings
```

Expected: `p4b doctor` shows the scanners only if you install them; the three
content tools stay `no` until you clone the rule repositories.

### Phase 2 — `sensor` VM

```bash
# Zeek (OpenSUSE OBS repo for the matching Ubuntu release)
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' \
  | sudo tee /etc/apt/sources.list.d/zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key \
  | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/zeek.gpg >/dev/null
sudo apt update && sudo apt install -y zeek

# Suricata
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt update && sudo apt install -y suricata

# traffic replay (this is how you get deterministic alerts without a victim VM)
sudo apt install -y tcpreplay tcpdump

sudo mkdir -p /data/zeek /data/suricata
```

Run the sensors on the host-only interface (`ip -br link` to find the name, usually
`ens37`):

```bash
sudo suricata -i ens37 -D
sudo zeek -i ens37 local
```

> **Important — how traffic becomes visible.** VMware's host-only network behaves like
> a switch; a third VM will not reliably see unicast traffic between two other VMs.
> Do not fight it. Replay instead:
> ```bash
> sudo tcpreplay -i ens37 sample.pcap
> ```
> Frames that `tcpreplay` writes to `ens37` are captured by both Zeek and Suricata
> listening on that interface. This is deterministic, repeatable, and needs no
> attacker VM.

Logs to collect:

| Tool | Path |
|---|---|
| Zeek | `/opt/zeek/logs/current/*.log` |
| Suricata | `/var/log/suricata/eve.json` |

### Phase 3 — `siem` VM

Wazuh manager only — no indexer, no dashboard:

```bash
sudo apt install -y docker.io
sudo mkdir -p /data/wazuh/{logs,etc,queue}
docker run -d --name wazuh-manager --restart unless-stopped \
  -p 1514:1514/tcp -p 1515:1515/tcp -p 55000:55000/tcp \
  -v /data/wazuh/logs:/var/ossec/logs \
  -v /data/wazuh/etc:/var/ossec/etc \
  -v /data/wazuh/queue:/var/ossec/queue \
  -e INDEXER_URL= -e FILEBEAT_ENABLED=false \
  wazuh/wazuh-manager:4.9.2
```

Pin the tag you actually deploy and record it in `tool_health`; do not use `latest`.

Install one agent on the `p4b` VM (or on `sensor`) so alerts are generated by a host
that is not the manager:

```bash
# on the agent host, following the official Wazuh agent guide
# manager address: 192.168.56.30
```

Alerts land in `/data/wazuh/logs/alerts/alerts.json`.

### Phase 4 — wiring

Pull, do not mount. VMware shared folders (HGFS) are slow and produce permission
errors with Zeek's log writer.

```bash
# on p4b, every minute via systemd timer or cron
rsync -az --delete lab@192.168.56.20:/opt/zeek/logs/current/ /data/ingest/zeek/
rsync -az lab@192.168.56.20:/var/log/suricata/eve.json       /data/ingest/suricata/
rsync -az lab@192.168.56.30:/data/wazuh/logs/alerts/alerts.json /data/ingest/wazuh/

p4b ingest zeek     /data/ingest/zeek
p4b ingest suricata /data/ingest/suricata/eve.json
p4b ingest wazuh    /data/ingest/wazuh/alerts.json
```

`--delete` on the Zeek directory is intentional: `current/` rotates, and stale files
would be re-read forever.

### Push instead of pull (optional)

Wazuh can ship alerts the moment they fire, through `integratord`. Copy
`deploy/wazuh/custom-p4b.py` into the manager and add the integration block from
[deploy/wazuh/README.md](../deploy/wazuh/README.md). The script posts one alert per
invocation to `POST /api/v1/ingest/wazuh`; the endpoint is idempotent, so a retry or a
duplicate alert only increments `count`.

Both paths produce identical findings — choose one. Pull is simpler; push is real
time.

### Verify the lab

```bash
sudo install -m 0755 deploy/lab/verify-lab.sh /usr/local/bin/p4b-verify-lab
p4b-verify-lab
```

It checks: `p4b` installed, database initialised, each ingest source present and
parsing, findings stored, re-ingest idempotent, and that the asset graph has fewer
assets than findings. Exit code is non-zero if anything fails.

HTTP push (the M4 alternative for Wazuh `integratord`) is documented in
`docs/ARCHITECTURE.md` §6.1; it is optional because rsync already works.

## 7. Ports

| From | To | Port | Purpose |
|---|---|---|---|
| `p4b` | `sensor` | 22/tcp | rsync over SSH |
| `p4b` | `siem` | 22/tcp | rsync over SSH |
| agent | `siem` | 1514/tcp | Wazuh agent events |
| agent | `siem` | 1515/tcp | enrollment |
| browser | `p4b` | 8080/tcp | P4B API/UI (M3) |

## 8. Snapshots

| Name | When | Why |
|---|---|---|
| `base` | clean OS + SSH + tools | rebuild any VM in seconds |
| `sensor-ready` | Zeek/Suricata run, one pcap replayed | sensor experiments can be reverted |
| `siem-ready` | manager up, one agent enrolled | avoid re-enrolling agents |
| `m4-green` | end-to-end ingest verified | the state you demo from |

Take `m4-green` **before** running offensive tests. Always revert after.

## 9. Verification checklist

Run these in order; each one has an observable result.

| # | Command (on `p4b`) | Expected |
|---|---|---|
| 1 | `p4b doctor` | at least `zeek`, `suricata`, `wazuh` resolvable if the agents are installed; content tools `no` until cloned |
| 2 | `p4b ingest wazuh demo/fixtures/wazuh/alerts.json` | `parsed 2 created 2` |
| 3 | `p4b ingest suricata /data/ingest/suricata/eve.json` | `alert=N` with N ≥ 1 after a replay |
| 4 | `p4b ingest zeek /data/ingest/zeek` | `notice ≥ 1` after a replay that triggers a notice |
| 5 | `p4b findings --source zeek` | at least one row with an asset key and ATT&CK (if mapped) |
| 6 | re-run step 2 | `created 0 merged 2` — idempotency holds |
| 7 | `sqlite3 data/p4b.db "select count(*) from assets"` | fewer assets than findings (same host merged) |

## 10. Gotchas

1. **Zeek log directory grows fast.** `conn.log` at 1k pps can reach hundreds of MB per
   hour. Rotate with `zeekctl` defaults and keep `--delete` on rsync.
2. **Clock skew breaks correlation.** The validation window is ±15 min, but keep all
   three VMs on NTP (`timedatectl set-ntp true`) — otherwise this is the bug you will
   spend an evening on.
3. **Clone changes identity.** After cloning the base image, update
   `/etc/hostname`, `/etc/hosts`, and the netplan file, otherwise all three VMs answer
   as `p4b`.
4. **Interface names differ per VM.** Always check `ip -br link` before writing
   `-i ens37` into a service file.
5. **Do not expose the lab.** Host-only `192.168.56.0/24` only; NAT is for packages.
   Never port-forward the Wazuh API or P4B to the internet.
6. **Suricata needs rules.** A fresh install ships with a minimal set; install
   `suricata-update` and run it once, or replays will produce zero alerts.

## 11. What "M4 done" means

- A pcap replayed on `sensor` produces Suricata and Zeek findings in P4B.
- An action on the agent host produces a Wazuh alert in P4B.
- `p4b coverage` shows the technique with `observed = true`.
- Re-running the same replay does not increase finding counts (only `count`).
- `p4b report` includes the three sources with non-zero findings.
