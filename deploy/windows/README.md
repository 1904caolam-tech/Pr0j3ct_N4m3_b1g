# Windows Server 2022 deployment

Status: **prepared, not executed on Server 2022.** Every command here was validated on
Windows 11 (same Python runtime, same console app); the install path is identical. The
differences that matter are listed below rather than hidden.

## What runs where

| Component | On Windows Server 2022? | Notes |
|---|---|---|
| P4B (API + UI + SQLite) | **yes, natively** | this guide |
| Docker Desktop | **no** | not supported on Windows Server; Linux images need WSL2, also unsupported |
| Wazuh manager | **no** | Linux only; keep the `siem` VM/box |
| Zeek / Suricata | no (practically) | Linux sensors; ship their logs to P4B |
| Nuclei / Trivy / Gitleaks / YARA | yes, Windows builds exist | put them on `PATH`; `p4b scan` was not tested on Windows |

So the realistic layout is: **P4B on the Windows server**, sensors and the Wazuh
manager on Linux, data arriving through HTTP ingest or a copied `alerts.json`.

## Can this box monitor live traffic?

**No, not by itself.** P4B contains no packet-capture code — it ingests files or HTTP
bodies that a sensor produced. Installing it on the Windows server gives you the API,
UI, correlation and coverage; it does not give you a sensor.

What *can* run on the Windows server:

| Option | Sees | Status |
|---|---|---|
| Wazuh agent for Windows | host telemetry: event log, FIM, processes, network connections | supported by Wazuh; sends to a Linux manager |
| Suricata Windows build + Npcap | packets on the server's own NIC, plus mirrored traffic if the switch port is a SPAN | same `eve.json` schema; `p4b ingest suricata` is untested on Windows |
| Zeek | — | no practical Windows build |
| P4B | nothing | no capture code |

A normal switched network does not deliver other hosts' unicast traffic to this NIC.
To see a whole segment you need a SPAN/mirror port, a TAP, or — in a Hyper-V lab —
port mirroring on the virtual switch feeding a sensor VM.

The supported shape is therefore:

```
Linux sensors (Suricata/Zeek) --HTTP or copied logs--> P4B on Windows
```

- real time: `deploy/wazuh/custom-p4b.py` posts each alert to
  `POST /api/v1/ingest/wazuh`;
- batch: copy `eve.json` / Zeek logs, then `p4b ingest <tool> <path>` on a schedule.
  There is no built-in ingest scheduler, so use Task Scheduler or cron for this path.

Making the Windows box itself a sensor would mean writing a capture adapter (pktmon
`etl2pcap` or Npcap) and a pcap parser; that does not exist today.

## Install

1. Install **Python 3.12 x64** from python.org and tick *Add python.exe to PATH*.
2. Put the repository at `C:\p4b` (clone or copy).
3. Elevated PowerShell:

   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass -Force
   cd C:\p4b
   .\deploy\windows\install-service.ps1 -InstallDir C:\p4b
   ```

   The script creates `.venv`, installs the package, writes `p4b.yaml` (bind
   `0.0.0.0:8080`, `require_auth: true`, SQLite under `C:\p4b\data`), initialises the
   schema, prints a bearer token **once**, and registers a startup task that runs
   `p4b serve` as `SYSTEM` with restart-on-failure.

   If the checkout lives somewhere else, add `-SourceDir D:\src\Pr0j3ct_N4m3__b1g`.
   Without elevation, or when IIS starts the process, use `-NoService` and run
   `.venv\Scripts\p4b.exe serve` yourself.

4. Open the port:

   ```powershell
   New-NetFirewallRule -DisplayName "P4B 8080" -Direction Inbound `
     -Protocol TCP -LocalPort 8080 -Action Allow
   ```

5. Verify:

   ```powershell
   .\deploy\windows\verify-windows.ps1 -InstallDir C:\p4b
   # add -NoService if you skipped the scheduled task
   ```

   With `require_auth: true`, reads over HTTP need a bearer token too — the check
   expects `401` on `/api/v1/summary` and passes. The UI's token bar stores it for
   writes.

## TLS and exposure

Do not publish 8080 directly to the internet. Two supported shapes:

- bind `api_host: 127.0.0.1` and reverse-proxy through **IIS ARR** (certificate on
  IIS), or
- keep `0.0.0.0` and put nginx/HAProxy in front.

`require_auth: true` is written by the installer; create more tokens with
`p4b token create --name <name> --scopes read,write`.

## Data and backup

- SQLite: `C:\p4b\data\p4b.db` (WAL). Stop the task, or run
  `sqlite3 p4b.db ".backup 'D:\backup\p4b.db'"`.
- Postgres instead: `pip install -e ".[postgres]"` (adds psycopg 3), then set
  `db_url: postgresql+psycopg://user:pass@host:5432/p4b`. The schema avoids
  SQLite-only constructs.

## Getting data in

- **Push** from a Linux Wazuh manager: `deploy/wazuh/custom-p4b.py` with
  `P4B_URL=http://<windows-server>:8080` and a write token.
- **Copy** `alerts.json` / `eve.json` / Zeek logs to a share, then run
  `p4b ingest <tool> <path>` from Task Scheduler or a `p4b job`.

## Uninstall

```powershell
.\deploy\windows\install-service.ps1 -Uninstall
```

Removes the scheduled task only; `C:\p4b\data` is kept.

## Known limits

- Task Scheduler is the service wrapper; there is no MSI and no Windows service
  binary. `verify-windows.ps1` reports the task state.
- `p4b scan` on Windows is untested (the binaries exist, the adapter path is the same).
- No IIS configuration is shipped; ARR is documented, not automated.
