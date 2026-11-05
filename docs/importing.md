# Importing Assets

VulnHQ supports two JSON import formats. Run commands from the `backend` folder with the virtual environment active.

## 1. Asset Inventory with Installed Software

For inventories that list software and versions but no CVEs. VulnHQ matches each software version, plus the operating system, against `backend/data/vuln_rules.json` and creates findings automatically.

```powershell
python -m scripts.import_inventory ..\sample-data\private\inventory.json
python -m scripts.import_inventory ..\sample-data\private\inventory.json --context ..\sample-data\private\context.json
python -m scripts.load_epss
```

Or use `POST /import/inventory` on the API docs page.

```json
{
  "assets": [
    {
      "asset_id": "FIN-SRV-001",
      "hostname": "fin-app01.corp.local",
      "ip_address": "10.10.1.11",
      "asset_type": "server",
      "department": "Finance",
      "criticality": "critical",
      "os": "Windows Server 2019",
      "os_version": "10.0.17763",
      "last_scan_date": "2026-10-12",
      "installed_software": [{ "name": "Apache HTTP Server", "version": "2.4.49" }]
    }
  ]
}
```

| Criticality | Score input |
|---|---|
| `critical` | 5 |
| `high` | 4 |
| `medium` | 3 |
| `low` | 2 |

### Match Confidence

| Confidence | Meaning |
|---|---|
| `confirmed` | The installed version is inside the affected range |
| `conditional` | The version is affected, but exploitation also depends on configuration (e.g., a module or feature must be enabled). The finding's `match_note` explains what to verify. |

### Business Context File

Inventories rarely include internet exposure, money movement or data classification, which drive 25 of the 100 risk points. A context file adds them by hostname:

```json
{
  "assets": [
    { "hostname": "ops-vpn01.corp.local", "internet_facing": true },
    { "hostname": "fin-app01.corp.local", "money_movement": "outbound_payments", "data_classification": "restricted" }
  ]
}
```

Also available as `POST /import/context`.

## 2. Applications and Assets with Known CVEs

For data that already lists CVEs per asset. See `sample-data/demo-assets.json`.

```powershell
python -m scripts.import_assets ..\sample-data\demo-assets.json
```

Or use `POST /import/assets`.

## Vulnerability Rules

`backend/data/vuln_rules.json` maps software name and version ranges to CVEs. Each rule cites NVD or the vendor advisory. KEV status and EPSS come from the database, so they stay current after `load_kev` and `load_epss`.

Software with no matching rule produces no finding. That means "no known match in VulnHQ's rules," not "no vulnerabilities."

## Private Data

`sample-data/private/` is in `.gitignore`. Keep customer, interview or other non-public files there.

## Starting a Demo Clean

```powershell
python -m scripts.reset_demo
```

Deletes applications, assets, software and findings. KEV and EPSS data are kept.
