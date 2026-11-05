# Importing Assets

VulnHQ supports two JSON import formats. Run commands from the `backend` folder with the virtual environment active.

## 1. Asset Inventory with Installed Software

For inventories that list software and versions but no CVEs. VulnHQ checks each software version, plus the operating system, in two steps:

1. **Vetted rules** (`backend/data/vuln_rules.json`): hand-checked version ranges for high-impact CVEs.
2. **Live NVD lookup** for any product the rules don't cover. VulnHQ finds the product's NVD ID, asks NVD for CVEs affecting that version, then re-checks each version range itself. Results are cached in `backend/data/nvd_cache.json`.

To keep the fix list focused, NVD matches below CVSS 7.0 are skipped unless the CVE is in CISA KEV (change with `--min-cvss`).

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
| `nvd` | Matched by NVD's version data, not yet vendor-verified. If NVD only lists a wide range (e.g., 15.0 through 15.6), `match_note` says to confirm with the vendor advisory. |

### What the Import Reports

| Section | Meaning |
|---|---|
| Not checked | Software that can't be matched reliably by version, with the reason. Examples: Windows and Office (patched by KB, not by build number), Java (NVD uses update numbers), Linux distributions (patched per package), Cisco IOS (NVD ranges cover whole release families). |
| Needs review | Software with no match whose product appears in CISA KEV. A person should check the version against the vendor advisory. |

Nothing is silently skipped: every software item ends up with findings, under "Not checked," or with no known match.

## Adding Software During a Demo

Add one item to an existing asset and check it immediately:

```powershell
python -m scripts.add_software hr-app01.corp.local "Atlassian Confluence" 8.5.1
```

Or use `POST /assets/{hostname}/software` on the API docs page:

```json
{ "name": "Atlassian Confluence", "version": "8.5.1" }
```

If VulnHQ can't identify the product, add its NVD ID (vendor:product), found by searching [NVD's product dictionary](https://nvd.nist.gov/products/cpe/search):

```json
{ "name": "Payroll Portal", "version": "4.2", "cpe": "vendor:product" }
```

Common names and their NVD IDs are in `backend/data/cpe_aliases.json`.

### Before the Demo

```powershell
python -m scripts.check_nvd
```

Confirms this computer can reach NVD. Without an API key, NVD allows about 5 requests per 30 seconds. A free key ([request one from NVD](https://nvd.nist.gov/developers/request-an-api-key)) raises that to 50; put it in `backend\.env` as `NVD_API_KEY=...`. Importing the inventory once before the demo fills the cache, so repeat imports are instant and work offline.

If NVD can't be reached, the vetted rules still work, and items they don't cover are listed under "Not checked."

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

Products in the rules file use only the rules (no NVD lookup), so their results are stable and hand-checked. Add `"cpe"` to an item to force an NVD lookup as well.

## Private Data

`sample-data/private/` is in `.gitignore`. Keep customer, interview or other non-public files there.

## Starting a Demo Clean

```powershell
python -m scripts.reset_demo
```

Deletes applications, assets, software and findings. KEV and EPSS data are kept.
