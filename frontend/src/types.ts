// One row from the API's /fix-list (matches FixListItem in backend/app/schemas.py)
export type FixItem = {
    finding_id: number
    cve_id: string
    vulnerability_name: string | null
    hostname: string
    software: string | null
    in_kev: boolean
    cvss_score: number | null
    epss_score: number | null
    confidence: string
    match_note: string | null
    scan_age_days: number | null
    risk_score: number
    tier: string
    due_date: string
    days_remaining: number
    overdue: boolean
    kev_due_date: string | null
    kev_past_due: boolean
    kev_days_overdue: number | null
    bod_tier: number
    bod_label: string
    bod_due_date: string | null
    bod_forensic_triage: boolean
    bod_assumed: string[]// Points from each scoring factor, e.g. { kev: 25, epss: 18.6 }
    breakdown: Record<string, number>
  }

  // Numbers for the dashboard cards, from GET /stats
export type Stats = {
    assets: number
    assets_with_findings: number
    stale_scan_assets: number
    stale_scan_days: number
    open_findings: number
    kev_findings: number
    overdue_findings: number
    findings_by_tier: Record<string, number>
    kev_past_due_findings: number
    kev_past_due_assets: number
    oldest_days_overdue: number | null
  }

  // One asset from GET /assets, with its software and finding counts
export type Asset = {
    hostname: string
    asset_id: string | null
    asset_type: string | null
    department: string | null
    os: string | null
    os_version: string | null
    criticality: number
    internet_facing: boolean
    money_movement: string
    data_classification: string | null
    last_scan_date: string | null
    scan_age_days: number | null
    software: { name: string; version: string }[]
    open_findings: number
    kev_findings: number
    tiers: Record<string, number>
    top_score: number
  }
  