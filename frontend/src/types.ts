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
    // Points from each scoring factor, e.g. { kev: 25, epss: 18.6 }
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
  }

  