import { useEffect, useState } from 'react'
import type { Stats } from './types'

function KpiCards() {
  const [stats, setStats] = useState<Stats | null>(null)

  // Runs once when the page opens: get the dashboard numbers
  useEffect(() => {
    fetch('/api/stats')
      .then((res) => res.json())
      .then(setStats)
      .catch(() => setStats(null))
  }, [])

  // Show nothing until the numbers arrive
  if (!stats) return null

  // One entry per card: title, number, and a short caption
  const cards = [
    {
      label: 'Critical open',
      value: stats.findings_by_tier.Critical ?? 0,
      note: 'Fix within 7 days',
      className: 'kpi kpi--critical',
    },
    {
      label: 'Known exploited',
      value: stats.kev_findings,
      note: 'On the CISA KEV list',
      className: 'kpi',
    },
    {
      label: 'Overdue',
      value: stats.overdue_findings,
      note: 'Past the fix-by date',
      className: 'kpi',
    },
    {
      label: 'Stale scans',
      value: stats.stale_scan_assets,
      note: `Assets not scanned in ${stats.stale_scan_days}+ days`,
      className: 'kpi',
    },
    {
      label: 'Open findings',
      value: stats.open_findings,
      note: `On ${stats.assets_with_findings} of ${stats.assets} assets`,
      className: 'kpi',
    },
  ]

  return (
    <section className="kpis">
      {cards.map((card) => (
        <div key={card.label} className={card.className}>
          <div className="kpi-label">{card.label}</div>
          <div className="kpi-value">{card.value}</div>
          <div className="kpi-note">{card.note}</div>
        </div>
      ))}
    </section>
  )
}

export default KpiCards