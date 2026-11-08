import { useEffect, useState } from 'react'
import type { FixItem } from './types'
import ScoreDetails from './ScoreDetails'
import KpiCards from './KpiCards'

function FixListPage() {
  const [items, setItems] = useState<FixItem[]>([])
  const [error, setError] = useState('')
  // Which tier to show; empty means all tiers
  const [tier, setTier] = useState('')
  // The finding whose score details are open; null means the panel is closed
  const [selected, setSelected] = useState<FixItem | null>(null)

  // Runs when the page opens, and again whenever the tier changes
  useEffect(() => {
    const url = tier ? `/api/fix-list?limit=25&tier=${tier}` : '/api/fix-list?limit=25'
    fetch(url)
      .then((res) => {
        if (!res.ok) throw new Error(`API returned ${res.status}`)
        return res.json()
      })
      .then(setItems)
      .catch((err) => setError(String(err)))
  }, [tier])

  return (
    <>
      <h1>Fix list</h1>
      <KpiCards />
      {error && <p>Can't load the fix list: {error}. Is the API running?</p>}
      <div className="filters">
        {['', 'Critical', 'High', 'Medium', 'Low'].map((t) => (
          <button
            key={t || 'all'}
            type="button"
            className={tier === t ? 'filter active' : 'filter'}
            onClick={() => setTier(t)}
          >
            {t || 'All'}
          </button>
        ))}
      </div>
      <table>
        <thead>
        <tr>
            <th>Asset</th>
            <th>Company ID</th>
            <th>Risk</th>
            <th>Score</th>
            <th>CVE</th>
            <th>Software</th>
            <th>KEV</th>
            <th>Confidence</th>
            <th>CISA deadline</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr
              key={item.finding_id}
              onClick={() => setSelected(item)}
              className={selected?.finding_id === item.finding_id ? 'row selected' : 'row'}
            >
              <td className="mono">{item.hostname}</td>
              <td className="mono">{item.asset_id ?? ''}</td>
              <td>
                <span className={`vhq-badge vhq-badge--${item.tier.toLowerCase()}`}>{item.tier}</span>
              </td>
              <td>{item.risk_score}</td>
              <td className="mono">{item.cve_id}</td>
              <td>{item.software}</td>
              <td>
                {item.in_kev ? 'Yes' : ''}
                {item.kev_past_due && (
                  <div className="kpi-note">Past due {item.kev_days_overdue}d</div>
                )}
              </td>
              <td>
                <span className={`chip chip--${item.confidence}`}>{item.confidence}</span>
              </td>
              <td>
                <div>{item.bod_label}</div>
                {item.bod_due_date && <div className="kpi-note">Due {item.bod_due_date}</div>}
                {item.bod_assumed.length > 0 && (
                  <div className="kpi-note">Assumed worst case</div>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      {selected && <ScoreDetails item={selected} onClose={() => setSelected(null)} />}
    </>
  )
}

export default FixListPage