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
            <th>#</th>
            <th>Tier</th>
            <th>Score</th>
            <th>CVE</th>
            <th>Asset</th>
            <th>Software</th>
            <th>KEV</th>
            <th>Confidence</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item, index) => (
            <tr
              key={item.finding_id}
              onClick={() => setSelected(item)}
              className={selected?.finding_id === item.finding_id ? 'row selected' : 'row'}
            >
              <td>{index + 1}</td>
              <td>
                <span className={`vhq-badge vhq-badge--${item.tier.toLowerCase()}`}>{item.tier}</span>
              </td>
              <td>{item.risk_score}</td>
              <td className="mono">{item.cve_id}</td>
              <td className="mono">{item.hostname}</td>
              <td>{item.software}</td>
              <td>{item.in_kev ? 'Yes' : ''}</td>
              <td>
                <span className={`chip chip--${item.confidence}`}>{item.confidence}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {selected && <ScoreDetails item={selected} onClose={() => setSelected(null)} />}
    </>
  )
}

export default FixListPage