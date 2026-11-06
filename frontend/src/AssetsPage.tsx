import { useEffect, useState } from 'react'
import type { Asset } from './types'

// Scans older than this many days are flagged as stale
const STALE_DAYS = 90

function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([])
  const [error, setError] = useState('')

  // Runs once when the page opens: get all assets, riskiest first
  useEffect(() => {
    fetch('/api/assets')
      .then((res) => {
        if (!res.ok) throw new Error(`API returned ${res.status}`)
        return res.json()
      })
      .then(setAssets)
      .catch((err) => setError(String(err)))
  }, [])

  return (
    <>
      <h1>Assets</h1>
      {error && <p>Can't load assets: {error}. Is the API running?</p>}
      <table>
        <thead>
          <tr>
            <th>Asset</th>
            <th>Department</th>
            <th>Criticality</th>
            <th>Internet-facing</th>
            <th>Money movement</th>
            <th>Last scan</th>
            <th>Software</th>
            <th>Open findings</th>
            <th>KEV</th>
            <th>Top score</th>
          </tr>
        </thead>
        <tbody>
          {assets.map((a) => (
            <tr key={a.hostname} className="row">
              <td className="mono">{a.hostname}</td>
              <td>{a.department ?? ''}</td>
              <td>{a.criticality} of 5</td>
              <td>{a.internet_facing ? 'Yes' : ''}</td>
              <td>{a.money_movement === 'none' ? '' : a.money_movement.replace('_', ' ')}</td>
              <td className={a.scan_age_days !== null && a.scan_age_days > STALE_DAYS ? 'stale' : ''}>
                {a.scan_age_days === null ? 'Never' : `${a.scan_age_days} days ago`}
              </td>
              <td>{a.software.length}</td>
              <td>{a.open_findings}</td>
              <td>{a.kev_findings || ''}</td>
              <td>{a.top_score}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  )
}

export default AssetsPage