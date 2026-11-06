import { useEffect, useState } from 'react'

// One row from the API's /fix-list
type FixItem = {
  finding_id: number
  cve_id: string
  hostname: string
  software: string | null
  in_kev: boolean
  risk_score: number
  tier: string
}

function App() {
  const [items, setItems] = useState<FixItem[]>([])
  const [error, setError] = useState('')

  // Runs once when the page opens: ask the API for the top 10 findings
  useEffect(() => {
    fetch('/api/fix-list?limit=10')
      .then((res) => {
        if (!res.ok) throw new Error(`API returned ${res.status}`)
        return res.json()
      })
      .then(setItems)
      .catch((err) => setError(String(err)))
  }, [])

  return (
    <main>
      <h1>VulnHQ fix list</h1>
      {error && <p>Can't load the fix list: {error}. Is the API running?</p>}
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
          </tr>
        </thead>
        <tbody>
          {items.map((item, index) => (
            <tr key={item.finding_id}>
              <td>{index + 1}</td>
              <td>
  <span className={`vhq-badge vhq-badge--${item.tier.toLowerCase()}`}>{item.tier}</span>
</td>
              <td>{item.risk_score}</td>
              <td className="mono">{item.cve_id}</td>
              <td className="mono">{item.hostname}</td>
              <td>{item.software}</td>
              <td>{item.in_kev ? 'Yes' : ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </main>
  )
}

export default App