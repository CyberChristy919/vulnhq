import { useEffect, useState } from 'react'

// One row from GET /api/patch-plan (matches PackagePlan in backend/app/patch_plan.py)
type PackagePlan = {
  package: string
  findings: number
  cves: string[]
  hosts: string[]
  versions: string[]
  kev_findings: number
  critical_findings: number
  risk_removed: number
}

function PatchPlanPage() {
  // One row per package, biggest priority first
  const [plan, setPlan] = useState<PackagePlan[]>([])
  // Plain-language reasons; the first line is the order rule
  const [why, setWhy] = useState<string[]>([])
  const [error, setError] = useState('')

  // Load the plan and the reasons once when the page opens
  useEffect(() => {
    fetch('/api/patch-plan')
      .then((res) => res.json())
      .then(setPlan)
      .catch((err) => setError(String(err)))

    // The reasons come wrapped as { why: [...] }, so pull out the list
    fetch('/api/patch-plan/why')
      .then((res) => res.json())
      .then((data) => setWhy(data.why))
      .catch((err) => setError(String(err)))
  }, [])

  return (
    <>
      <h1>Patch plan</h1>
      <p className="note">Which software to patch first, and why.</p>

      {error && <p>Can't load the patch plan: {error}. Is the API running?</p>}

       {/* Why this order: the first line is the ranking rule, the rest explain each package */}
       {why.length > 0 && (
        <>
          <h3>Why this order</h3>
          <p className="ask-why-rule">{why[0]}</p>
          <ol className="ask-why">
            {why.slice(1).map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ol>
        </>
      )}

      {/* One row per package, in patch order */}
      {plan.length > 0 && (
        <>
          <h3>Packages ({plan.length})</h3>
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Package</th>
                <th>Actively exploited</th>
                <th>Findings</th>
                <th>Critical</th>
                <th>Hosts</th>
                <th>Risk removed</th>
              </tr>
            </thead>
            <tbody>
              {plan.map((p, i) => (
                <tr key={p.package}>
                  <td>{i + 1}</td>
                  <td>{p.package}</td>
                  <td>{p.kev_findings}</td>
                  <td>{p.findings}</td>
                  <td>{p.critical_findings}</td>
                  <td>{p.hosts.length}</td>
                  <td>{p.risk_removed}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </>
  )
}

export default PatchPlanPage