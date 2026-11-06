import { useState } from 'react'
import type { Asset } from './types'

type Props = {
  asset: Asset
  onClose: () => void
  // Called after software is added, so the page can reload the assets
  onChanged: () => void
}

// What the API sends back after adding software
type AddResult = {
  summary: { findings_created: number; kev_findings: number; not_checked: string[]; needs_review: string[] }
  findings: { cve_id: string; name: string | null; in_kev: boolean; cvss_score: number | null }[]
}

function AssetDetails({ asset, onClose, onChanged }: Props) {
  // What's typed in the form
  const [name, setName] = useState('')
  const [version, setVersion] = useState('')
  const [cpe, setCpe] = useState('')
  // True while waiting for the API (NVD lookups can take a while)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<AddResult | null>(null)
  const [formError, setFormError] = useState('')

  // Skip the version if the OS name already ends with it ("RHEL 8.4" + "8.4")
  const os = asset.os && asset.os_version && !asset.os.endsWith(asset.os_version)
    ? `${asset.os} ${asset.os_version}`
    : asset.os ?? 'Unknown'

  async function addSoftware(event: React.FormEvent) {
    // Stop the browser from reloading the page when the form is submitted
    event.preventDefault()
    setBusy(true)
    setResult(null)
    setFormError('')
    try {
      const res = await fetch(`/api/assets/${encodeURIComponent(asset.hostname)}/software`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, version, cpe: cpe || null }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail ?? `API returned ${res.status}`)
      setResult(data)
      setName('')
      setVersion('')
      setCpe('')
      onChanged()
    } catch (err) {
      setFormError(String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <aside className="details">
      <button type="button" className="close" onClick={onClose} aria-label="Close">
        ×
      </button>
      <div className="mono">{asset.asset_id ?? ''}</div>
      <h2 className="mono">{asset.hostname}</h2>

      <h3>Details</h3>
      <dl>
        <dt>Department</dt>
        <dd>{asset.department ?? 'Unknown'}</dd>
        <dt>Type</dt>
        <dd>{asset.asset_type ?? 'Unknown'}</dd>
        <dt>OS</dt>
        <dd>{os}</dd>
        <dt>Criticality</dt>
        <dd>{asset.criticality} of 5</dd>
        <dt>Internet-facing</dt>
        <dd>{asset.internet_facing ? 'Yes' : 'No'}</dd>
        <dt>Money movement</dt>
        <dd>{asset.money_movement.replace('_', ' ')}</dd>
        <dt>Data</dt>
        <dd>{asset.data_classification ?? 'Unknown'}</dd>
        <dt>Open findings</dt>
        <dd>
          {asset.open_findings} ({asset.kev_findings} on KEV)
        </dd>
      </dl>

      <h3>Software ({asset.software.length})</h3>
      <ul className="software-list">
        {asset.software.map((s) => (
          <li key={`${s.name} ${s.version}`}>
            {s.name} <span className="mono">{s.version}</span>
          </li>
        ))}
      </ul>

      <h3>Add software</h3>
      <form className="add-form" onSubmit={addSoftware}>
        <label>
          Name
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Apache Tomcat" required />
        </label>
        <label>
          Version
          <input value={version} onChange={(e) => setVersion(e.target.value)} placeholder="9.0.30" required />
        </label>
        <label>
          NVD product ID (optional)
          <input value={cpe} onChange={(e) => setCpe(e.target.value)} placeholder="apache:tomcat" />
        </label>
        <button type="submit" className="primary" disabled={busy}>
          {busy ? 'Checking for CVEs...' : 'Add and check'}
        </button>
        {busy && <p className="note">Checking the rules and NVD. This can take up to a minute.</p>}
      </form>

      {formError && <p className="form-error">{formError}</p>}

      {result && (
        <div className="add-result">
          <p>
            <strong>{result.summary.findings_created}</strong> new findings,{' '}
            <strong>{result.summary.kev_findings}</strong> on KEV
          </p>
          <ul>
            {result.findings.slice(0, 10).map((f) => (
              <li key={f.cve_id}>
                <span className="mono">{f.cve_id}</span> CVSS {f.cvss_score ?? '?'}
                {f.in_kev && <span className="vhq-badge vhq-badge--critical">KEV</span>}
              </li>
            ))}
          </ul>
          {result.summary.not_checked.map((n) => (
            <p key={n} className="note">Not checked: {n}</p>
          ))}
          {result.summary.needs_review.map((n) => (
            <p key={n} className="note">Needs review: {n}</p>
          ))}
        </div>
      )}
    </aside>
  )
}

export default AssetDetails