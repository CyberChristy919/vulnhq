import type { FixItem } from './types'

// Each scoring factor: key from the API, label, and maximum points (see docs/scoring.md)
const FACTORS: [string, string, number][] = [
  ['kev', 'On CISA KEV list', 25],
  ['epss', 'EPSS exploit likelihood', 20],
  ['ransomware', 'Used in ransomware', 10],
  ['criticality', 'Asset criticality', 20],
  ['internet_facing', 'Internet-facing', 10],
  ['money_movement', 'Money movement', 10],
  ['sensitive_data', 'Sensitive data', 5],
]

type Props = {
  item: FixItem
  onClose: () => void
}

function ScoreDetails({ item, onClose }: Props) {
  const epss =
    item.epss_score != null
      ? `${(item.epss_score * 100).toFixed(1)}% chance of exploitation in the next 30 days`
      : 'No score'

  return (
    <aside className="details" aria-label="Score details">
      <button type="button" className="close" onClick={onClose} aria-label="Close">
        ×
      </button>
      <p className="mono">{item.cve_id}</p>
      <h2>{item.vulnerability_name}</h2>
      <p>
        <span className={`vhq-badge vhq-badge--${item.tier.toLowerCase()}`}>{item.tier}</span>{' '}
        Score <strong>{item.risk_score}</strong> of 100, fix by {item.due_date}
      </p>

      <h3>Why it ranks here</h3>
      {FACTORS.map(([key, label, max]) => {
        const points = item.breakdown[key] ?? 0
        return (
          <div className="factor" key={key}>
            <div className="factor-label">
              <span>{label}</span>
              <span>
                {points} / {max}
              </span>
            </div>
            <div className="bar">
              <div className="bar-fill" style={{ width: `${(points / max) * 100}%` }} />
            </div>
          </div>
        )
      })}

      <h3>Details</h3>
      <dl>
        <dt>Asset</dt>
        <dd className="mono">{item.hostname}</dd>
        <dt>Software</dt>
        <dd>{item.software ?? 'Not recorded'}</dd>
        <dt>CVSS</dt>
        <dd>{item.cvss_score ?? 'Not scored'}</dd>
        <dt>EPSS</dt>
        <dd>{epss}</dd>
        <dt>Confidence</dt>
        <dd>{item.confidence}</dd>
        <dt>Last scan</dt>
        <dd>{item.scan_age_days != null ? `${item.scan_age_days} days ago` : 'Unknown'}</dd>
      </dl>
      {item.match_note && <p className="note">{item.match_note}</p>}
      <a href={`https://nvd.nist.gov/vuln/detail/${item.cve_id}`} target="_blank" rel="noreferrer">
        View on NVD
      </a>
    </aside>
  )
}

export default ScoreDetails