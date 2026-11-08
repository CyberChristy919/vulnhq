import { useEffect, useState } from 'react'

// One citation row behind an answer (matches evidence_row in backend/app/ask.py)
type Evidence = {
  asset_id: string | null
  hostname: string
  cve_id: string
  cvss: number | null
  source: string
  kev_due_date: string | null
  bod_due_date: string | null
  confidence: string
  nvd_url: string
}

// What POST /api/ask sends back (matches the Answer dataclass)
type AskResult = {
  intent: string | null
  answer: string
  evidence: Evidence[]
  notes: string[]
  suggestions: string[]
}

function AskPage() {
  // What the user is typing
  const [question, setQuestion] = useState('')
  // The 10 shortcut questions from the API
  const [examples, setExamples] = useState<string[]>([])
  const [result, setResult] = useState<AskResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  // Load the shortcut questions once when the page opens
  useEffect(() => {
    fetch('/api/ask/examples')
      .then((res) => res.json())
      .then(setExamples)
      .catch(() => setExamples([]))
  }, [])

  // Sends any question (typed or a shortcut) to the API
  function ask(q: string) {
    if (!q.trim()) return
    setQuestion(q)
    setLoading(true)
    setError('')
    fetch('/api/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question: q }),
    })
      .then((res) => {
        if (!res.ok) throw new Error(`API returned ${res.status}`)
        return res.json()
      })
      .then(setResult)
      .catch((err) => setError(String(err)))
      .finally(() => setLoading(false))
  }

  return (
    <>
      <h1>Ask VulnHQ</h1>
      <p className="note">
        Ask in your own words. Every answer is calculated from your inventory, CISA KEV and NVD data, with the
        findings behind it listed below.
      </p>

      {/* Pressing Enter or clicking Ask sends the question */}
      <form
        className="ask-form"
        onSubmit={(e) => {
          e.preventDefault()
          ask(question)
        }}
      >
        <input
          className="ask-input"
          type="text"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="e.g. Which Finance assets have actively exploited vulnerabilities?"
          maxLength={500}
        />
        <button type="submit" className="filter active" disabled={loading}>
          {loading ? 'Asking...' : 'Ask'}
        </button>
      </form>

      {/* Shortcut questions; clicking one asks it right away */}
      <div className="ask-examples">
        {examples.map((ex) => (
          <button key={ex} type="button" className="filter" onClick={() => ask(ex)}>
            {ex}
          </button>
        ))}
      </div>

      {error && <p>Can't get an answer: {error}. Is the API running?</p>}

      {result && (
        <div className="card ask-result">
          <h2>Answer</h2>
          <p className="ask-answer">{result.answer}</p>

          {/* Suggestions appear when the question wasn't understood or was ambiguous */}
          {result.intent && result.suggestions.length > 0 && (
            <div className="ask-examples">
              {result.suggestions.map((s) => (
                <button key={s} type="button" className="filter" onClick={() => ask(s)}>
                  {s}
                </button>
              ))}
            </div>
          )}

          {/* Caveats: uncertain matches, missing data, assumptions */}
          {result.notes.length > 0 && (
            <>
              <h3>What to know</h3>
              <ul className="ask-notes">
                {result.notes.map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            </>
          )}

          {/* Evidence: one row per finding, so the answer can be checked */}
          {result.evidence.length > 0 && (
            <>
              <h3>Evidence ({result.evidence.length} findings)</h3>
              <table>
                <thead>
                  <tr>
                    <th>Asset</th>
                    <th>Company ID</th>
                    <th>CVE</th>
                    <th>CVSS</th>
                    <th>Source</th>
                    <th>KEV due</th>
                    <th>CISA deadline</th>
                    <th>Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {result.evidence.map((e) => (
                    <tr key={`${e.hostname}-${e.cve_id}`}>
                      <td className="mono">{e.hostname}</td>
                      <td className="mono">{e.asset_id ?? ''}</td>
                      <td className="mono">
                        <a href={e.nvd_url} target="_blank" rel="noreferrer">
                          {e.cve_id}
                        </a>
                      </td>
                      <td>{e.cvss ?? 'None'}</td>
                      <td>{e.source}</td>
                      <td>{e.kev_due_date ?? ''}</td>
                      <td>{e.bod_due_date ?? ''}</td>
                      <td>
                        <span className={`chip chip--${e.confidence}`}>{e.confidence}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </div>
      )}
    </>
  )
}

export default AskPage