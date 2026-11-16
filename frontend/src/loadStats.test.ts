import { describe, expect, it } from 'vitest'
import { loadStats } from './loadStats'

// What GET /stats sends back, here with an empty database
const emptyStats = {
  assets: 0,
  assets_with_findings: 0,
  stale_scan_assets: 0,
  stale_scan_days: 90,
  open_findings: 0,
  kev_findings: 0,
  overdue_findings: 0,
  findings_by_tier: { Critical: 0, High: 0, Medium: 0, Low: 0 },
  kev_past_due_findings: 0,
  kev_past_due_assets: 0,
  oldest_days_overdue: null,
}

// Builds a fake reply, like the one fetch() gives KpiCards
function reply(body: string, status = 200) {
  return new Response(body, { status })
}

describe('loadStats', () => {
  it('returns the stats from a good reply', async () => {
    const stats = { ...emptyStats, open_findings: 12, findings_by_tier: { Critical: 3 } }
    expect(await loadStats(reply(JSON.stringify(stats)))).toEqual(stats)
  })

  it('returns the stats when the database is empty, so the cards show 0', async () => {
    expect(await loadStats(reply(JSON.stringify(emptyStats)))).toEqual(emptyStats)
  })

  it('returns null for an error reply with a JSON body', async () => {
    expect(await loadStats(reply('{"detail":"Not Found"}', 404))).toBeNull()
  })

  it('returns null for an error reply that is not JSON', async () => {
    expect(await loadStats(reply('Internal Server Error', 500))).toBeNull()
  })

  it('returns null when a 200 reply is missing findings_by_tier', async () => {
    expect(await loadStats(reply('{"detail":"Something went wrong"}'))).toBeNull()
  })

  it('returns null when a 200 reply is not JSON', async () => {
    expect(await loadStats(reply('<html>Proxy error</html>'))).toBeNull()
  })
})
