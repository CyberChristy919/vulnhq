import type { Stats } from './types'


// Turns the /stats reply into Stats, or null if it isn't usable
export async function loadStats(res: Response): Promise<Stats | null> {
    // 1. If the reply is an error (res.ok is false), stop here
    if (!res.ok) return null

    try {
      const data = await res.json()
      // 2. Return data only if it has findings_by_tier, otherwise null
      return data && data.findings_by_tier ? data : null
    } catch {
      // 3. The body wasn't JSON, like "Internal Server Error"
      return null
    }
  }