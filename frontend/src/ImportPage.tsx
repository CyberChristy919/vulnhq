import { useState } from 'react'

// What the API sends back after importing an inventory file
type InventoryResult = {
  assets_created: number
  assets_updated: number
  software_items: number
  findings_created: number
  kev_findings: number
  conditional_findings: number
  nvd_findings: number
  not_checked: string[]
  needs_review: string[]
}

// What the API sends back after importing a business context file
type ContextResult = {
  assets_updated: number
  not_found: string[]
}

// Reads a JSON file from your computer and sends it to the API
async function postFile(url: string, file: File) {
  // Remove the invisible marker some Windows editors put at the start of a file
  const text = (await file.text()).replace(/^\uFEFF/, '')
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: text,
  })
  const data = await res.json()
  if (!res.ok) {
    // FastAPI sends a list of problems when the file isn't in the expected format
    const detail = typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail)
    throw new Error(detail)
  }
  return data
}

function ImportPage() {
  // The files picked in each box
  const [inventoryFile, setInventoryFile] = useState<File | null>(null)
  const [contextFile, setContextFile] = useState<File | null>(null)
  // Which import is running: 'inventory', 'context', or '' for none
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const [inventory, setInventory] = useState<InventoryResult | null>(null)
  const [context, setContext] = useState<ContextResult | null>(null)

  async function importInventory() {
    if (!inventoryFile) return
    setBusy('inventory')
    setError('')
    setInventory(null)
    try {
        // Check the file before sending it: count the software on every asset
        const parsed = JSON.parse((await inventoryFile.text()).replace(/^\uFEFF/, ''))
        const softwareCount = (parsed.assets ?? []).reduce(
          (total: number, a: { installed_software?: unknown[] }) => total + (a.installed_software?.length ?? 0),
          0,
        )
        if (softwareCount === 0) {
          throw new Error('This file has no installed_software lists, so nothing can be checked for CVEs. Is it the right file?')
        }
        setInventory(await postFile('/api/import/inventory', inventoryFile))
    } catch (err) {
      setError(`Inventory import failed: ${err}`)
    } finally {
      setBusy('')
    }
  }

  async function importContext() {
    if (!contextFile) return
    setBusy('context')
    setError('')
    setContext(null)
    try {
      setContext(await postFile('/api/import/context', contextFile))
    } catch (err) {
      setError(`Context import failed: ${err}`)
    } finally {
      setBusy('')
    }
  }

  return (
    <>
      <h1>Import</h1>
      <p className="lede">Two files are all VulnHQ needs: what you own, and why it matters to the business.</p>
      {error && <p className="form-error">{error}</p>}

      <section className="card">
        <h2>1. Asset inventory</h2>
        {/* Plain-language explanation of the file, for people new to the app */}
        <div className="note">
          <p><strong>What it is:</strong> the list of company devices and the software installed on each one, like a parts list.</p>
          <p><strong>What's in it:</strong> asset ID, hostname, department, how critical the asset is, last scan date, and each software name and version.</p>
          <p><strong>What VulnHQ does with it:</strong> checks every software version against CISA's list of flaws attackers are actively using (KEV), then the National Vulnerability Database (NVD), and turns each match into a finding.</p>
        </div>
        <input type="file" accept=".json" onChange={(e) => setInventoryFile(e.target.files?.[0] ?? null)} />
        <button type="button" className="primary" disabled={!inventoryFile || busy !== ''} onClick={importInventory}>
          {busy === 'inventory' ? 'Importing and checking for CVEs...' : 'Import inventory'}
        </button>
        {busy === 'inventory' && <p className="note">NVD lookups can take a few minutes without an API key.</p>}

        {inventory && (
          <div className="add-result">
            <p>
              <strong>{inventory.assets_created}</strong> assets created, <strong>{inventory.assets_updated}</strong> updated,{' '}
              <strong>{inventory.software_items}</strong> software items checked
            </p>
            <p>
              <strong>{inventory.findings_created}</strong> findings: <strong>{inventory.kev_findings}</strong> on KEV,{' '}
              <strong>{inventory.conditional_findings}</strong> need a configuration check,{' '}
              <strong>{inventory.nvd_findings}</strong> from NVD
            </p>
            {inventory.not_checked.length > 0 && (
            <details>
                <summary>Not checked ({inventory.not_checked.length})</summary>
                <ul>
                  {inventory.not_checked.map((n) => (
                    <li key={n}>{n}</li>
                  ))}
                </ul>
              </details>
            )}
            {inventory.needs_review.length > 0 && (
              <details>
                <summary>Needs review ({inventory.needs_review.length})</summary>
                <ul>
                  {inventory.needs_review.map((n) => (
                    <li key={n}>{n}</li>
                  ))}
                </ul>
              </details>
            )}
          </div>
        )}
      </section>

      <section className="card">
        <h2>2. Business context</h2>
        {/* Plain-language explanation of the file, for people new to the app */}
        <div className="note">
          <p><strong>What it is:</strong> what each asset means to the business, matched by hostname. Import the inventory first.</p>
          <p><strong>What's in it:</strong> whether the asset can be reached from the internet, whether it moves money, and how sensitive its data is.</p>
          <p><strong>What VulnHQ does with it:</strong> moves findings on internet-facing, payment and sensitive-data systems up the fix list, so the same flaw ranks higher where it could hurt the business most.</p>
        </div>
        <input type="file" accept=".json" onChange={(e) => setContextFile(e.target.files?.[0] ?? null)} />
        <button type="button" className="primary" disabled={!contextFile || busy !== ''} onClick={importContext}>
          {busy === 'context' ? 'Importing...' : 'Import context'}
        </button>

        {context && (
          <div className="add-result">
            <p>
              <strong>{context.assets_updated}</strong> assets updated
            </p>
            {context.not_found.length > 0 && (
              <p className="note">Not found (import these assets first): {context.not_found.join(', ')}</p>
            )}
          </div>
        )}
      </section>
    </>
  )
}

export default ImportPage