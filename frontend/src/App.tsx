import { useState } from 'react'
import FixListPage from './FixListPage'
import AssetsPage from './AssetsPage'
import ImportPage from './ImportPage'
import AskPage from './AskPage'
import PatchPlanPage from './PatchPlanPage'

// The pages in the sidebar. Add a new page here first.
const PAGES = ['Ask', 'Fix list', 'Patch plan', 'Assets', 'Import']

function App() {
  // Which page is showing right now
  const [page, setPage] = useState('Fix list')

  return (
    <div className="layout">
      <nav className="sidebar">
        <div className="brand">VulnHQ</div>
        {PAGES.map((p) => (
          <button
            key={p}
            type="button"
            className={page === p ? 'nav-item active' : 'nav-item'}
            onClick={() => setPage(p)}
          >
            {p}
          </button>
        ))}
      </nav>
      <main>
        {page === 'Fix list' && <FixListPage />}
        {page === 'Assets' && <AssetsPage />}
        {page === 'Import' && <ImportPage />}
        {page === 'Ask' && <AskPage />}
        {page === 'Patch plan' && <PatchPlanPage />}
      </main>
    </div>
  )
}

export default App