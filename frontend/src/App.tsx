import { useState } from 'react'
import FixListPage from './FixListPage'
import AssetsPage from './AssetsPage'

// The pages in the sidebar. Add a new page here first.
const PAGES = ['Fix list', 'Assets']

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
      </main>
    </div>
  )
}

export default App