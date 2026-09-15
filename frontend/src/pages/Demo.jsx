import { useState } from 'react'
import { api } from '../services/api.js'
import { PageHeader } from '../components/PageHeader.jsx'

const TESTS = [
  {
    id: 'end-to-end',
    label: 'End-to-end flow',
    run: () => api.tests.endToEnd(),
  },
  {
    id: 'different-recipients',
    label: 'Different recipients receive different watermarks',
    run: () => api.tests.differentRecipients(),
  },
  {
    id: 'attribution',
    label: 'A leaked copy is attributed to the right recipient',
    run: () => api.tests.attribution(),
  },
  {
    id: 'signature-tampering',
    label: 'Signature tampering is detected',
    run: () => api.tests.signatureTampering(),
  },
  {
    id: 'ledger-tampering',
    label: 'Ledger tampering is detected',
    run: () => api.tests.ledgerTampering(),
  },
  {
    id: 'fake-watermark',
    label: 'A fake watermark is rejected',
    run: () => api.tests.fakeWatermark(),
  },
]

function formatValue(value) {
  if (value === undefined || value === null) return 'Not reported'
  if (typeof value === 'string') return value
  if (typeof value === 'boolean' || typeof value === 'number') return String(value)
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

export function Demo({ onDemoComplete }) {
  const [entries, setEntries] = useState({})
  const running = TESTS.some((test) => entries[test.id] && entries[test.id].status === 'running')

  const runTest = async (test) => {
    setEntries((prev) => ({ ...prev, [test.id]: { status: 'running' } }))
    try {
      const result = await test.run()
      setEntries((prev) => ({ ...prev, [test.id]: { status: 'done', result } }))
    } catch (err) {
      setEntries((prev) => ({ ...prev, [test.id]: { status: 'error', error: err.message } }))
    } finally {
      if (onDemoComplete) onDemoComplete()
    }
  }

  const runAll = async () => {
    for (const test of TESTS) {
      await runTest(test)
    }
  }

  return (
    <div>
      <PageHeader
        title="Security demos"
        description="Run individual checks or the full set against the live backend."
        action={
          <button type="button" className="btn primary" onClick={runAll} disabled={running}>
            {running ? 'Running...' : 'Run all'}
          </button>
        }
      />

      {TESTS.map((test) => {
        const entry = entries[test.id] || { status: 'idle' }
        return (
          <section className="card" key={test.id}>
            <div className="card-head">
              <h3>{test.label}</h3>
              <div className="row-actions">
                {entry.status === 'done' && (
                  <span className={entry.result.passed ? 'badge ok' : 'badge bad'}>
                    {entry.result.passed ? 'Passed' : 'Failed'}
                  </span>
                )}
                <button
                  type="button"
                  className="btn small"
                  disabled={running || entry.status === 'running'}
                  onClick={() => runTest(test)}
                >
                  {entry.status === 'running' ? 'Running...' : 'Run'}
                </button>
              </div>
            </div>

            {entry.status === 'idle' && <p className="muted">Not run yet.</p>}
            {entry.status === 'running' && <p className="muted">Running...</p>}
            {entry.status === 'error' && (
              <p className="error" role="alert">
                {entry.error}
              </p>
            )}
            {entry.status === 'done' && (
              <dl className="kv">
                <dt>Test</dt>
                <dd className="mono">{entry.result.test || test.id}</dd>
                <dt>Expected</dt>
                <dd>{formatValue(entry.result.expected)}</dd>
                {entry.result.actual !== undefined && (
                  <>
                    <dt>Observed</dt>
                    <dd>{formatValue(entry.result.actual)}</dd>
                  </>
                )}
              </dl>
            )}
          </section>
        )
      })}
    </div>
  )
}
