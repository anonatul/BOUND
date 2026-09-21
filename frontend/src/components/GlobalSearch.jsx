import { useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../services/api.js'
import { useDebouncedValue } from '../hooks/useDebouncedValue.js'
import { FileTypeBadge } from './FileTypeBadge.jsx'

const MIN_QUERY = 2
const GROUP_LIMIT = 5

export function GlobalSearch({ onSelect }) {
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)
  const [data, setData] = useState({ documents: [], recipients: [], entries: [] })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const wrapRef = useRef(null)

  const debounced = useDebouncedValue(query.trim(), 250)

  useEffect(() => {
    function handlePointerDown(event) {
      if (wrapRef.current && !wrapRef.current.contains(event.target)) setOpen(false)
    }
    document.addEventListener('mousedown', handlePointerDown)
    return () => document.removeEventListener('mousedown', handlePointerDown)
  }, [])

  useEffect(() => {
    if (debounced.length < MIN_QUERY) {
      setData({ documents: [], recipients: [], entries: [] })
      setError('')
      setLoading(false)
      return undefined
    }

    let active = true
    setLoading(true)
    setError('')

    Promise.allSettled([api.documents(), api.recipients(), api.ledger()]).then((results) => {
      if (!active) return
      const [documents, recipients, ledger] = results
      const failed = results.filter((result) => result.status === 'rejected').length
      setData({
        documents: documents.status === 'fulfilled' ? documents.value.documents || [] : [],
        recipients: recipients.status === 'fulfilled' ? recipients.value.recipients || [] : [],
        entries: ledger.status === 'fulfilled' ? ledger.value.entries || [] : [],
      })
      setError(failed > 0 ? 'Some results could not be loaded.' : '')
      setLoading(false)
    })

    return () => {
      active = false
    }
  }, [debounced])

  const results = useMemo(() => {
    const needle = debounced.toLowerCase()
    if (needle.length < MIN_QUERY) {
      return { documents: [], recipients: [], entries: [] }
    }

    const documents = data.documents
      .filter((doc) =>
        [
          doc.original_filename,
          doc.document_id,
          doc.document_hash,
          (doc.authorized_recipients || []).join(' '),
        ].some((value) => String(value || '').toLowerCase().includes(needle))
      )
      .slice(0, GROUP_LIMIT)

    const recipients = data.recipients
      .filter((person) =>
        [
          person.display_name,
          person.recipient_id,
          person.mlkem_fingerprint,
          person.mldsa_fingerprint,
        ].some((value) => String(value || '').toLowerCase().includes(needle))
      )
      .slice(0, GROUP_LIMIT)

    const entries = data.entries
      .filter((entry) =>
        [entry.watermark_id, entry.session_id, entry.document_id, entry.recipient_id].some((value) =>
          String(value || '').toLowerCase().includes(needle)
        )
      )
      .slice(0, GROUP_LIMIT)

    return { documents, recipients, entries }
  }, [debounced, data])

  const showPanel = open && query.trim().length >= MIN_QUERY
  const hasResults =
    results.documents.length + results.recipients.length + results.entries.length > 0

  const pick = (result) => {
    setQuery('')
    setOpen(false)
    onSelect(result)
  }

  return (
    <div className="global-search" ref={wrapRef}>
      <input
        id="global-search-input"
        className="input"
        type="text"
        value={query}
        placeholder="Search documents, people, ledger"
        aria-label="Search documents, people and ledger entries"
        onChange={(event) => {
          setQuery(event.target.value)
          setOpen(true)
        }}
        onFocus={() => setOpen(true)}
        onKeyDown={(event) => {
          if (event.key === 'Escape') setOpen(false)
        }}
      />

      {showPanel ? (
        <div className="global-results">
          {loading ? <p className="global-message muted">Searching...</p> : null}
          {!loading && error ? <p className="global-message error">{error}</p> : null}
          {!loading && !hasResults ? <p className="global-message muted">No matches.</p> : null}

          {!loading && results.documents.length > 0 ? (
            <div className="global-group">
              <p className="global-group-title">Documents</p>
              {results.documents.map((doc) => (
                <button
                  type="button"
                  key={doc.document_id}
                  className="global-item"
                  onClick={() =>
                    pick({ kind: 'document', document_id: doc.document_id, role: doc.role })
                  }
                >
                  <span className="global-item-title">
                    <FileTypeBadge name={doc.original_filename} />
                    <span>{doc.original_filename || 'Untitled'}</span>
                  </span>
                  <span className="global-item-sub mono">
                    {doc.document_id} | {doc.role === 'owner' ? 'Shared by me' : 'Shared with me'}
                  </span>
                </button>
              ))}
            </div>
          ) : null}

          {!loading && results.recipients.length > 0 ? (
            <div className="global-group">
              <p className="global-group-title">People</p>
              {results.recipients.map((person) => (
                <button
                  type="button"
                  key={person.recipient_id}
                  className="global-item"
                  onClick={() => pick({ kind: 'recipient', recipient_id: person.recipient_id })}
                >
                  <span>{person.display_name || person.recipient_id}</span>
                  <span className="global-item-sub mono">{person.recipient_id}</span>
                </button>
              ))}
            </div>
          ) : null}

          {!loading && results.entries.length > 0 ? (
            <div className="global-group">
              <p className="global-group-title">Ledger</p>
              {results.entries.map((entry, index) => (
                <button
                  type="button"
                  key={`${entry.current_hash || entry.watermark_id || entry.document_id}-${index}`}
                  className="global-item"
                  onClick={() =>
                    pick({
                      kind: 'ledger',
                      session_id: entry.session_id,
                      document_id: entry.document_id,
                      watermark_id: entry.watermark_id,
                    })
                  }
                >
                  <span className="mono">{entry.watermark_id || entry.session_id || 'Entry'}</span>
                  <span className="global-item-sub mono">
                    {entry.recipient_id} | {entry.document_id}
                  </span>
                </button>
              ))}
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}
