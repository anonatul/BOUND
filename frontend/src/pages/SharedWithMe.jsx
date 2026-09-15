import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../services/api.js'
import { formatBytes, formatDate, shortHash } from '../services/format.js'
import { sortRows, matchesAny } from '../services/sort.js'
import { PageHeader } from '../components/PageHeader.jsx'
import { SearchInput } from '../components/SearchInput.jsx'
import { Select } from '../components/Select.jsx'
import { DataTable } from '../components/DataTable.jsx'
import { DetailDrawer } from '../components/DetailDrawer.jsx'
import { Copyable } from '../components/Copyable.jsx'
import { EmptyState } from '../components/EmptyState.jsx'
import { Pagination } from '../components/Pagination.jsx'
import { UnlockDialog } from '../components/UnlockDialog.jsx'
import { useToast } from '../components/Toasts.jsx'

function ownerOf(doc) {
  return doc.owner || doc.owner_id || doc.owner_recipient_id || doc.sender_id || doc.sender || 'Unknown'
}

export function SharedWithMe({ unlocked, focus, onFocusHandled, onSessionChanged, onOpenAudit }) {
  const toast = useToast()

  const [documents, setDocuments] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [search, setSearch] = useState('')
  const [ownerFilter, setOwnerFilter] = useState('all')
  const [sort, setSort] = useState({ key: 'created_at', dir: 'desc' })
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)

  const [activeDoc, setActiveDoc] = useState(null)
  const [busyId, setBusyId] = useState(null)
  const [pendingUnlock, setPendingUnlock] = useState(null)
  const [result, setResult] = useState(null)

  const loadDocuments = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const data = await api.documents()
      setDocuments(data.documents || [])
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadDocuments()
  }, [loadDocuments])

  useEffect(() => {
    setPage(1)
  }, [search, ownerFilter, pageSize])

  const sharedDocuments = useMemo(
    () => documents.filter((doc) => doc.role === 'recipient'),
    [documents]
  )

  const ownerOptions = useMemo(() => {
    const owners = new Set()
    sharedDocuments.forEach((doc) => owners.add(ownerOf(doc)))
    return [
      { value: 'all', label: 'All owners' },
      ...Array.from(owners)
        .sort()
        .map((owner) => ({ value: owner, label: owner })),
    ]
  }, [sharedDocuments])

  const filtered = useMemo(
    () =>
      sharedDocuments.filter((doc) => {
        if (ownerFilter !== 'all' && ownerOf(doc) !== ownerFilter) return false
        return matchesAny(
          [doc.original_filename, doc.document_id, doc.document_hash, ownerOf(doc)],
          search
        )
      }),
    [sharedDocuments, ownerFilter, search]
  )

  const sorted = useMemo(
    () =>
      sortRows(filtered, sort, {
        original_filename: (doc) => (doc.original_filename || '').toLowerCase(),
        created_at: (doc) => doc.created_at || '',
        ciphertext_len: (doc) => Number(doc.ciphertext_len) || 0,
        owner: (doc) => ownerOf(doc).toLowerCase(),
      }),
    [filtered, sort]
  )

  const pageCount = Math.max(1, Math.ceil(sorted.length / pageSize))
  const safePage = Math.min(page, pageCount)
  const pageRows = sorted.slice((safePage - 1) * pageSize, safePage * pageSize)

  useEffect(() => {
    if (!focus || focus.type !== 'document' || loading) return
    const doc = sharedDocuments.find((item) => item.document_id === focus.documentId)
    if (doc) setActiveDoc(doc)
    onFocusHandled()
  }, [focus, sharedDocuments, loading, onFocusHandled])

  const decrypt = async (documentId) => {
    setBusyId(documentId)
    setError('')
    setResult(null)
    try {
      const data = await api.decrypt(documentId)
      setPendingUnlock(null)
      setResult(data)
      setActiveDoc(null)
      toast.push(
        data.message || 'Copy decrypted and ready to download.',
        'success'
      )
    } catch (err) {
      if (err.status === 403) {
        setPendingUnlock({ document_id: documentId, message: err.message })
      } else {
        setPendingUnlock(null)
        setError(err.message)
      }
    } finally {
      setBusyId(null)
    }
  }

  const handleUnlocked = async () => {
    const documentId = pendingUnlock && pendingUnlock.document_id
    setPendingUnlock(null)
    if (onSessionChanged) onSessionChanged()
    toast.push('Keys unlocked.', 'success')
    if (documentId) await decrypt(documentId)
  }

  const columns = [
    {
      key: 'original_filename',
      label: 'Name',
      sortable: true,
      render: (doc) => doc.original_filename || 'Untitled',
    },
    {
      key: 'document_id',
      label: 'ID',
      render: (doc) => <span className="mono">{doc.document_id}</span>,
    },
    {
      key: 'owner',
      label: 'Owner',
      sortable: true,
      render: (doc) => ownerOf(doc),
    },
    {
      key: 'created_at',
      label: 'Shared on',
      sortable: true,
      render: (doc) => formatDate(doc.created_at),
    },
    {
      key: 'ciphertext_len',
      label: 'Size',
      sortable: true,
      render: (doc) => formatBytes(doc.ciphertext_len),
    },
    {
      key: 'document_hash',
      label: 'Hash',
      render: (doc) => (
        <span className="mono" title={doc.document_hash}>
          {shortHash(doc.document_hash)}
        </span>
      ),
    },
    {
      key: 'action',
      label: 'Action',
      render: (doc) => (
        <button
          type="button"
          className="btn small"
          disabled={busyId === doc.document_id}
          onClick={(event) => {
            event.stopPropagation()
            decrypt(doc.document_id)
          }}
        >
          {busyId === doc.document_id ? 'Decrypting...' : 'Decrypt'}
        </button>
      ),
    },
  ]

  return (
    <div>
      <PageHeader
        title="Shared with me"
        description="Documents that other people have shared with you."
      />

      {unlocked === false ? (
        <div className="panel warn banner">
          <div className="banner-text">
            <p className="banner-title">Keys locked</p>
            <p className="muted">
              Unlock your private keys to decrypt and download shared documents.
            </p>
          </div>
          <button
            type="button"
            className="btn primary"
            onClick={() =>
              setPendingUnlock({
                document_id: null,
                message: 'Unlock your private keys for this session.',
              })
            }
          >
            Unlock
          </button>
        </div>
      ) : null}

      <section className="card">
        <div className="card-head">
          <h2>Documents</h2>
          <button type="button" className="btn small" onClick={loadDocuments} disabled={loading}>
            Refresh
          </button>
        </div>

        <div className="toolbar">
          <div className="field">
            <label htmlFor="shared-search">Search</label>
            <SearchInput
              id="shared-search"
              value={search}
              onChange={setSearch}
              placeholder="Name, ID, hash or owner"
              label="Search shared documents"
            />
          </div>
          <Select
            id="shared-owner-filter"
            label="Owner"
            value={ownerFilter}
            onChange={setOwnerFilter}
            options={ownerOptions}
            disabled={loading}
          />
          <div className="toolbar-count">
            <span className="field-label">Results</span>
            <span className="muted">
              {sorted.length} of {sharedDocuments.length}
            </span>
          </div>
        </div>

        {loading ? <p className="muted">Loading documents...</p> : null}
        {!loading && error ? (
          <p className="error" role="alert">
            {error}{' '}
            <button type="button" className="link-btn" onClick={loadDocuments}>
              Retry
            </button>
          </p>
        ) : null}

        {!loading && !error && sharedDocuments.length === 0 ? (
          <EmptyState
            title="Nothing shared yet"
            message="Documents shared with you will appear here."
          />
        ) : null}

        {!loading && !error && sharedDocuments.length > 0 && sorted.length === 0 ? (
          <EmptyState
            title="No matching documents"
            message="No documents match the current search or owner filter."
            actionLabel="Clear filters"
            onAction={() => {
              setSearch('')
              setOwnerFilter('all')
            }}
          />
        ) : null}

        {!loading && !error && sorted.length > 0 ? (
          <>
            <DataTable
              columns={columns}
              rows={pageRows}
              getRowKey={(doc) => doc.document_id}
              onRowClick={(doc) => setActiveDoc(doc)}
              sort={sort}
              onSortChange={setSort}
              emptyMessage="No documents."
            />
            <Pagination
              page={safePage}
              pageSize={pageSize}
              total={sorted.length}
              onPageChange={setPage}
              onPageSizeChange={setPageSize}
            />
          </>
        ) : null}

        {result ? (
          <div className="panel ok">
            <h3>Copy decrypted</h3>
            <dl className="kv">
              <dt>Recipient</dt>
              <dd>{result.recipient_id || 'Unknown'}</dd>
              <dt>Session</dt>
              <dd>
                <Copyable value={result.session_id} label="session ID" />
              </dd>
              <dt>Watermark</dt>
              <dd>
                <Copyable value={result.watermark_id} label="watermark ID" />
              </dd>
              {result.ledger ? (
                <>
                  <dt>Audit</dt>
                  <dd>Recorded in audit ledger (quorum {result.ledger.node_quorum ?? 'unknown'})</dd>
                </>
              ) : null}
            </dl>
            {result.message ? <p className="muted">{result.message}</p> : null}
            <div className="form-actions">
              {result.download_url ? (
                <a className="btn primary" href={result.download_url} download={result.filename}>
                  Download marked copy
                </a>
              ) : null}
              {result.session_id ? (
                <button
                  type="button"
                  className="btn"
                  onClick={() => onOpenAudit && onOpenAudit(result.session_id)}
                >
                  View session in Audit
                </button>
              ) : null}
            </div>
          </div>
        ) : null}
      </section>

      <DetailDrawer
        open={activeDoc !== null}
        title={activeDoc ? activeDoc.original_filename || 'Document' : 'Document'}
        onClose={() => setActiveDoc(null)}
        footer={
          activeDoc ? (
            <button
              type="button"
              className="btn primary"
              disabled={busyId === activeDoc.document_id}
              onClick={() => decrypt(activeDoc.document_id)}
            >
              {busyId === activeDoc.document_id ? 'Decrypting...' : 'Decrypt and download'}
            </button>
          ) : null
        }
      >
        {activeDoc ? (
          <>
            <dl className="kv">
              <dt>Document ID</dt>
              <dd>
                <Copyable value={activeDoc.document_id} label="document ID" />
              </dd>
              <dt>Hash</dt>
              <dd>
                <Copyable value={activeDoc.document_hash} label="document hash" />
              </dd>
              <dt>Owner</dt>
              <dd>{ownerOf(activeDoc)}</dd>
              <dt>Shared on</dt>
              <dd>{formatDate(activeDoc.created_at)}</dd>
              <dt>Size</dt>
              <dd>{formatBytes(activeDoc.ciphertext_len)}</dd>
              <dt>Decryptions</dt>
              <dd>{activeDoc.decryption_count ?? 0}</dd>
              <dt>Last decrypted</dt>
              <dd>{formatDate(activeDoc.last_decrypted_at)}</dd>
            </dl>
            <h3 className="detail-heading">Authorized recipients</h3>
            <ul className="recipient-tags">
              {(activeDoc.authorized_recipients || []).map((id) => (
                <li key={id} className="tag">
                  <span className="mono">{id}</span>
                </li>
              ))}
            </ul>
          </>
        ) : null}
      </DetailDrawer>

      <UnlockDialog
        open={pendingUnlock !== null}
        title="Unlock keys"
        message={pendingUnlock ? pendingUnlock.message : undefined}
        onClose={() => setPendingUnlock(null)}
        onUnlocked={handleUnlocked}
      />
    </div>
  )
}
