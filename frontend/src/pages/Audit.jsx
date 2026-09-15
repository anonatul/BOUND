import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../services/api.js'
import { formatDate, shortHash } from '../services/format.js'
import { sortRows, matchesAny } from '../services/sort.js'
import { PageHeader } from '../components/PageHeader.jsx'
import { SearchInput } from '../components/SearchInput.jsx'
import { Select } from '../components/Select.jsx'
import { DataTable } from '../components/DataTable.jsx'
import { Copyable } from '../components/Copyable.jsx'
import { EmptyState } from '../components/EmptyState.jsx'
import { Pagination } from '../components/Pagination.jsx'
import { InfoTip } from '../components/InfoTip.jsx'
import { useToast } from '../components/Toasts.jsx'

function parseQuorum(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value
  const ratio = String(value || '').match(/(\d+)\s*\/\s*(\d+)/)
  if (ratio) return Number(ratio[1])
  const single = String(value || '').match(/(\d+)/)
  return single ? Number(single[1]) : 3
}

function entryKey(entry) {
  return (
    entry.current_hash ||
    `${entry.watermark_id || ''}:${entry.session_id || ''}:${entry.document_id || ''}`
  )
}

function entryHasIssues(entry, required) {
  if (entry.quorum_ok === false) return true
  if (Array.isArray(entry.valid_nodes) && entry.valid_nodes.length > 0) {
    return entry.valid_nodes.length < required
  }
  return false
}

function nodeMap(value) {
  if (!value || typeof value !== 'object') return 'Not reported'
  const parts = Object.entries(value).map(
    ([name, ok]) => `${name}: ${ok ? 'valid' : 'invalid'}`
  )
  return parts.length > 0 ? parts.join(', ') : 'Not reported'
}

export function Audit({ focus, onFocusHandled, ledgerVersion }) {
  const toast = useToast()

  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [nodeFilter, setNodeFilter] = useState('all')
  const [documentFilter, setDocumentFilter] = useState('all')
  const [recipientFilter, setRecipientFilter] = useState('all')
  const [sort, setSort] = useState({ key: 'time', dir: 'desc' })
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(15)
  const [expandedKey, setExpandedKey] = useState(null)

  const [repairing, setRepairing] = useState(false)
  const [repairResult, setRepairResult] = useState(null)
  const [pendingExpand, setPendingExpand] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      setData(await api.ledger())
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load, ledgerVersion])

  useEffect(() => {
    setPage(1)
  }, [search, statusFilter, nodeFilter, documentFilter, recipientFilter, pageSize])

  const entries = (data && data.entries) || []
  const details = (data && data.details) || {}
  const nodeNames = useMemo(
    () =>
      Object.keys(details)
        .filter((name) => /^node\d+$/.test(name))
        .sort(),
    [details]
  )
  const quorumRequired = parseQuorum(data && data.quorum)
  const divergent = (data && data.divergent_nodes) || []
  const checkpointTotal = useMemo(
    () =>
      nodeNames.reduce(
        (sum, name) => sum + (Number(details[name] && details[name].checkpoint_count) || 0),
        0
      ),
    [nodeNames, details]
  )

  useEffect(() => {
    if (!focus || focus.type !== 'ledger') return
    setPendingExpand({
      sessionId: focus.sessionId || null,
      watermarkId: focus.watermarkId || null,
      documentId: focus.documentId || null,
    })
    setSearch(focus.sessionId || focus.watermarkId || '')
    setDocumentFilter(focus.documentId || 'all')
    setStatusFilter('all')
    setNodeFilter('all')
    setRecipientFilter('all')
    onFocusHandled()
  }, [focus, onFocusHandled])

  const documentOptions = useMemo(() => {
    const ids = new Set()
    entries.forEach((entry) => {
      if (entry.document_id) ids.add(entry.document_id)
    })
    return [
      { value: 'all', label: 'All documents' },
      ...Array.from(ids)
        .sort()
        .map((id) => ({ value: id, label: id })),
    ]
  }, [entries])

  const recipientOptions = useMemo(() => {
    const ids = new Set()
    entries.forEach((entry) => {
      if (entry.recipient_id) ids.add(entry.recipient_id)
    })
    return [
      { value: 'all', label: 'All recipients' },
      ...Array.from(ids)
        .sort()
        .map((id) => ({ value: id, label: id })),
    ]
  }, [entries])

  const nodeOptions = useMemo(
    () => [
      { value: 'all', label: 'All nodes' },
      ...nodeNames.map((name) => ({ value: name, label: name })),
    ],
    [nodeNames]
  )

  const filtered = useMemo(
    () =>
      entries.filter((entry) => {
        const hasIssues = entryHasIssues(entry, quorumRequired)
        if (statusFilter === 'valid' && hasIssues) return false
        if (statusFilter === 'issues' && !hasIssues) return false
        if (
          nodeFilter !== 'all' &&
          !(Array.isArray(entry.valid_nodes) && entry.valid_nodes.includes(nodeFilter))
        ) {
          return false
        }
        if (documentFilter !== 'all' && entry.document_id !== documentFilter) return false
        if (recipientFilter !== 'all' && entry.recipient_id !== recipientFilter) return false
        return matchesAny(
          [
            entry.watermark_id,
            entry.session_id,
            entry.document_id,
            entry.recipient_id,
            entry.current_hash,
            entry.previous_hash,
          ],
          search
        )
      }),
    [entries, statusFilter, nodeFilter, documentFilter, recipientFilter, search, quorumRequired]
  )

  const sorted = useMemo(
    () =>
      sortRows(filtered, sort, {
        time: (entry) => (entry.event && entry.event.timestamp) || '',
        document_id: (entry) => entry.document_id || '',
        recipient_id: (entry) => entry.recipient_id || '',
        session_id: (entry) => entry.session_id || '',
        watermark_id: (entry) => entry.watermark_id || '',
      }),
    [filtered, sort]
  )

  const pageCount = Math.max(1, Math.ceil(sorted.length / pageSize))
  const safePage = Math.min(page, pageCount)
  const pageRows = sorted.slice((safePage - 1) * pageSize, safePage * pageSize)

  useEffect(() => {
    if (!pendingExpand) return
    const index = sorted.findIndex(
      (entry) =>
        (pendingExpand.watermarkId && entry.watermark_id === pendingExpand.watermarkId) ||
        (pendingExpand.sessionId && entry.session_id === pendingExpand.sessionId) ||
        (pendingExpand.documentId && entry.document_id === pendingExpand.documentId)
    )
    if (index < 0) return
    setExpandedKey(entryKey(sorted[index]))
    setPage(Math.floor(index / pageSize) + 1)
    setPendingExpand(null)
  }, [pendingExpand, sorted, pageSize])

  const handleRepair = async () => {
    setRepairing(true)
    setRepairResult(null)
    setError('')
    try {
      const result = await api.ledgerRepair()
      setRepairResult(result)
      await load()
      toast.push(
        result.message || (result.valid ? 'Ledger re-synced from quorum.' : 'Re-sync incomplete.'),
        result.valid ? 'success' : 'error'
      )
    } catch (err) {
      setError(err.message)
      toast.push(err.message, 'error')
    } finally {
      setRepairing(false)
    }
  }

  const columns = useMemo(
    () => [
      {
        key: 'time',
        label: 'Time',
        sortable: true,
        render: (entry) => formatDate(entry.event && entry.event.timestamp),
      },
      {
        key: 'document_id',
        label: 'Document',
        sortable: true,
        render: (entry) => <span className="mono">{entry.document_id || 'Unknown'}</span>,
      },
      {
        key: 'recipient_id',
        label: 'Recipient',
        sortable: true,
        render: (entry) => entry.recipient_id || 'Unknown',
      },
      {
        key: 'session_id',
        label: 'Session',
        sortable: true,
        render: (entry) => <span className="mono">{entry.session_id || 'Unknown'}</span>,
      },
      {
        key: 'watermark_id',
        label: 'Watermark',
        sortable: true,
        render: (entry) => <span className="mono">{entry.watermark_id || 'Unknown'}</span>,
      },
      {
        key: 'quorum',
        label: 'Quorum',
        render: (entry) => (
          <span className={entryHasIssues(entry, quorumRequired) ? 'badge bad' : 'badge ok'}>
            {entryHasIssues(entry, quorumRequired) ? 'Issues' : 'Valid'}
          </span>
        ),
      },
      {
        key: 'hash',
        label: 'Hash',
        render: (entry) => (
          <span className="mono" title={entry.current_hash}>
            {shortHash(entry.current_hash)}
          </span>
        ),
      },
    ],
    [quorumRequired]
  )

  const renderExpanded = (entry) => {
    const signature =
      entry.recipient_signature ?? entry.signature ?? entry.signature_present
    let signatureText = 'Not reported'
    if (typeof signature === 'boolean') signatureText = signature ? 'Present' : 'Missing'
    else if (signature) signatureText = 'Present'

    return (
      <div className="expand-cell">
        <dl className="kv kv-tight">
          <dt>Event</dt>
          <dd>Decryption recorded for {entry.recipient_id || 'an unknown recipient'}</dd>
          <dt>Timestamp</dt>
          <dd>{formatDate(entry.event && entry.event.timestamp)}</dd>
          <dt>Session</dt>
          <dd className="mono">{entry.session_id || 'Unknown'}</dd>
          <dt>Watermark</dt>
          <dd className="mono">{entry.watermark_id || 'Unknown'}</dd>
          <dt>Document</dt>
          <dd className="mono">{entry.document_id || 'Unknown'}</dd>
          <dt>Recipient signature</dt>
          <dd>{signatureText}</dd>
          <dt>Node quorum</dt>
          <dd>
            {entry.quorum_ok === false ? 'Not met' : 'Met'} (needs {quorumRequired} nodes)
          </dd>
          <dt>Valid nodes</dt>
          <dd>
            {Array.isArray(entry.valid_nodes) && entry.valid_nodes.length > 0
              ? entry.valid_nodes.join(', ')
              : 'Not reported'}
          </dd>
          <dt>Current hash</dt>
          <dd>
            <Copyable value={entry.current_hash} label="current hash" />
          </dd>
          <dt>Previous hash</dt>
          <dd>
            <Copyable value={entry.previous_hash} label="previous hash" />
          </dd>
        </dl>
      </div>
    )
  }

  const filtersActive =
    search.trim() !== '' ||
    statusFilter !== 'all' ||
    nodeFilter !== 'all' ||
    documentFilter !== 'all' ||
    recipientFilter !== 'all'

  const clearFilters = () => {
    setSearch('')
    setStatusFilter('all')
    setNodeFilter('all')
    setDocumentFilter('all')
    setRecipientFilter('all')
  }

  return (
    <div>
      <PageHeader
        title="Audit"
        description="Ledger integrity, node status and recorded decryption events."
        action={
          <button type="button" className="btn primary" onClick={load} disabled={loading}>
            {loading ? 'Checking...' : 'Re-verify'}
          </button>
        }
      />

      <section className="card">
        <div className="card-head">
          <h2>Ledger status</h2>
        </div>

        {loading ? <p className="muted">Loading ledger...</p> : null}
        {!loading && error ? (
          <p className="error" role="alert">
            {error}{' '}
            <button type="button" className="link-btn" onClick={load}>
              Retry
            </button>
          </p>
        ) : null}

        {!loading && data ? (
          <>
            <div className="stat-grid">
              <div className="stat-card">
                <p className="stat-label">Integrity</p>
                <p className="stat-value">
                  <span className={data.integrity_valid ? 'badge ok' : 'badge bad'}>
                    {data.integrity_valid ? 'Valid' : 'Failed'}
                  </span>
                </p>
                <p className="muted stat-note">
                  {data.integrity || 'All nodes match their checkpoints.'}{' '}
                  <InfoTip label="ledger integrity">
                    Each node keeps its own copy of the ledger. Integrity is valid when every
                    node&apos;s copy matches its stored checkpoints and signatures.
                  </InfoTip>
                </p>
              </div>

              <div className="stat-card">
                <p className="stat-label">
                  Quorum{' '}
                  <InfoTip label="quorum">
                    Every event is written to all four ledger nodes. A record is accepted when at
                    least three nodes agree, so one faulty or tampered node cannot rewrite the
                    recorded history.
                  </InfoTip>
                </p>
                <p className="stat-value">
                  <span className={data.quorum_ok === false ? 'badge bad' : 'badge ok'}>
                    {data.quorum_ok === false ? 'Not met' : 'Met'}
                  </span>
                </p>
                <p className="muted stat-note">
                  {typeof data.quorum === 'number'
                    ? `${data.quorum} of ${nodeNames.length || 4} nodes`
                    : `${quorumRequired} of ${nodeNames.length || 4}`}
                </p>
              </div>

              <div className="stat-card">
                <p className="stat-label">
                  Merkle root{' '}
                  <InfoTip label="Merkle root">
                    A single hash summarizing every ledger entry (its current_hash). If any entry
                    changes, the root changes, so tampering is detectable.
                  </InfoTip>
                </p>
                <p className="stat-value">
                  <Copyable
                    value={data.merkle_root}
                    display={shortHash(data.merkle_root, 14)}
                    label="Merkle root"
                  />
                </p>
                <p className="muted stat-note">Merkle root over all ledger entries</p>
              </div>

              <div className="stat-card">
                <p className="stat-label">Checkpoints</p>
                <p className="stat-value">{checkpointTotal}</p>
                <p className="muted stat-note">Across {nodeNames.length || 0} nodes</p>
              </div>
            </div>

            {divergent.length > 0 ? (
              <p className="error">Divergent nodes: {divergent.join(', ')}</p>
            ) : null}

            {data.integrity_valid === false ? (
              <div className="form-actions">
                <button
                  type="button"
                  className="btn primary"
                  onClick={handleRepair}
                  disabled={repairing}
                >
                  {repairing ? 'Re-syncing...' : 'Re-sync from quorum'}
                </button>
              </div>
            ) : null}

            {repairResult ? (
              <div className={repairResult.valid ? 'panel ok' : 'panel warn'}>
                <h3>Re-sync result</h3>
                <p>
                  {repairResult.message ||
                    (repairResult.valid
                      ? 'Nodes are consistent again.'
                      : 'Some nodes are still inconsistent.')}
                </p>
                <dl className="kv">
                  <dt>Repaired</dt>
                  <dd>{(repairResult.repaired || []).join(', ') || 'None'}</dd>
                  <dt>Before</dt>
                  <dd>{nodeMap(repairResult.before)}</dd>
                  <dt>After</dt>
                  <dd>{nodeMap(repairResult.after)}</dd>
                </dl>
              </div>
            ) : null}

            <div className="node-grid">
              {nodeNames.length === 0 ? (
                <p className="muted">No node details reported.</p>
              ) : null}
              {nodeNames.map((name) => {
                const node = details[name] || {}
                return (
                  <div className={node.valid ? 'node-card' : 'node-card bad'} key={name}>
                    <div className="node-card-head">
                      <span className="mono">{name}</span>
                      <span className={node.valid ? 'badge ok' : 'badge bad'}>
                        {node.valid ? 'Valid' : 'Invalid'}
                      </span>
                    </div>
                    <div className="muted">
                      {node.count ?? 0} entries | {node.checkpoint_count ?? 0} checkpoints
                    </div>
                    {node.merkle_root ? (
                      <Copyable
                        value={node.merkle_root}
                        display={`Root ${shortHash(node.merkle_root, 16)}`}
                        label={`${name} Merkle root`}
                      />
                    ) : null}
                    {node.last_hash ? (
                      <div className="muted mono">Last {shortHash(node.last_hash)}</div>
                    ) : null}
                    {node.error ? <p className="error">{node.error}</p> : null}
                  </div>
                )
              })}
            </div>
          </>
        ) : null}
      </section>

      <section className="card">
        <div className="card-head">
          <h2>Ledger entries</h2>
          <span className="muted">
            {sorted.length} of {entries.length}
          </span>
        </div>

        <div className="toolbar toolbar-wide">
          <div className="field">
            <label htmlFor="audit-search">Search</label>
            <SearchInput
              id="audit-search"
              value={search}
              onChange={setSearch}
              placeholder="Watermark, session, document, recipient"
              label="Search ledger entries"
            />
          </div>
          <Select
            id="audit-status-filter"
            label="Status"
            value={statusFilter}
            onChange={setStatusFilter}
            options={[
              { value: 'all', label: 'All' },
              { value: 'valid', label: 'Valid' },
              { value: 'issues', label: 'Issues' },
            ]}
          />
          <Select
            id="audit-node-filter"
            label="Node"
            value={nodeFilter}
            onChange={setNodeFilter}
            options={nodeOptions}
          />
          <Select
            id="audit-document-filter"
            label="Document"
            value={documentFilter}
            onChange={setDocumentFilter}
            options={documentOptions}
          />
          <Select
            id="audit-recipient-filter"
            label="Recipient"
            value={recipientFilter}
            onChange={setRecipientFilter}
            options={recipientOptions}
          />
        </div>

        {filtersActive ? (
          <div className="form-actions">
            <button type="button" className="link-btn" onClick={clearFilters}>
              Clear filters
            </button>
          </div>
        ) : null}

        {!loading && !error && entries.length === 0 ? (
          <EmptyState
            title="No ledger entries yet"
            message="Decryption events will appear here once documents are opened."
          />
        ) : null}

        {!loading && !error && entries.length > 0 && sorted.length === 0 ? (
          <EmptyState
            title="No matching entries"
            message="No ledger entries match the current search or filters."
            actionLabel="Clear filters"
            onAction={clearFilters}
          />
        ) : null}

        {!loading && !error && sorted.length > 0 ? (
          <>
            <DataTable
              columns={columns}
              rows={pageRows}
              getRowKey={entryKey}
              onRowClick={(entry) =>
                setExpandedKey((current) => (current === entryKey(entry) ? null : entryKey(entry)))
              }
              sort={sort}
              onSortChange={setSort}
              expandedKey={expandedKey}
              renderExpanded={renderExpanded}
              emptyMessage="No entries."
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
      </section>
    </div>
  )
}
