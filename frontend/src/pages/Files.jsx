import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
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
import { RecipientPicker } from '../components/RecipientPicker.jsx'
import { DropZone } from '../components/DropZone.jsx'
import { FileTypeBadge } from '../components/FileTypeBadge.jsx'
import { useToast } from '../components/Toasts.jsx'
import { fileTypeLabel } from '../services/fileTypes.js'

export function Files({ user, focus, onFocusHandled }) {
  const toast = useToast()

  const [recipients, setRecipients] = useState([])
  const [recipientsLoading, setRecipientsLoading] = useState(true)
  const [recipientsError, setRecipientsError] = useState('')

  const [documents, setDocuments] = useState([])
  const [documentsLoading, setDocumentsLoading] = useState(true)
  const [documentsError, setDocumentsError] = useState('')

  const [search, setSearch] = useState('')
  const [recipientFilter, setRecipientFilter] = useState('all')
  const [sort, setSort] = useState({ key: 'created_at', dir: 'desc' })
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)

  const [activeDoc, setActiveDoc] = useState(null)
  const [events, setEvents] = useState(null)
  const [eventsLoading, setEventsLoading] = useState(false)
  const [eventsError, setEventsError] = useState('')

  const [file, setFile] = useState(null)
  const [selected, setSelected] = useState([])
  const [sharing, setSharing] = useState(false)
  const [shareError, setShareError] = useState('')
  const [confirmation, setConfirmation] = useState(null)
  const [prefill, setPrefill] = useState(null)
  const shareRef = useRef(null)

  const currentUserId = user ? user.recipient_id || user.username : null

  const loadRecipients = useCallback(async () => {
    setRecipientsLoading(true)
    setRecipientsError('')
    try {
      const data = await api.recipients()
      setRecipients(data.recipients || [])
    } catch (err) {
      setRecipientsError(err.message)
    } finally {
      setRecipientsLoading(false)
    }
  }, [])

  const loadDocuments = useCallback(async () => {
    setDocumentsLoading(true)
    setDocumentsError('')
    try {
      const data = await api.documents()
      setDocuments(data.documents || [])
    } catch (err) {
      setDocumentsError(err.message)
    } finally {
      setDocumentsLoading(false)
    }
  }, [])

  useEffect(() => {
    loadRecipients()
  }, [loadRecipients])

  useEffect(() => {
    loadDocuments()
  }, [loadDocuments])

  useEffect(() => {
    setPage(1)
  }, [search, recipientFilter, pageSize])

  useEffect(() => {
    if (recipientsLoading || recipientsError || recipients.length === 0) return
    setSelected((prev) =>
      prev.filter((id) => recipients.some((person) => person.recipient_id === id))
    )
  }, [recipients, recipientsLoading, recipientsError])

  const recipientNames = useMemo(() => {
    const map = {}
    recipients.forEach((person) => {
      map[person.recipient_id] = person.display_name || person.recipient_id
    })
    return map
  }, [recipients])

  const recipientLabel = useCallback((id) => recipientNames[id] || id, [recipientNames])

  const ownedDocuments = useMemo(
    () => documents.filter((doc) => doc.role === 'owner'),
    [documents]
  )

  const recipientOptions = useMemo(() => {
    const ids = new Set()
    ownedDocuments.forEach((doc) => {
      ;(doc.authorized_recipients || []).forEach((id) => ids.add(id))
    })
    return [
      { value: 'all', label: 'All recipients' },
      ...Array.from(ids)
        .sort()
        .map((id) => ({ value: id, label: recipientLabel(id) })),
    ]
  }, [ownedDocuments, recipientLabel])

  const filtered = useMemo(
    () =>
      ownedDocuments.filter((doc) => {
        if (
          recipientFilter !== 'all' &&
          !(doc.authorized_recipients || []).includes(recipientFilter)
        ) {
          return false
        }
        return matchesAny(
          [
            doc.original_filename,
            doc.document_id,
            doc.document_hash,
            (doc.authorized_recipients || []).join(' '),
            (doc.authorized_recipients || []).map((id) => recipientLabel(id)).join(' '),
          ],
          search
        )
      }),
    [ownedDocuments, recipientFilter, search, recipientLabel]
  )

  const sorted = useMemo(
    () =>
      sortRows(filtered, sort, {
        original_filename: (doc) => (doc.original_filename || '').toLowerCase(),
        created_at: (doc) => doc.created_at || '',
        ciphertext_len: (doc) => Number(doc.ciphertext_len) || 0,
        recipient_count: (doc) => (doc.authorized_recipients || []).length,
      }),
    [filtered, sort]
  )

  const pageCount = Math.max(1, Math.ceil(sorted.length / pageSize))
  const safePage = Math.min(page, pageCount)
  const pageRows = sorted.slice((safePage - 1) * pageSize, safePage * pageSize)

  useEffect(() => {
    if (!activeDoc) {
      setEvents(null)
      setEventsError('')
      setEventsLoading(false)
      return undefined
    }

    let active = true
    setEventsLoading(true)
    setEventsError('')
    setEvents(null)
    api
      .documentEvents(activeDoc.document_id)
      .then((data) => {
        if (active) setEvents(data)
      })
      .catch((err) => {
        if (active) setEventsError(err.message)
      })
      .finally(() => {
        if (active) setEventsLoading(false)
      })

    return () => {
      active = false
    }
  }, [activeDoc])

  useEffect(() => {
    if (!focus || focus.type !== 'document' || documentsLoading) return
    const doc = ownedDocuments.find((item) => item.document_id === focus.documentId)
    if (doc) setActiveDoc(doc)
    onFocusHandled()
  }, [focus, ownedDocuments, documentsLoading, onFocusHandled])

  const focusShareForm = () => {
    if (shareRef.current) {
      shareRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
    window.setTimeout(() => {
      const input = document.getElementById('share-file')
      if (input) input.focus()
    }, 300)
  }

  const handleShare = async (event) => {
    event.preventDefault()
    if (!file) {
      setShareError('Choose a file to share.')
      return
    }
    if (selected.length === 0) {
      setShareError('Select at least one recipient.')
      return
    }

    setSharing(true)
    setShareError('')
    setConfirmation(null)
    try {
      const result = await api.encrypt(file, selected)
      const sharedCount = (result.authorized_recipients || selected).length
      setConfirmation(result)
      setPrefill(null)
      setFile(null)
      setSelected([])
      loadDocuments()
      toast.push(`Document shared with ${sharedCount} ${sharedCount === 1 ? 'person' : 'people'}.`, 'success')
    } catch (err) {
      setShareError(err.message)
    } finally {
      setSharing(false)
    }
  }

  const handleShareAnother = (doc) => {
    const ownerId = String(currentUserId || '').toLowerCase()
    const nextSelected = (doc.authorized_recipients || []).filter(
      (id) => String(id).toLowerCase() !== ownerId
    )
    setPrefill({ filename: doc.original_filename || 'Untitled' })
    setSelected(nextSelected)
    setFile(null)
    setActiveDoc(null)
    setConfirmation(null)
    setShareError('')
    focusShareForm()
  }

  const columns = useMemo(
    () => [
      {
        key: 'original_filename',
        label: 'Name',
        sortable: true,
        render: (doc) => (
          <span className="name-cell">
            <FileTypeBadge name={doc.original_filename} />
            <span>{doc.original_filename || 'Untitled'}</span>
          </span>
        ),
      },
      {
        key: 'document_id',
        label: 'ID',
        render: (doc) => <span className="mono">{doc.document_id}</span>,
      },
      {
        key: 'recipient_count',
        label: 'Recipients',
        sortable: true,
        render: (doc) => {
          const ids = doc.authorized_recipients || []
          if (ids.length === 0) return 'None'
          return ids.map((id) => recipientLabel(id)).join(', ')
        },
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
    ],
    [recipientLabel]
  )

  const canShare = Boolean(file) && selected.length > 0 && !sharing

  return (
    <div>
      <PageHeader
        title="Files"
        description="Share files and manage the documents you own."
        action={
          <button type="button" className="btn primary" onClick={focusShareForm}>
            New share
          </button>
        }
      />

      <section className="card" ref={shareRef}>
        <div className="card-head">
          <h2>Share a document</h2>
        </div>
        <p className="muted">Upload a file and choose the people who may decrypt it.</p>
        <p className="muted hint">
          PDFs, images, text, CSV/JSON, and Word/Excel/PowerPoint files are watermarked natively.
          Other file types are delivered in a forensic ZIP container.
        </p>

        {prefill ? (
          <div className="panel">
            <div className="card-head">
              <p className="muted">
                Sharing another copy of <span className="mono">{prefill.filename}</span>. Choose the
                same file and people below.
              </p>
              <button type="button" className="link-btn" onClick={() => setPrefill(null)}>
                Clear
              </button>
            </div>
          </div>
        ) : null}

        <form onSubmit={handleShare}>
          <div className="field">
            <label htmlFor="share-file">File</label>
            <DropZone id="share-file" file={file} onFile={setFile} disabled={sharing} />
          </div>

          <RecipientPicker
            id="share-recipients"
            people={recipients}
            loading={recipientsLoading}
            error={recipientsError}
            onRetry={loadRecipients}
            selected={selected}
            onChange={setSelected}
            excludeId={currentUserId}
            disabled={sharing}
          />

          {shareError ? (
            <p className="error" role="alert">
              {shareError}
            </p>
          ) : null}

          <div className="share-summary">
            {file && selected.length > 0 ? (
              <>
                <p>
                  <strong>{file.name}</strong> ({formatBytes(file.size)}), {selected.length}{' '}
                  {selected.length === 1 ? 'recipient' : 'recipients'}
                </p>
                <p className="muted">
                  One encrypted copy is stored; each recipient gets an individually wrapped key.
                </p>
              </>
            ) : (
              <p className="muted">
                {!file ? 'Choose a file.' : 'Select at least one recipient.'}
              </p>
            )}
          </div>

          <div className="form-actions">
            <button type="submit" className="btn primary" disabled={!canShare}>
              {sharing ? 'Sharing...' : 'Share'}
            </button>
          </div>
        </form>

        {confirmation ? (
          <div className="panel ok">
            <h3>Document shared</h3>
            <dl className="kv">
              <dt>Document ID</dt>
              <dd>
                <Copyable value={confirmation.document_id} label="document ID" />
              </dd>
              <dt>Hash</dt>
              <dd>
                <Copyable value={confirmation.document_hash} label="document hash" />
              </dd>
              <dt>Can decrypt</dt>
              <dd>
                {(confirmation.authorized_recipients || [])
                  .map((id) => recipientLabel(id))
                  .join(', ') || 'None listed'}
              </dd>
            </dl>
            <div className="next-steps">
              <p className="next-steps-title">What happens next</p>
              <ol>
                <li>Each recipient signs in and opens the document under Shared with me.</li>
                <li>
                  On decryption a copy is generated with a watermark unique to that recipient.
                </li>
                <li>The decryption event is recorded in the audit ledger.</li>
                <li>Any copy can be checked later on the Verify page.</li>
              </ol>
            </div>
          </div>
        ) : null}
      </section>

      <section className="card">
        <div className="card-head">
          <h2>My documents</h2>
          <button
            type="button"
            className="btn small"
            onClick={loadDocuments}
            disabled={documentsLoading}
          >
            Refresh
          </button>
        </div>

        <div className="toolbar">
          <div className="field">
            <label htmlFor="files-search">Search</label>
            <SearchInput
              id="files-search"
              value={search}
              onChange={setSearch}
              placeholder="Name, ID, hash or recipient"
              label="Search my documents"
            />
          </div>
          <Select
            id="files-recipient-filter"
            label="Recipient"
            value={recipientFilter}
            onChange={setRecipientFilter}
            options={recipientOptions}
            disabled={documentsLoading}
          />
          <div className="toolbar-count">
            <span className="field-label">Results</span>
            <span className="muted">
              {sorted.length} of {ownedDocuments.length}
            </span>
          </div>
        </div>

        {documentsLoading ? <p className="muted">Loading documents...</p> : null}
        {!documentsLoading && documentsError ? (
          <p className="error" role="alert">
            {documentsError}{' '}
            <button type="button" className="link-btn" onClick={loadDocuments}>
              Retry
            </button>
          </p>
        ) : null}

        {!documentsLoading && !documentsError && ownedDocuments.length === 0 ? (
          <EmptyState
            title="No documents yet"
            message="Use the form above to share your first file."
            actionLabel="New share"
            onAction={focusShareForm}
          />
        ) : null}

        {!documentsLoading && !documentsError && ownedDocuments.length > 0 && sorted.length === 0 ? (
          <EmptyState
            title="No matching documents"
            message="No documents match the current search or recipient filter."
            actionLabel="Clear filters"
            onAction={() => {
              setSearch('')
              setRecipientFilter('all')
            }}
          />
        ) : null}

        {!documentsLoading && !documentsError && sorted.length > 0 ? (
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
              onClick={() => handleShareAnother(activeDoc)}
            >
              Share another copy
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
              <dt>File type</dt>
              <dd>{fileTypeLabel(activeDoc.original_filename)}</dd>
              <dt>Status</dt>
              <dd>
                <span className="badge">{activeDoc.status || 'stored'}</span>
              </dd>
              <dt>Shared on</dt>
              <dd>{formatDate(activeDoc.created_at)}</dd>
              <dt>Size</dt>
              <dd>{formatBytes(activeDoc.ciphertext_len)}</dd>
              <dt>Decryptions</dt>
              <dd>{activeDoc.decryption_count ?? (events ? events.count : 0)}</dd>
              <dt>Last decrypted</dt>
              <dd>{formatDate(activeDoc.last_decrypted_at)}</dd>
            </dl>

            <h3 className="detail-heading">Authorized recipients</h3>
            {(activeDoc.authorized_recipients || []).length === 0 ? (
              <p className="muted">None listed.</p>
            ) : (
              <ul className="recipient-tags">
                {(activeDoc.authorized_recipients || []).map((id) => (
                  <li key={id} className="tag">
                    <span>{recipientLabel(id)}</span>
                    <span className="mono muted">{id}</span>
                  </li>
                ))}
              </ul>
            )}

            <h3 className="detail-heading">Decryption events</h3>
            {eventsLoading ? <p className="muted">Loading events...</p> : null}
            {!eventsLoading && eventsError ? (
              <p className="error" role="alert">
                {eventsError}
              </p>
            ) : null}
            {!eventsLoading && !eventsError && events && (events.events || []).length === 0 ? (
              <p className="muted">No decryptions recorded for this document.</p>
            ) : null}
            {!eventsLoading && !eventsError && events && (events.events || []).length > 0 ? (
              <ol className="event-list">
                {(events.events || []).map((event, index) => (
                  <li className="event-item" key={`${event.session_id || 'session'}-${index}`}>
                    <div className="event-head">
                      <span>{event.recipient_id || 'Unknown recipient'}</span>
                      <span className="muted">{formatDate(event.timestamp)}</span>
                    </div>
                    <div className="muted mono">Session {event.session_id || 'unknown'}</div>
                    <div className="muted mono">Watermark {event.watermark_id || 'unknown'}</div>
                    <div className="muted">
                      {event.quorum_ok === false ? 'Quorum not met' : 'Quorum ok'}
                      {Array.isArray(event.valid_nodes) && event.valid_nodes.length > 0
                        ? ` (${event.valid_nodes.join(', ')})`
                        : ''}
                    </div>
                    {event.current_hash ? (
                      <Copyable value={event.current_hash} label="event hash" />
                    ) : null}
                  </li>
                ))}
              </ol>
            ) : null}
          </>
        ) : null}
      </DetailDrawer>
    </div>
  )
}
