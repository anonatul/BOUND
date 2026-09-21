import { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../services/api.js'
import { formatDate } from '../services/format.js'
import { sortRows, matchesAny } from '../services/sort.js'
import { PageHeader } from '../components/PageHeader.jsx'
import { SearchInput } from '../components/SearchInput.jsx'
import { Select } from '../components/Select.jsx'
import { DataTable } from '../components/DataTable.jsx'
import { DetailDrawer } from '../components/DetailDrawer.jsx'
import { Copyable } from '../components/Copyable.jsx'
import { EmptyState } from '../components/EmptyState.jsx'
import { Pagination } from '../components/Pagination.jsx'
import { InfoTip } from '../components/InfoTip.jsx'

const STORAGE_LABELS = {
  encrypted: 'Encrypted',
  legacy: 'Legacy',
}

function storageLabel(value) {
  return STORAGE_LABELS[String(value || '').toLowerCase()] || value || 'Unknown'
}

export function People({ focus, onFocusHandled }) {
  const [people, setPeople] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const [search, setSearch] = useState('')
  const [storageFilter, setStorageFilter] = useState('all')
  const [sort, setSort] = useState({ key: 'display_name', dir: 'asc' })
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)

  const [detail, setDetail] = useState(null)
  const [detailData, setDetailData] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [detailError, setDetailError] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const data = await api.recipients()
      setPeople(data.recipients || [])
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    setPage(1)
  }, [search, storageFilter, pageSize])

  useEffect(() => {
    if (!detail) {
      setDetailData(null)
      setDetailError('')
      return undefined
    }

    let active = true
    setDetailLoading(true)
    setDetailError('')
    setDetailData(null)
    api
      .recipient(detail.id)
      .then((data) => {
        if (active) setDetailData(data)
      })
      .catch((err) => {
        if (active) setDetailError(err.message)
      })
      .finally(() => {
        if (active) setDetailLoading(false)
      })

    return () => {
      active = false
    }
  }, [detail])

  useEffect(() => {
    if (!focus || focus.type !== 'recipient' || loading) return
    const person = people.find((item) => item.recipient_id === focus.recipientId)
    setDetail({ id: focus.recipientId, base: person || null })
    onFocusHandled()
  }, [focus, people, loading, onFocusHandled])

  const filtered = useMemo(
    () =>
      people.filter(
        (person) =>
          (storageFilter === 'all' ||
            String(person.key_storage || '').toLowerCase() === storageFilter) &&
          matchesAny(
            [
              person.display_name,
              person.recipient_id,
              person.mlkem_fingerprint,
              person.mldsa_fingerprint,
            ],
            search
          )
      ),
    [people, search, storageFilter]
  )

  const sorted = useMemo(
    () =>
      sortRows(filtered, sort, {
        display_name: (person) => (person.display_name || person.recipient_id || '').toLowerCase(),
        recipient_id: (person) => (person.recipient_id || '').toLowerCase(),
        created_at: (person) => person.created_at || '',
        documents_owned: (person) => Number(person.documents_owned) || 0,
        documents_shared: (person) => Number(person.documents_shared) || 0,
      }),
    [filtered, sort]
  )

  const pageCount = Math.max(1, Math.ceil(sorted.length / pageSize))
  const safePage = Math.min(page, pageCount)
  const pageRows = sorted.slice((safePage - 1) * pageSize, safePage * pageSize)

  const columns = useMemo(
    () => [
      {
        key: 'display_name',
        label: 'Name',
        sortable: true,
        render: (person) => person.display_name || person.recipient_id,
      },
      {
        key: 'recipient_id',
        label: 'ID',
        sortable: true,
        render: (person) => <span className="mono">{person.recipient_id}</span>,
      },
      {
        key: 'key_storage',
        label: 'Key storage',
        render: (person) => (
          <span className="badge">{storageLabel(person.key_storage)}</span>
        ),
      },
      {
        key: 'created_at',
        label: 'Registered',
        sortable: true,
        render: (person) => formatDate(person.created_at),
      },
      {
        key: 'documents_owned',
        label: 'Owned',
        sortable: true,
        render: (person) => person.documents_owned ?? 0,
      },
      {
        key: 'documents_shared',
        label: 'Shared',
        sortable: true,
        render: (person) => person.documents_shared ?? 0,
      },
    ],
    []
  )

  const person = detailData || (detail && detail.base) || null

  return (
    <div>
      <PageHeader
        title="People"
        description="Registered users and their public keys. Only public information is shown."
      />

      <section className="card">
        <div className="card-head">
          <h2>Directory</h2>
          <button type="button" className="btn small" onClick={load} disabled={loading}>
            Refresh
          </button>
        </div>

        <div className="toolbar">
          <div className="field">
            <label htmlFor="people-search">Search</label>
            <SearchInput
              id="people-search"
              value={search}
              onChange={setSearch}
              placeholder="Name, ID or fingerprint"
              label="Search people"
            />
          </div>
          <Select
            id="people-storage-filter"
            label="Key storage"
            value={storageFilter}
            onChange={setStorageFilter}
            options={[
              { value: 'all', label: 'All' },
              { value: 'encrypted', label: 'Encrypted' },
              { value: 'legacy', label: 'Legacy' },
            ]}
            disabled={loading}
          />
          <div className="toolbar-count">
            <span className="field-label">Results</span>
            <span className="muted">
              {sorted.length} of {people.length}
            </span>
          </div>
        </div>

        {loading ? <p className="muted">Loading people...</p> : null}
        {!loading && error ? (
          <p className="error" role="alert">
            {error}{' '}
            <button type="button" className="link-btn" onClick={load}>
              Retry
            </button>
          </p>
        ) : null}

        {!loading && !error && people.length === 0 ? (
          <EmptyState title="No registered users" message="Accounts will appear here once created." />
        ) : null}

        {!loading && !error && people.length > 0 && sorted.length === 0 ? (
          <EmptyState
            title="No matching people"
            message="No users match the current search or filter."
            actionLabel="Clear filters"
            onAction={() => {
              setSearch('')
              setStorageFilter('all')
            }}
          />
        ) : null}

        {!loading && !error && sorted.length > 0 ? (
          <>
            <DataTable
              columns={columns}
              rows={pageRows}
              getRowKey={(item) => item.recipient_id}
              onRowClick={(item) => setDetail({ id: item.recipient_id, base: item })}
              sort={sort}
              onSortChange={setSort}
              emptyMessage="No people."
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
        open={detail !== null}
        title={person ? person.display_name || person.recipient_id : 'Person'}
        onClose={() => setDetail(null)}
      >
        {detailLoading ? <p className="muted">Loading details...</p> : null}
        {!detailLoading && detailError ? (
          <p className="error" role="alert">
            Full details unavailable: {detailError}
          </p>
        ) : null}
        {person ? (
          <>
            <dl className="kv">
              <dt>Display name</dt>
              <dd>{person.display_name || 'Not set'}</dd>
              <dt>Recipient ID</dt>
              <dd>
                <Copyable value={person.recipient_id} label="recipient ID" />
              </dd>
              <dt>Key storage</dt>
              <dd>
                <span className="badge">{storageLabel(person.key_storage)}</span>{' '}
                <InfoTip label="key storage">
                  Encrypted means the private key is protected by the account passphrase. Legacy
                  means the key was created before passphrase protection was introduced.
                </InfoTip>
              </dd>
              <dt>Registered</dt>
              <dd>{formatDate(person.created_at)}</dd>
              <dt>Signing algorithm</dt>
              <dd>{person.mldsa_variant || 'Unknown'}</dd>
              <dt>Key exchange algorithm</dt>
              <dd>{person.mlkem_variant || 'Unknown'}</dd>
              <dt>Documents owned</dt>
              <dd>{person.documents_owned ?? 0}</dd>
              <dt>Documents shared</dt>
              <dd>{person.documents_shared ?? 0}</dd>
            </dl>

            <h3 className="detail-heading">Public key fingerprints</h3>
            <dl className="kv">
              <dt>
                ML-DSA fingerprint{' '}
                <InfoTip label="ML-DSA fingerprint">
                  A short hash of this user&apos;s signing public key. Use it to confirm that
                  documents signed by this account are really from them.
                </InfoTip>
              </dt>
              <dd>
                <Copyable value={person.mldsa_fingerprint} label="ML-DSA fingerprint" />
              </dd>
              <dt>
                ML-KEM fingerprint{' '}
                <InfoTip label="ML-KEM fingerprint">
                  A short hash of this user&apos;s encryption public key. Use it to confirm that
                  files encrypted for them can only be opened by them.
                </InfoTip>
              </dt>
              <dd>
                <Copyable value={person.mlkem_fingerprint} label="ML-KEM fingerprint" />
              </dd>
            </dl>
            <p className="muted">
              Fingerprints are short representations of public keys. They contain no private data
              and cannot be used to decrypt anything.
            </p>
          </>
        ) : null}
        {!detailLoading && !person && !detailError && detail ? (
          <p className="muted">No details available for this user.</p>
        ) : null}
      </DetailDrawer>
    </div>
  )
}
