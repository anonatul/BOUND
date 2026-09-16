import { useEffect, useState } from 'react'
import { api } from '../services/api.js'
import { formatDate } from '../services/format.js'
import { PageHeader } from '../components/PageHeader.jsx'
import { Copyable } from '../components/Copyable.jsx'
import { formatLabel } from '../services/fileTypes.js'

const PANEL_TITLES = {
  verified: 'Copy attributed',
  no_watermark: 'No watermark',
  no_ledger_match: 'No ledger match',
  signature_invalid: 'Signature invalid',
  ledger_tampered: 'Ledger tampered',
}

const PANEL_CLASSES = {
  verified: 'panel ok',
  no_watermark: 'panel bad',
  no_ledger_match: 'panel bad',
  signature_invalid: 'panel bad',
  ledger_tampered: 'panel bad',
}

function classify(result) {
  const status = String(result.status || '').toLowerCase()
  const known = {
    verified: 'verified',
    valid: 'verified',
    ok: 'verified',
    no_watermark: 'no_watermark',
    watermark_missing: 'no_watermark',
    watermark_not_found: 'no_watermark',
    no_ledger_match: 'no_ledger_match',
    ledger_no_match: 'no_ledger_match',
    ledger_mismatch: 'no_ledger_match',
    signature_invalid: 'signature_invalid',
    invalid_signature: 'signature_invalid',
    ledger_tampered: 'ledger_tampered',
    ledger_invalid: 'ledger_tampered',
  }
  if (known[status]) return known[status]
  if (result.watermark_detected === false) return 'no_watermark'
  if (result.ledger_match_found === false) return 'no_ledger_match'
  if (result.signature_valid === false) return 'signature_invalid'
  if (result.ledger_valid === false) return 'ledger_tampered'
  return 'verified'
}

function outcomeText(result, kind) {
  switch (kind) {
    case 'verified':
      return `This copy was issued to ${result.recipient_id || 'the recorded recipient'} in session ${
        result.session_id || 'unknown'
      } on ${formatDate(result.timestamp)}.`
    case 'no_watermark':
      return 'No watermark was found in this file. It cannot be attributed to a recipient.'
    case 'no_ledger_match':
      return 'A watermark was found, but there is no matching entry in the audit ledger. This is expected for copies issued before the ledger was reset or by another system, and it is also what a forged watermark would look like. Re-issue the copy from Shared with me to get a verifiable record.'
    case 'signature_invalid':
      return 'A ledger entry was found, but its signature did not verify. The record may have been tampered with.'
    case 'ledger_tampered':
      return 'The ledger integrity check failed. The audit record for this copy has been modified.'
    default:
      return ''
  }
}

function adviceText(kind) {
  switch (kind) {
    case 'verified':
      return 'No action needed. This copy matches the ledger record for the recipient above.'
    case 'no_watermark':
      return 'Treat the file as unverified. It was not issued through BOUND, or the watermark was removed after decryption.'
    case 'no_ledger_match':
      return 'Do not rely on this copy. The watermark does not correspond to any copy recorded in the ledger, so it may have been forged.'
    case 'signature_invalid':
      return 'Do not trust this record. Report the file to an administrator and keep the original for investigation.'
    case 'ledger_tampered':
      return 'Open the Audit page and use Re-sync from quorum to repair the affected nodes, then verify the file again.'
    default:
      return ''
  }
}

function CheckRow({ label, value }) {
  let text = 'Unknown'
  let className = 'muted'
  if (value === true) {
    text = 'Passed'
    className = 'result-pass'
  } else if (value === false) {
    text = 'Failed'
    className = 'result-fail'
  }
  return (
    <div className="check-row">
      <span>{label}</span>
      <span className={className}>{text}</span>
    </div>
  )
}

export function Verify({ onOpenDocument, onOpenAudit }) {
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const [documentRole, setDocumentRole] = useState(null)

  useEffect(() => {
    if (!result || !result.document_id) {
      setDocumentRole(null)
      return undefined
    }

    let active = true
    api
      .documents()
      .then((data) => {
        if (!active) return
        const doc = (data.documents || []).find(
          (item) => item.document_id === result.document_id
        )
        setDocumentRole(doc ? doc.role : null)
      })
      .catch(() => {
        if (active) setDocumentRole(null)
      })

    return () => {
      active = false
    }
  }, [result])

  const handleSubmit = async (event) => {
    event.preventDefault()
    if (!file) {
      setError('Choose a file to verify.')
      return
    }

    setLoading(true)
    setError('')
    setResult(null)
    try {
      setResult(await api.verify(file))
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const kind = result ? classify(result) : null

  return (
    <div>
      <PageHeader
        title="Verify"
        description="Check whether a copy of a shared file matches the audit ledger."
      />

      <section className="card">
        <h2>Upload a copy</h2>
        <p className="muted">
          The file is checked for a watermark, a ledger match and a valid signature.
        </p>

        <form onSubmit={handleSubmit}>
          <div className="field">
            <label htmlFor="verify-file">File</label>
            <input
              id="verify-file"
              className="input"
              type="file"
              disabled={loading}
              onChange={(event) =>
                setFile(event.target.files && event.target.files[0] ? event.target.files[0] : null)
              }
            />
          </div>

          {error ? (
            <p className="error" role="alert">
              {error}
            </p>
          ) : null}

          <div className="form-actions">
            <button type="submit" className="btn primary" disabled={loading}>
              {loading ? 'Verifying...' : 'Verify'}
            </button>
          </div>
        </form>
      </section>

      {result ? (
        <section className={PANEL_CLASSES[kind]}>
          <div className="card-head">
            <h3>{PANEL_TITLES[kind]}</h3>
            <span className="badge">{result.status || 'UNKNOWN'}</span>
          </div>
          <p>{outcomeText(result, kind)}</p>
          <p className="muted">{adviceText(kind)}</p>
          {result.format ? (
            <p className="muted">Analyzed as: {formatLabel(result.format)}.</p>
          ) : null}

          <div className="check-list">
            <CheckRow label="Watermark detected" value={result.watermark_detected} />
            <CheckRow label="Ledger match found" value={result.ledger_match_found} />
            <CheckRow label="Signature valid" value={result.signature_valid} />
            <CheckRow label="Ledger valid" value={result.ledger_valid} />
          </div>

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
            <dt>Document</dt>
            <dd>
              <Copyable value={result.document_id} label="document ID" />
            </dd>
            <dt>Time</dt>
            <dd>{formatDate(result.timestamp)}</dd>
          </dl>

          {result.message ? <p className="muted">{result.message}</p> : null}

          {result.document_id || result.session_id ? (
            <div className="form-actions">
              {result.document_id && documentRole === 'owner' ? (
                <button
                  type="button"
                  className="btn"
                  onClick={() => onOpenDocument(result.document_id, 'owner')}
                >
                  Open document in Files
                </button>
              ) : null}
              {result.document_id && documentRole === 'recipient' ? (
                <button
                  type="button"
                  className="btn"
                  onClick={() => onOpenDocument(result.document_id, 'recipient')}
                >
                  Open document in Shared with me
                </button>
              ) : null}
              {result.session_id ? (
                <button
                  type="button"
                  className="btn"
                  onClick={() => onOpenAudit(result.session_id)}
                >
                  View session in Audit
                </button>
              ) : null}
            </div>
          ) : null}
        </section>
      ) : null}
    </div>
  )
}
