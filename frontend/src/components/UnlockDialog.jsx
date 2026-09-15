import { useEffect, useId, useState } from 'react'
import { api } from '../services/api.js'
import { PasswordInput } from './PasswordInput.jsx'

export function UnlockDialog({ open, title, message, onClose, onUnlocked }) {
  const passphraseId = useId()
  const [passphrase, setPassphrase] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return undefined
    setPassphrase('')
    setError('')
    setBusy(false)
    function handleKey(event) {
      if (event.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handleKey)
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', handleKey)
      document.body.style.overflow = previousOverflow
    }
  }, [open, onClose])

  if (!open) return null

  const handleSubmit = async (event) => {
    event.preventDefault()
    if (!passphrase) {
      setError('Enter your passphrase.')
      return
    }
    setBusy(true)
    setError('')
    try {
      await api.unlock(passphrase)
      setPassphrase('')
      if (onUnlocked) onUnlocked()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal-overlay" onMouseDown={onClose}>
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="unlock-dialog-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="modal-head">
          <h2 id="unlock-dialog-title">{title || 'Unlock keys'}</h2>
          <button type="button" className="btn small" onClick={onClose}>
            Close
          </button>
        </div>
        <p className="muted">
          {message || 'Enter your passphrase to unlock your private keys for this session.'}
        </p>
        <form onSubmit={handleSubmit}>
          <div className="field">
            <label htmlFor={passphraseId}>Passphrase</label>
            <PasswordInput
              id={passphraseId}
              value={passphrase}
              autoComplete="current-password"
              disabled={busy}
              onChange={setPassphrase}
            />
          </div>
          {error ? (
            <p className="error" role="alert">
              {error}
            </p>
          ) : null}
          <div className="form-actions">
            <button type="submit" className="btn primary" disabled={busy}>
              {busy ? 'Unlocking...' : 'Unlock'}
            </button>
            <button type="button" className="btn" onClick={onClose} disabled={busy}>
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
