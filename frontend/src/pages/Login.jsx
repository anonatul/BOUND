import { useEffect, useState } from 'react'
import { api } from '../services/api.js'
import { PasswordInput } from '../components/PasswordInput.jsx'
import { useDebouncedValue } from '../hooks/useDebouncedValue.js'

const MIN_PASSPHRASE = 8

export function Login({ onSignedIn }) {
  const [mode, setMode] = useState('signin')
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [fieldErrors, setFieldErrors] = useState({})
  const [formError, setFormError] = useState('')
  const [loading, setLoading] = useState(false)
  const [availability, setAvailability] = useState(null)
  const [checking, setChecking] = useState(false)

  const isRegister = mode === 'register'
  const trimmedUsername = username.trim()
  const debouncedUsername = useDebouncedValue(trimmedUsername, 400)

  const availabilityMatches =
    availability &&
    availability.username &&
    availability.username.toLowerCase() === trimmedUsername.toLowerCase()

  useEffect(() => {
    if (!isRegister) {
      setAvailability(null)
      setChecking(false)
      return undefined
    }
    if (debouncedUsername.length < 2) {
      setAvailability(null)
      setChecking(false)
      return undefined
    }

    let active = true
    setChecking(true)
    api
      .usernameAvailable(debouncedUsername)
      .then((data) => {
        if (active) setAvailability(data)
      })
      .catch(() => {
        if (active) setAvailability(null)
      })
      .finally(() => {
        if (active) setChecking(false)
      })

    return () => {
      active = false
    }
  }, [debouncedUsername, isRegister])

  const handleUsernameBlur = async () => {
    if (!isRegister || trimmedUsername.length < 2) return
    setChecking(true)
    try {
      setAvailability(await api.usernameAvailable(trimmedUsername))
    } catch {
      setAvailability(null)
    } finally {
      setChecking(false)
    }
  }

  const handleSubmit = async (event) => {
    event.preventDefault()
    const errors = {}

    if (!trimmedUsername) errors.username = 'Enter a username.'
    else if (isRegister && trimmedUsername.length < 2) {
      errors.username = 'Username must be at least 2 characters.'
    }
    if (!passphrase) errors.passphrase = 'Enter your passphrase.'
    if (isRegister && !displayName.trim()) errors.displayName = 'Enter a display name.'
    if (isRegister && availabilityMatches && availability.available === false) {
      errors.username = availability.reason || 'That username is already taken.'
    }

    setFieldErrors(errors)
    setFormError('')
    if (Object.keys(errors).length > 0) return

    setLoading(true)
    try {
      if (isRegister) {
        let check = null
        try {
          check = await api.usernameAvailable(trimmedUsername)
        } catch {
          check = null
        }
        if (check && check.available === false) {
          setAvailability(check)
          setFieldErrors({ username: check.reason || 'That username is already taken.' })
          return
        }
        await api.register(trimmedUsername, displayName.trim(), passphrase)
      }
      const session = await api.login(trimmedUsername, passphrase)
      onSignedIn(session.user)
    } catch (err) {
      setFormError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const switchMode = () => {
    setMode(isRegister ? 'signin' : 'register')
    setFieldErrors({})
    setFormError('')
    setAvailability(null)
  }

  const usernameMessage = (() => {
    if (!isRegister || trimmedUsername.length < 2) return null
    if (checking) return { className: 'availability muted', text: 'Checking availability...' }
    if (!availabilityMatches) return null
    if (availability.available === false) {
      return {
        className: 'availability bad',
        text: availability.reason || 'That username is already taken.',
      }
    }
    return { className: 'availability ok', text: 'Username is available.' }
  })()

  return (
    <div className="login-wrap">
      <div className="card login-card">
        <h1>BOUND Documents</h1>
        <p className="muted">Internal document sharing.</p>
        <h2 className="login-heading">{isRegister ? 'Create account' : 'Sign in'}</h2>

        <form onSubmit={handleSubmit} noValidate>
          <div className="field">
            <label htmlFor="login-username">Username</label>
            <input
              id="login-username"
              className="input"
              type="text"
              value={username}
              autoComplete="username"
              disabled={loading}
              onChange={(event) => setUsername(event.target.value)}
              onBlur={handleUsernameBlur}
              aria-describedby={usernameMessage ? 'login-username-status' : undefined}
            />
            {usernameMessage ? (
              <p id="login-username-status" className={usernameMessage.className}>
                {usernameMessage.text}
              </p>
            ) : null}
            {fieldErrors.username ? (
              <p className="field-error" role="alert">
                {fieldErrors.username}
              </p>
            ) : null}
          </div>

          {isRegister && (
            <div className="field">
              <label htmlFor="login-display-name">Display name</label>
              <input
                id="login-display-name"
                className="input"
                type="text"
                value={displayName}
                autoComplete="name"
                disabled={loading}
                onChange={(event) => setDisplayName(event.target.value)}
              />
              {fieldErrors.displayName ? (
                <p className="field-error" role="alert">
                  {fieldErrors.displayName}
                </p>
              ) : null}
            </div>
          )}

          <div className="field">
            <label htmlFor="login-passphrase">Passphrase</label>
            <PasswordInput
              id="login-passphrase"
              value={passphrase}
              autoComplete={isRegister ? 'new-password' : 'current-password'}
              disabled={loading}
              onChange={setPassphrase}
            />
            {isRegister ? (
              <p className="hint muted">
                Use at least {MIN_PASSPHRASE} characters.{' '}
                {passphrase
                  ? `${passphrase.length} entered${passphrase.length >= MIN_PASSPHRASE ? '' : ', too short'}.`
                  : ''}
              </p>
            ) : null}
            {fieldErrors.passphrase ? (
              <p className="field-error" role="alert">
                {fieldErrors.passphrase}
              </p>
            ) : null}
          </div>

          {formError ? (
            <p className="error" role="alert">
              {formError}
            </p>
          ) : null}

          <div className="form-actions">
            <button
              type="submit"
              className="btn primary"
              disabled={
                loading ||
                (isRegister && availabilityMatches && availability.available === false)
              }
            >
              {loading ? 'Please wait...' : isRegister ? 'Create account' : 'Sign in'}
            </button>
          </div>
        </form>

        <div className="login-footer">
          <button type="button" className="link-btn" onClick={switchMode} disabled={loading}>
            {isRegister ? 'Back to sign in' : 'Create an account'}
          </button>
          <p className="muted mono">Demo: ALICE / demo12345</p>
        </div>
      </div>
    </div>
  )
}
