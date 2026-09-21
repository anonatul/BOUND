import { useEffect, useRef, useState } from 'react'
import { formatDate } from '../services/format.js'
import { Avatar } from './Avatar.jsx'

export function UserMenu({
  user,
  unlocked,
  unlockExpiresAt,
  locking,
  onLock,
  onUnlock,
  onSignOut,
}) {
  const [open, setOpen] = useState(false)
  const wrapRef = useRef(null)

  useEffect(() => {
    if (!open) return undefined
    function handlePointerDown(event) {
      if (wrapRef.current && !wrapRef.current.contains(event.target)) setOpen(false)
    }
    function handleKey(event) {
      if (event.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', handlePointerDown)
    document.addEventListener('keydown', handleKey)
    return () => {
      document.removeEventListener('mousedown', handlePointerDown)
      document.removeEventListener('keydown', handleKey)
    }
  }, [open])

  const name = user.display_name || user.username

  return (
    <div className="user-menu" ref={wrapRef}>
      <button
        type="button"
        className="user-menu-trigger"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((current) => !current)}
      >
        <Avatar name={name} id={user.recipient_id || user.username} />
        <span className="user-menu-name">{name}</span>
      </button>

      {open ? (
        <div className="user-menu-panel" role="menu">
          <div className="user-menu-info">
            <p className="user-menu-title">{name}</p>
            <p className="mono muted">{user.recipient_id || user.username}</p>
          </div>

          <div className="user-menu-status">
            <span className={unlocked ? 'badge ok' : 'badge'}>
              {unlocked ? 'Keys unlocked' : 'Keys locked'}
            </span>
            {unlocked && unlockExpiresAt ? (
              <p className="muted">Expires {formatDate(unlockExpiresAt)}</p>
            ) : null}
          </div>

          {unlocked ? (
            <button
              type="button"
              className="btn small"
              role="menuitem"
              onClick={onLock}
              disabled={locking}
            >
              {locking ? 'Locking...' : 'Lock session'}
            </button>
          ) : (
            <button
              type="button"
              className="btn small"
              role="menuitem"
              onClick={() => {
                setOpen(false)
                onUnlock()
              }}
            >
              Unlock keys
            </button>
          )}

          <button
            type="button"
            className="btn small"
            role="menuitem"
            onClick={() => {
              setOpen(false)
              onSignOut()
            }}
          >
            Sign out
          </button>
        </div>
      ) : null}
    </div>
  )
}
