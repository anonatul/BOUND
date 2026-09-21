import { useCallback, useEffect, useState } from 'react'
import { api, clearToken, getToken, setUnauthorizedHandler } from './services/api.js'
import { GlobalSearch } from './components/GlobalSearch.jsx'
import { AppNav } from './components/AppNav.jsx'
import { UserMenu } from './components/UserMenu.jsx'
import { UnlockDialog } from './components/UnlockDialog.jsx'
import { useToast } from './components/Toasts.jsx'
import { Login } from './pages/Login.jsx'
import { Files } from './pages/Files.jsx'
import { SharedWithMe } from './pages/SharedWithMe.jsx'
import { People } from './pages/People.jsx'
import { Verify } from './pages/Verify.jsx'
import { Audit } from './pages/Audit.jsx'
import { Demo } from './pages/Demo.jsx'

const MAIN_ITEMS = [
  { id: 'files', label: 'Files', icon: 'files' },
  { id: 'shared', label: 'Shared with me', icon: 'shared' },
  { id: 'people', label: 'People', icon: 'people' },
  { id: 'verify', label: 'Verify', icon: 'verify' },
  { id: 'audit', label: 'Audit', icon: 'audit' },
]

const SECONDARY_ITEMS = [{ id: 'demo', label: 'Security demos', icon: 'demo' }]

export default function App() {
  const toast = useToast()
  const [user, setUser] = useState(null)
  const [session, setSession] = useState({ unlocked: false, unlockExpiresAt: null })
  const [booting, setBooting] = useState(true)
  const [page, setPage] = useState('files')
  const [focus, setFocus] = useState(null)
  const [ledgerVersion, setLedgerVersion] = useState(0)
  const [unlockOpen, setUnlockOpen] = useState(false)
  const [locking, setLocking] = useState(false)

  const applySession = useCallback((payload) => {
    if (!payload) return
    setSession({
      unlocked: Boolean(payload.unlocked),
      unlockExpiresAt: payload.unlock_expires_at || null,
    })
  }, [])

  const refreshSession = useCallback(async () => {
    try {
      const data = await api.me()
      if (data.user) setUser(data.user)
      applySession(data)
    } catch {
      // 401 is handled globally by the api layer
    }
  }, [applySession])

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setUser(null)
      setSession({ unlocked: false, unlockExpiresAt: null })
    })

    let active = true
    async function restoreSession() {
      if (!getToken()) {
        if (active) setBooting(false)
        return
      }
      try {
        const data = await api.me()
        if (!active) return
        setUser(data.user || null)
        applySession(data)
      } catch {
        if (active) setUser(null)
      } finally {
        if (active) setBooting(false)
      }
    }

    restoreSession()
    return () => {
      active = false
    }
  }, [applySession])

  const navigate = useCallback((nextPage, nextFocus = null) => {
    setPage(nextPage)
    setFocus(nextFocus ? { ...nextFocus } : null)
  }, [])

  const handleFocusHandled = useCallback(() => setFocus(null), [])

  const handleSignedIn = useCallback(
    (nextUser) => {
      setUser(nextUser)
      setPage('files')
      setFocus(null)
      setUnlockOpen(false)
      refreshSession()
    },
    [refreshSession]
  )

  const handleSignOut = useCallback(async () => {
    try {
      await api.logout()
    } catch {
      // session may already be gone
    }
    clearToken()
    setUser(null)
    setSession({ unlocked: false, unlockExpiresAt: null })
    setPage('files')
    setFocus(null)
    setUnlockOpen(false)
  }, [])

  const handleLock = useCallback(async () => {
    setLocking(true)
    try {
      await api.lock()
      setSession({ unlocked: false, unlockExpiresAt: null })
      toast.push('Session locked.', 'info')
    } catch (err) {
      toast.push(err.message, 'error')
    } finally {
      setLocking(false)
    }
  }, [toast])

  const handleUnlocked = useCallback(() => {
    setUnlockOpen(false)
    refreshSession()
    toast.push('Keys unlocked.', 'success')
  }, [refreshSession, toast])

  const handleGlobalSelect = useCallback(
    (result) => {
      if (result.kind === 'document') {
        navigate(result.role === 'recipient' ? 'shared' : 'files', {
          type: 'document',
          documentId: result.document_id,
        })
      } else if (result.kind === 'recipient') {
        navigate('people', { type: 'recipient', recipientId: result.recipient_id })
      } else if (result.kind === 'ledger') {
        navigate('audit', {
          type: 'ledger',
          sessionId: result.session_id,
          documentId: result.document_id,
          watermarkId: result.watermark_id,
        })
      }
    },
    [navigate]
  )

  if (booting) {
    return (
      <div className="booting">
        <span className="muted">Loading...</span>
      </div>
    )
  }

  if (!user) {
    return <Login onSignedIn={handleSignedIn} />
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">BOUND Documents</div>
        <div className="sidebar-nav">
          <AppNav items={MAIN_ITEMS} current={page} onSelect={navigate} ariaLabel="Main" />
        </div>
        <div className="sidebar-spacer" />
        <div className="sidebar-bottom">
          <p className="sidebar-section-title">Secondary</p>
          <AppNav
            items={SECONDARY_ITEMS}
            current={page}
            onSelect={navigate}
            ariaLabel="Secondary"
          />
        </div>
      </aside>

      <div className="app-main">
        <header className="topbar">
          <div className="topbar-inner">
            <div className="mobile-brand">BOUND Documents</div>
            <div className="topbar-search">
              <GlobalSearch onSelect={handleGlobalSelect} />
            </div>
            <UserMenu
              user={user}
              unlocked={session.unlocked}
              unlockExpiresAt={session.unlockExpiresAt}
              locking={locking}
              onLock={handleLock}
              onUnlock={() => setUnlockOpen(true)}
              onSignOut={handleSignOut}
            />
          </div>
        </header>

        <div className="mobile-nav-wrap">
          <AppNav items={MAIN_ITEMS} current={page} onSelect={navigate} ariaLabel="Main" />
          <AppNav
            items={SECONDARY_ITEMS}
            current={page}
            onSelect={navigate}
            ariaLabel="Secondary"
          />
        </div>

        <main className="content">
          {page === 'files' && (
            <Files user={user} focus={focus} onFocusHandled={handleFocusHandled} />
          )}
          {page === 'shared' && (
            <SharedWithMe
              unlocked={session.unlocked}
              focus={focus}
              onFocusHandled={handleFocusHandled}
              onSessionChanged={refreshSession}
              onOpenAudit={(sessionId) => navigate('audit', { type: 'ledger', sessionId })}
            />
          )}
          {page === 'people' && <People focus={focus} onFocusHandled={handleFocusHandled} />}
          {page === 'verify' && (
            <Verify
              onOpenDocument={(documentId, role) =>
                navigate(role === 'recipient' ? 'shared' : 'files', {
                  type: 'document',
                  documentId,
                })
              }
              onOpenAudit={(sessionId) => navigate('audit', { type: 'ledger', sessionId })}
            />
          )}
          {page === 'audit' && (
            <Audit focus={focus} onFocusHandled={handleFocusHandled} ledgerVersion={ledgerVersion} />
          )}
          {page === 'demo' && <Demo onDemoComplete={() => setLedgerVersion((v) => v + 1)} />}
        </main>
      </div>

      <UnlockDialog
        open={unlockOpen}
        title="Unlock keys"
        message="Enter your passphrase to unlock your private keys for this session."
        onClose={() => setUnlockOpen(false)}
        onUnlocked={handleUnlocked}
      />
    </div>
  )
}
