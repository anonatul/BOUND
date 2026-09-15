import { useEffect, useRef, useState } from 'react'

export function InfoTip({ label, children }) {
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

  return (
    <span className="infotip" ref={wrapRef}>
      <button
        type="button"
        className="infotip-btn"
        aria-expanded={open}
        aria-label={label ? `More information: ${label}` : 'More information'}
        onClick={() => setOpen((current) => !current)}
      >
        ?
      </button>
      {open ? (
        <span className="infotip-panel" role="note">
          {children}
        </span>
      ) : null}
    </span>
  )
}
