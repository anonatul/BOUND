import { useState } from 'react'
import { useToast } from './Toasts.jsx'

async function copyText(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    await navigator.clipboard.writeText(text)
    return
  }
  const area = document.createElement('textarea')
  area.value = text
  area.setAttribute('readonly', '')
  area.style.position = 'fixed'
  area.style.opacity = '0'
  document.body.appendChild(area)
  area.select()
  document.execCommand('copy')
  document.body.removeChild(area)
}

export function Copyable({ value, display, label }) {
  const toast = useToast()
  const [feedback, setFeedback] = useState('')

  const text = value === null || value === undefined ? '' : String(value)

  const handleCopy = async () => {
    if (!text) return
    try {
      await copyText(text)
      setFeedback('Copied')
      toast.push(label ? `Copied ${label}.` : 'Copied to clipboard.', 'success')
    } catch {
      setFeedback('Failed')
      toast.push('Copy failed.', 'error')
    }
    window.setTimeout(() => setFeedback(''), 1500)
  }

  return (
    <span className="copyable">
      <span className="mono break" title={text || undefined}>
        {display || text || 'Unknown'}
      </span>
      <button
        type="button"
        className="link-btn copy-btn"
        onClick={handleCopy}
        disabled={!text}
        aria-label={label ? `Copy ${label}` : 'Copy value'}
      >
        {feedback || 'Copy'}
      </button>
    </span>
  )
}
