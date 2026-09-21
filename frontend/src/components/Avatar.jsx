const PALETTE = ['#dfeaf5', '#e3f1e6', '#f7ecdd', '#f0e5f4', '#e0eff2', '#efeae0']

function hashText(text) {
  let hash = 0
  for (let index = 0; index < text.length; index += 1) {
    hash = (hash * 31 + text.charCodeAt(index)) % 100000
  }
  return hash
}

function initials(name, id) {
  const text = String(name || id || '').trim()
  if (!text) return '?'
  const parts = text.split(/\s+/).filter(Boolean)
  if (parts.length >= 2) return `${parts[0][0]}${parts[1][0]}`.toUpperCase()
  return text.slice(0, 2).toUpperCase()
}

export function Avatar({ name, id, size = 'md' }) {
  const key = String(id || name || '?')
  return (
    <span
      className={`avatar avatar-${size}`}
      style={{ background: PALETTE[hashText(key) % PALETTE.length] }}
      aria-hidden="true"
    >
      {initials(name, id)}
    </span>
  )
}
