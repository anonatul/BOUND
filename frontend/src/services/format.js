export function formatDate(value) {
  if (!value) return 'Unknown'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function formatBytes(value) {
  const size = Number(value)
  if (!Number.isFinite(size)) return 'Unknown'
  if (size < 1024) return `${size} B`
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`
  return `${(size / (1024 * 1024)).toFixed(1)} MB`
}

export function shortHash(value, length = 12) {
  if (!value) return 'Unknown'
  const text = String(value)
  return text.length > length ? `${text.slice(0, length)}...` : text
}
