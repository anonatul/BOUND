export function extensionOf(name) {
  const value = String(name || '')
  const index = value.lastIndexOf('.')
  if (index < 0 || index === value.length - 1) return ''
  return value.slice(index + 1).toLowerCase()
}

export function fileTypeLabel(name) {
  const extension = extensionOf(name)
  if (!extension) return 'FILE'
  return extension.toUpperCase().slice(0, 6)
}

export function isZipName(name) {
  return extensionOf(name) === 'zip'
}

const FORMAT_LABELS = {
  pdf: 'PDF',
  image: 'image',
  text: 'text',
  ooxml: 'OOXML',
  container: 'ZIP container',
  zip: 'ZIP container',
  unknown: 'unknown',
}

export function formatLabel(format) {
  if (!format) return ''
  const key = String(format).toLowerCase()
  return FORMAT_LABELS[key] || String(format)
}
