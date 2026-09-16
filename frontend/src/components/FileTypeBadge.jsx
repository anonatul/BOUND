import { fileTypeLabel } from '../services/fileTypes.js'

export function FileTypeBadge({ name }) {
  return <span className="badge type-badge">{fileTypeLabel(name)}</span>
}
