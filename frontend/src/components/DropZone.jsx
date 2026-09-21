import { useRef, useState } from 'react'
import { formatBytes } from '../services/format.js'
import { FileTypeBadge } from './FileTypeBadge.jsx'

export function DropZone({ id, file, onFile, disabled }) {
  const inputRef = useRef(null)
  const [dragActive, setDragActive] = useState(false)

  const acceptFiles = (fileList) => {
    if (disabled || !fileList || fileList.length === 0) return
    onFile(fileList[0])
  }

  const clear = () => {
    onFile(null)
    if (inputRef.current) inputRef.current.value = ''
  }

  return (
    <div
      className={`dropzone ${dragActive ? 'active' : ''} ${disabled ? 'disabled' : ''}`}
      onDragOver={(event) => {
        event.preventDefault()
        if (!disabled) setDragActive(true)
      }}
      onDragLeave={(event) => {
        event.preventDefault()
        setDragActive(false)
      }}
      onDrop={(event) => {
        event.preventDefault()
        setDragActive(false)
        acceptFiles(event.dataTransfer.files)
      }}
    >
      <input
        id={id}
        ref={inputRef}
        className="visually-hidden-file"
        type="file"
        disabled={disabled}
        onChange={(event) => acceptFiles(event.target.files)}
      />

      {file ? (
        <div className="dropzone-file">
          <div className="dropzone-file-info">
            <span className="dropzone-file-main">
              <FileTypeBadge name={file.name} />
              <span className="dropzone-name">{file.name}</span>
            </span>
            <span className="muted">{formatBytes(file.size)}</span>
          </div>
          <div className="row-actions">
            <button
              type="button"
              className="btn small"
              disabled={disabled}
              onClick={() => inputRef.current && inputRef.current.click()}
            >
              Change
            </button>
            <button type="button" className="btn small" disabled={disabled} onClick={clear}>
              Remove
            </button>
          </div>
        </div>
      ) : (
        <label className="dropzone-empty" htmlFor={id}>
          <span>Drag a file here or click to browse</span>
          <span className="muted">Any file type</span>
        </label>
      )}
    </div>
  )
}
