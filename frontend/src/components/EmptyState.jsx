export function EmptyState({ title, message, actionLabel, onAction }) {
  return (
    <div className="empty">
      <p className="empty-title">{title}</p>
      {message ? <p className="muted">{message}</p> : null}
      {actionLabel && onAction ? (
        <button type="button" className="btn small" onClick={onAction}>
          {actionLabel}
        </button>
      ) : null}
    </div>
  )
}
