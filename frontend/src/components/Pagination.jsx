export function Pagination({ page, pageSize, total, onPageChange, onPageSizeChange }) {
  const pageCount = Math.max(1, Math.ceil(total / pageSize))
  const current = Math.min(Math.max(page, 1), pageCount)
  const from = total === 0 ? 0 : (current - 1) * pageSize + 1
  const to = Math.min(total, current * pageSize)

  return (
    <div className="pagination">
      <span className="muted">
        Showing {from}-{to} of {total}
      </span>
      <div className="pagination-controls">
        {onPageSizeChange ? (
          <label className="page-size">
            <span className="muted">Rows</span>
            <select
              className="input input-inline"
              value={pageSize}
              onChange={(event) => onPageSizeChange(Number(event.target.value))}
            >
              {[10, 15, 25, 50].map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
          </label>
        ) : null}
        <button
          type="button"
          className="btn small"
          disabled={current <= 1}
          onClick={() => onPageChange(current - 1)}
        >
          Previous
        </button>
        <span className="muted">
          Page {current} of {pageCount}
        </span>
        <button
          type="button"
          className="btn small"
          disabled={current >= pageCount}
          onClick={() => onPageChange(current + 1)}
        >
          Next
        </button>
      </div>
    </div>
  )
}
