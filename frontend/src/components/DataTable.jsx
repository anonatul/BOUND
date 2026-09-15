import { Fragment } from 'react'

export function DataTable({
  columns,
  rows,
  getRowKey,
  onRowClick,
  sort,
  onSortChange,
  emptyMessage,
  expandedKey,
  renderExpanded,
}) {
  const handleSort = (key) => {
    if (!onSortChange) return
    if (sort && sort.key === key) {
      onSortChange({ key, dir: sort.dir === 'asc' ? 'desc' : 'asc' })
    } else {
      onSortChange({ key, dir: 'asc' })
    }
  }

  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            {columns.map((column) => (
              <th
                key={column.key}
                aria-sort={
                  sort && sort.key === column.key
                    ? sort.dir === 'asc'
                      ? 'ascending'
                      : 'descending'
                    : undefined
                }
              >
                {column.sortable ? (
                  <button type="button" className="th-sort" onClick={() => handleSort(column.key)}>
                    {column.label}
                    <span className="sort-mark" aria-hidden="true">
                      {sort && sort.key === column.key ? (sort.dir === 'asc' ? 'asc' : 'desc') : ''}
                    </span>
                  </button>
                ) : (
                  column.label
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const key = getRowKey(row)
            const expanded = expandedKey !== undefined && expandedKey !== null && expandedKey === key
            return (
              <Fragment key={key}>
                <tr
                  className={onRowClick ? 'row-click' : undefined}
                  tabIndex={onRowClick ? 0 : undefined}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                  onKeyDown={
                    onRowClick
                      ? (event) => {
                          if (event.key === 'Enter' || event.key === ' ') {
                            event.preventDefault()
                            onRowClick(row)
                          }
                        }
                      : undefined
                  }
                >
                  {columns.map((column) => (
                    <td key={column.key}>
                      {column.render ? column.render(row) : row[column.key]}
                    </td>
                  ))}
                </tr>
                {expanded && renderExpanded ? (
                  <tr className="expand-row">
                    <td colSpan={columns.length}>{renderExpanded(row)}</td>
                  </tr>
                ) : null}
              </Fragment>
            )
          })}
          {rows.length === 0 ? (
            <tr>
              <td className="muted" colSpan={columns.length}>
                {emptyMessage || 'No records.'}
              </td>
            </tr>
          ) : null}
        </tbody>
      </table>
    </div>
  )
}
