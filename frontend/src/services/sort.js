export function sortRows(rows, sort, accessors) {
  if (!sort || !sort.key) return rows
  const accessor = accessors[sort.key]
  if (!accessor) return rows
  const direction = sort.dir === 'desc' ? -1 : 1

  return [...rows].sort((a, b) => {
    const left = accessor(a)
    const right = accessor(b)
    if (left === null || left === undefined) {
      if (right === null || right === undefined) return 0
      return -1 * direction
    }
    if (right === null || right === undefined) return 1 * direction
    if (typeof left === 'number' && typeof right === 'number') {
      return (left - right) * direction
    }
    return (
      String(left).localeCompare(String(right), undefined, { sensitivity: 'base', numeric: true }) *
      direction
    )
  })
}

export function matchesAny(values, query) {
  const needle = String(query === null || query === undefined ? '' : query)
    .trim()
    .toLowerCase()
  if (!needle) return true
  return values.some((value) =>
    String(value === null || value === undefined ? '' : value)
      .toLowerCase()
      .includes(needle)
  )
}
