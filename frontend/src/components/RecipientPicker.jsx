import { useMemo, useState } from 'react'
import { SearchInput } from './SearchInput.jsx'
import { Avatar } from './Avatar.jsx'

function storageLabel(value) {
  const key = String(value || '').toLowerCase()
  if (key === 'encrypted') return 'Protected'
  if (key === 'legacy') return 'Demo key'
  return value ? String(value) : 'Unknown'
}

function sortByName(list) {
  return [...list].sort((a, b) =>
    String(a.display_name || a.recipient_id || '').localeCompare(
      String(b.display_name || b.recipient_id || ''),
      undefined,
      { sensitivity: 'base' }
    )
  )
}

function displayName(person) {
  return person.display_name || person.recipient_id
}

export function RecipientPicker({
  id,
  people,
  loading,
  error,
  onRetry,
  selected,
  onChange,
  excludeId,
  disabled,
}) {
  const [search, setSearch] = useState('')

  const selectedSet = useMemo(() => new Set(selected), [selected])
  const exclude = String(excludeId || '').toLowerCase()

  const candidates = useMemo(
    () =>
      sortByName(
        people.filter(
          (person) => String(person.recipient_id || '').toLowerCase() !== exclude
        )
      ),
    [people, exclude]
  )

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase()
    if (!needle) return candidates
    return candidates.filter((person) =>
      [person.display_name, person.recipient_id].some((value) =>
        String(value || '').toLowerCase().includes(needle)
      )
    )
  }, [candidates, search])

  const selectedPeople = filtered.filter((person) => selectedSet.has(person.recipient_id))
  const otherPeople = filtered.filter((person) => !selectedSet.has(person.recipient_id))
  const selectedChips = sortByName(
    candidates.filter((person) => selectedSet.has(person.recipient_id))
  )

  const allFilteredSelected =
    filtered.length > 0 && filtered.every((person) => selectedSet.has(person.recipient_id))
  const anyFilteredSelected = filtered.some((person) => selectedSet.has(person.recipient_id))

  const toggle = (recipientId) => {
    if (disabled) return
    onChange(
      selectedSet.has(recipientId)
        ? selected.filter((value) => value !== recipientId)
        : [...selected, recipientId]
    )
  }

  const selectAll = () => {
    if (disabled || filtered.length === 0) return
    const next = new Set(selected)
    filtered.forEach((person) => next.add(person.recipient_id))
    onChange(Array.from(next))
  }

  const clearFiltered = () => {
    if (disabled) return
    const remove = new Set(filtered.map((person) => person.recipient_id))
    onChange(selected.filter((value) => !remove.has(value)))
  }

  const renderOption = (person) => {
    const isSelected = selectedSet.has(person.recipient_id)
    return (
      <button
        type="button"
        key={person.recipient_id}
        className={`person-option ${isSelected ? 'selected' : ''}`}
        aria-pressed={isSelected}
        disabled={disabled}
        onClick={() => toggle(person.recipient_id)}
      >
        <Avatar name={displayName(person)} id={person.recipient_id} size="sm" />
        <span className="person-option-main">
          <span className="person-option-name">{displayName(person)}</span>
          <span className="person-option-sub mono">{person.recipient_id}</span>
        </span>
        <span className="badge">{storageLabel(person.key_storage)}</span>
        {typeof person.documents_shared === 'number' ? (
          <span className="person-option-count muted">{person.documents_shared} shared</span>
        ) : null}
      </button>
    )
  }

  return (
    <div className="picker" id={id}>
      <div className="picker-head">
        <span className="field-label">People</span>
        <span className="picker-count muted">
          {selected.length} {selected.length === 1 ? 'person' : 'people'} can decrypt this
        </span>
      </div>

      {selectedChips.length > 0 ? (
        <ul className="chips">
          {selectedChips.map((person) => (
            <li className="chip" key={person.recipient_id}>
              <Avatar name={displayName(person)} id={person.recipient_id} size="sm" />
              <span className="chip-name">{displayName(person)}</span>
              <button
                type="button"
                className="chip-remove"
                aria-label={`Remove ${displayName(person)}`}
                disabled={disabled}
                onClick={() => toggle(person.recipient_id)}
              >
                x
              </button>
            </li>
          ))}
        </ul>
      ) : null}

      <p className="muted picker-note">
        You keep owner access; recipients listed here can decrypt.
      </p>

      <div className="picker-controls">
        <SearchInput
          id={`${id}-search`}
          value={search}
          onChange={setSearch}
          placeholder="Search by name or ID"
          label="Search people"
          disabled={disabled || loading}
        />
        <div className="picker-actions">
          <button
            type="button"
            className="link-btn"
            onClick={selectAll}
            disabled={disabled || loading || allFilteredSelected || filtered.length === 0}
          >
            Select all
          </button>
          <button
            type="button"
            className="link-btn"
            onClick={clearFiltered}
            disabled={disabled || !anyFilteredSelected}
          >
            Clear
          </button>
        </div>
      </div>

      {loading ? <p className="muted">Loading people...</p> : null}
      {!loading && error ? (
        <p className="error">
          {error}{' '}
          <button type="button" className="link-btn" onClick={onRetry}>
            Retry
          </button>
        </p>
      ) : null}
      {!loading && !error && filtered.length === 0 ? (
        <p className="muted picker-empty">No people match.</p>
      ) : null}

      {!loading && !error && filtered.length > 0 ? (
        <div className="picker-list">
          {selectedPeople.length > 0 ? (
            <div className="picker-group">
              <p className="picker-group-title">Selected</p>
              {selectedPeople.map(renderOption)}
            </div>
          ) : null}
          {otherPeople.length > 0 ? (
            <div className="picker-group">
              <p className="picker-group-title">Everyone else</p>
              {otherPeople.map(renderOption)}
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}
