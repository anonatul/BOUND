export function SearchInput({ id, value, onChange, placeholder, label, disabled }) {
  return (
    <div className="search-input">
      <input
        id={id}
        className="input"
        type="text"
        value={value}
        placeholder={placeholder}
        aria-label={label || placeholder || 'Search'}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value)}
      />
      {value ? (
        <button type="button" className="search-clear" onClick={() => onChange('')} aria-label="Clear search">
          Clear
        </button>
      ) : null}
    </div>
  )
}
