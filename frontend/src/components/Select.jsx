export function Select({ id, label, value, onChange, options, disabled, className }) {
  return (
    <div className={className || 'field'}>
      {label ? <label htmlFor={id}>{label}</label> : null}
      <select
        id={id}
        className="input"
        value={value}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value)}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  )
}
