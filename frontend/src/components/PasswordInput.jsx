import { useState } from 'react'

export function PasswordInput({ id, value, onChange, autoComplete, disabled, onBlur }) {
  const [visible, setVisible] = useState(false)

  return (
    <div className="password-wrap">
      <input
        id={id}
        className="input"
        type={visible ? 'text' : 'password'}
        value={value}
        autoComplete={autoComplete}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value)}
        onBlur={onBlur}
      />
      <button
        type="button"
        className="password-toggle"
        aria-pressed={visible}
        aria-label={visible ? 'Hide passphrase' : 'Show passphrase'}
        onClick={() => setVisible((current) => !current)}
      >
        {visible ? 'Hide' : 'Show'}
      </button>
    </div>
  )
}
