const ICONS = {
  files: (
    <>
      <path d="M4.5 2.5h4.2l2.8 2.8v8.2h-7z" />
      <path d="M8.7 2.5v2.8h2.8" />
    </>
  ),
  shared: (
    <>
      <path d="M2.5 9.5h3l1 1.8h4l1-1.8h3" />
      <path d="M3.2 4.5h9.6l1.7 5v4h-13v-4z" />
    </>
  ),
  people: (
    <>
      <circle cx="8" cy="5.6" r="2.4" />
      <path d="M3.6 13.2c0.6-2.2 2.3-3.4 4.4-3.4s3.8 1.2 4.4 3.4" />
    </>
  ),
  verify: (
    <>
      <circle cx="8" cy="8" r="5.8" />
      <path d="M5.4 8.3l1.8 1.8 3.4-3.7" />
    </>
  ),
  audit: (
    <>
      <path d="M3 4.2h10" />
      <path d="M3 8h10" />
      <path d="M3 11.8h6.5" />
    </>
  ),
  demo: <path d="M8 2.4l4.8 1.9v3.9c0 2.8-2.1 4.8-4.8 5.6-2.7-.8-4.8-2.8-4.8-5.6V4.3z" />,
}

function NavIcon({ name }) {
  return (
    <svg
      className="nav-icon"
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.4"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {ICONS[name] || null}
    </svg>
  )
}

export function AppNav({ items, current, onSelect, ariaLabel }) {
  return (
    <nav className="nav-list" aria-label={ariaLabel || 'Main'}>
      {items.map((item) => (
        <button
          key={item.id}
          type="button"
          className={`nav-item ${current === item.id ? 'active' : ''}`}
          aria-current={current === item.id ? 'page' : undefined}
          onClick={() => onSelect(item.id)}
        >
          <NavIcon name={item.icon} />
          <span>{item.label}</span>
        </button>
      ))}
    </nav>
  )
}
