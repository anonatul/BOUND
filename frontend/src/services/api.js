const TOKEN_KEY = 'bound_token'

export class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

export function getToken() {
  try {
    return localStorage.getItem(TOKEN_KEY)
  } catch {
    return null
  }
}

export function setToken(token) {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token)
    else localStorage.removeItem(TOKEN_KEY)
  } catch {
    // storage unavailable; session stays in memory only
  }
}

export function clearToken() {
  try {
    localStorage.removeItem(TOKEN_KEY)
  } catch {
    // ignore
  }
}

let unauthorizedHandler = null

export function setUnauthorizedHandler(handler) {
  unauthorizedHandler = handler
}

function detailOf(data) {
  if (!data) return ''
  if (typeof data.detail === 'string') return data.detail
  if (Array.isArray(data.detail)) {
    return data.detail
      .map((item) => item && (item.msg || JSON.stringify(item)))
      .filter(Boolean)
      .join('; ')
  }
  if (typeof data.message === 'string') return data.message
  return ''
}

async function request(path, options = {}) {
  const { method = 'GET', body, form } = options
  const headers = {}
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`

  let payload
  if (form) {
    payload = form
  } else if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
    payload = JSON.stringify(body)
  }

  let response
  try {
    response = await fetch(path, { method, headers, body: payload })
  } catch {
    throw new ApiError('Could not reach the server. Check that the backend is running.', 0)
  }

  const text = await response.text()
  let data = null
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      data = { detail: text }
    }
  }

  if (response.status === 401) {
    clearToken()
    if (unauthorizedHandler) unauthorizedHandler()
    throw new ApiError(detailOf(data) || 'Your session has expired. Please sign in again.', 401)
  }

  if (!response.ok) {
    throw new ApiError(detailOf(data) || `Request failed (HTTP ${response.status}).`, response.status)
  }

  return data || {}
}

export const api = {
  register(username, display_name, passphrase) {
    return request('/api/auth/register', {
      method: 'POST',
      body: { username, display_name, passphrase },
    })
  },

  async login(username, passphrase) {
    const data = await request('/api/auth/login', {
      method: 'POST',
      body: { username, passphrase },
    })
    if (data.token) setToken(data.token)
    return data
  },

  unlock(passphrase) {
    return request('/api/auth/unlock', { method: 'POST', body: { passphrase } })
  },

  lock() {
    return request('/api/auth/lock', { method: 'POST' })
  },

  logout() {
    return request('/api/auth/logout', { method: 'POST' })
  },

  me() {
    return request('/api/auth/me')
  },

  usernameAvailable(username) {
    return request(`/api/auth/username-available?username=${encodeURIComponent(username)}`)
  },

  recipients() {
    return request('/api/recipients')
  },

  recipient(recipientId) {
    return request(`/api/recipients/${encodeURIComponent(recipientId)}`)
  },

  encrypt(file, recipients) {
    const form = new FormData()
    form.append('file', file)
    form.append('recipients', JSON.stringify(recipients))
    return request('/api/encrypt', { method: 'POST', form })
  },

  documents() {
    return request('/api/documents')
  },

  documentEvents(documentId) {
    return request(`/api/documents/${encodeURIComponent(documentId)}/events`)
  },

  decrypt(document_id) {
    return request('/api/decrypt', { method: 'POST', body: { document_id } })
  },

  verify(file) {
    const form = new FormData()
    form.append('file', file)
    return request('/api/verify', { method: 'POST', form })
  },

  ledger() {
    return request('/api/ledger')
  },

  ledgerRepair() {
    return request('/api/ledger/repair', { method: 'POST' })
  },

  tests: {
    endToEnd() {
      return request('/api/test/end-to-end', { method: 'POST' })
    },
    differentRecipients() {
      return request('/api/test/different-recipients', { method: 'POST' })
    },
    attribution() {
      return request('/api/test/attribution', { method: 'POST' })
    },
    signatureTampering() {
      return request('/api/test/signature-tampering', { method: 'POST' })
    },
    ledgerTampering() {
      return request('/api/test/ledger-tampering', { method: 'POST' })
    },
    fakeWatermark() {
      return request('/api/test/fake-watermark', { method: 'POST' })
    },
  },
}
