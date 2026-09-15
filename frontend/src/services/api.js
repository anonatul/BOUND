const BASE = '';

async function fetchJSON(url, opts) {
  const r = await fetch(url, opts);
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  if (!r.ok) throw new Error(data.detail || data.message || `HTTP ${r.status}`);
  return data;
}

export const api = {
  health: () => fetchJSON('/api/health'),
  recipients: () => fetchJSON('/api/recipients'),
  ensureRecipients: () => fetchJSON('/api/recipients/ensure', { method: 'POST' }),
  encrypt: (file, recipients) => {
    const fd = new FormData();
    fd.append('file', file);
    fd.append('recipients', JSON.stringify(recipients));
    return fetchJSON('/api/encrypt', { method: 'POST', body: fd });
  },
  documents: () => fetchJSON('/api/documents'),
  decrypt: (document_id, recipient_id) => fetchJSON('/api/decrypt', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ document_id, recipient_id })
  }),
  ledger: () => fetchJSON('/api/ledger'),
  ledgerVerify: () => fetchJSON('/api/ledger/verify', { method: 'POST' }),
  verify: (file) => {
    const fd = new FormData();
    fd.append('file', file);
    return fetchJSON('/api/verify', { method: 'POST', body: fd });
  },
  test: {
    differentRecipients: () => fetchJSON('/api/test/different-recipients', { method: 'POST' }),
    attribution: () => fetchJSON('/api/test/attribution', { method: 'POST' }),
    signatureTampering: () => fetchJSON('/api/test/signature-tampering', { method: 'POST' }),
    ledgerTampering: () => fetchJSON('/api/test/ledger-tampering', { method: 'POST' }),
    fakeWatermark: () => fetchJSON('/api/test/fake-watermark', { method: 'POST' }),
    endToEnd: () => fetchJSON('/api/test/end-to-end', { method: 'POST' }),
  }
};
