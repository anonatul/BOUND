import React, { useState, useEffect } from 'react'
import { api } from '../services/api.js'

export function Sender({ onEncrypted }) {
  const [file, setFile] = useState(null)
  const [recipients, setRecipients] = useState(['ALICE','BOB'])
  const [available, setAvailable] = useState([])
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    api.recipients().then(r => setAvailable(r.recipients.map(x=>x.recipient_id))).catch(()=>{})
  }, [])

  const toggle = (rid) => {
    setRecipients(prev => prev.includes(rid) ? prev.filter(x=>x!==rid) : [...prev, rid])
  }

  const handleEncrypt = async () => {
    if (!file) { setError('Select a PDF first'); return; }
    if (recipients.length===0) { setError('Select at least one recipient'); return; }
    setLoading(true); setError(''); setResult(null);
    try {
      const r = await api.encrypt(file, recipients)
      setResult(r)
      onEncrypted && onEncrypted(r)
    } catch(e){ setError(e.message) }
    finally{ setLoading(false) }
  }

  return (
    <div className="grid" style={{ gap:16 }}>
      <div className="card">
        <h3 style={{ marginBottom:8 }}>Sender — Encrypt Document</h3>
        <p style={{ color:'#9aa0b2', fontSize:13, marginBottom:12 }}>Select a PDF. System will AES-256-GCM encrypt and ML-KEM wrap the key for each recipient. Plaintext never stored in encrypted file.</p>

        <div style={{ display:'grid', gap:12 }}>
          <div>
            <label style={{ fontSize:12, color:'#9aa0b2' }}>Upload PDF</label>
            <input type="file" accept="application/pdf" className="input" onChange={e=>setFile(e.target.files[0])} />
            {file && <div className="mono" style={{ fontSize:12, marginTop:6, color:'#a29bfe' }}>{file.name} — {(file.size/1024).toFixed(1)} KB</div>}
          </div>

          <div>
            <label style={{ fontSize:12, color:'#9aa0b2' }}>Authorized recipients</label>
            <div style={{ display:'flex', gap:8, marginTop:6 }}>
              {['ALICE','BOB'].map(rid=>(
                <label key={rid} style={{ display:'flex', alignItems:'center', gap:6, background:'#1f232e', padding:'8px 12px', borderRadius:8, border: recipients.includes(rid) ? '1px solid #6c5ce7' : '1px solid #2a2f3f', cursor:'pointer' }}>
                  <input type="checkbox" checked={recipients.includes(rid)} onChange={()=>toggle(rid)} />
                  <span style={{ fontWeight:600 }}>{rid}</span>
                </label>
              ))}
            </div>
            <div style={{ fontSize:11, color:'#6b7280', marginTop:4 }}>ML-KEM will protect AES key individually for each recipient</div>
          </div>

          <button className="btn-primary" onClick={handleEncrypt} disabled={loading}>
            {loading ? 'Encrypting...' : 'Encrypt'}
          </button>
          {error && <div style={{ color:'#ff7675', fontSize:13, background:'rgba(214,48,49,0.1)', padding:8, borderRadius:8 }}>{error}</div>}
        </div>
      </div>

      {result && (
        <div className="card" style={{ borderColor:'#00b894' }}>
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
            <h4 style={{ color:'#00b894' }}>Encryption Successful ✓</h4>
            <span className="badge badge-success">COMMITTED</span>
          </div>
          <div className="mono" style={{ fontSize:13, marginTop:12, display:'grid', gap:6 }}>
            <div>Document ID: <b style={{ color:'#fdcb6e' }}>{result.document_id}</b></div>
            <div>Original SHA-256: <span style={{ color:'#a29bfe', wordBreak:'break-all' }}>{result.document_hash}</span></div>
            <div>Authorized recipients: <b>{result.authorized_recipients.join(', ')}</b></div>
            <div>Ciphertext length: {result.ciphertext_len} bytes (plaintext not contained)</div>
            <div style={{ color:'#00b894', marginTop:6 }}>{result.message}</div>
          </div>
          <div style={{ fontSize:11, color:'#6b7280', marginTop:8 }}>Encrypted file stored at <span className="mono">storage/encrypted/{result.document_id}.json</span></div>
        </div>
      )}

      <div style={{ fontSize:11, color:'#6b7280', padding:8, background:'rgba(253,203,110,0.08)', border:'1px solid rgba(253,203,110,0.2)', borderRadius:8 }}>
        <b>Security Note:</b> Encrypted file must not contain plaintext. AES-256-GCM + ML-KEM-768 wrapping verified via automated test (ML-KEM encrypt/decrypt, AES round-trip).
      </div>
    </div>
  )
}
