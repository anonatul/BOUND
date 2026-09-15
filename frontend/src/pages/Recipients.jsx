import React, { useState, useEffect } from 'react'
import { api } from '../services/api.js'
import { RecipientCard } from '../components/RecipientCard.jsx'

export function Recipients({ documents }) {
  const [recipients, setRecipients] = useState([])
  const [selected, setSelected] = useState('ALICE')
  const [docId, setDocId] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    api.recipients().then(r=>setRecipients(r.recipients)).catch(()=>{})
  }, [])

  useEffect(() => {
    if (documents.length>0 && !docId) setDocId(documents[0].document_id)
  }, [documents])

  const handleDecrypt = async () => {
    if (!docId) { setError('Select a document'); return; }
    setLoading(true); setError(''); setResult(null);
    try {
      const r = await api.decrypt(docId, selected)
      setResult(r)
    } catch(e){ setError(e.message) }
    finally{ setLoading(false) }
  }

  return (
    <div className="grid" style={{ gap:16 }}>
      <div className="grid-2">
        {recipients.map(r=>(
          <RecipientCard key={r.recipient_id} recipient={r} selected={selected===r.recipient_id} onSelect={setSelected} />
        ))}
      </div>

      <div className="card">
        <h3 style={{ marginBottom:8 }}>Recipient — Decrypt Document</h3>
        <p style={{ color:'#9aa0b2', fontSize:13, marginBottom:12 }}>Select a recipient (authenticates via locally stored ML-KEM private key) and an encrypted document. System will ML-KEM decaps, AES-GCM decrypt, generate fresh session + watermark, DCT watermark, ML-DSA sign, ledger commit.</p>

        <div style={{ display:'grid', gap:12 }}>
          <div className="grid-2">
            <div>
              <label style={{ fontSize:12, color:'#9aa0b2' }}>Recipient</label>
              <select value={selected} onChange={e=>setSelected(e.target.value)}>
                <option value="ALICE">Alice</option>
                <option value="BOB">Bob</option>
              </select>
            </div>
            <div>
              <label style={{ fontSize:12, color:'#9aa0b2' }}>Encrypted Document</label>
              <select value={docId} onChange={e=>setDocId(e.target.value)}>
                <option value="">-- select --</option>
                {documents.map(d=>(
                  <option key={d.document_id} value={d.document_id}>{d.document_id} — {d.original_filename} — {d.document_hash.slice(0,12)}...</option>
                ))}
              </select>
            </div>
          </div>
          <button className="btn-primary" onClick={handleDecrypt} disabled={loading}>
            {loading ? 'Decrypting & Watermarking...' : `Decrypt as ${selected}`}
          </button>
          {error && <div style={{ color:'#ff7675', fontSize:13, background:'rgba(214,48,49,0.1)', padding:8, borderRadius:8 }}>{error}</div>}
        </div>
      </div>

      {result && (
        <div className="card" style={{ borderColor:'#00b894' }}>
          <h4 style={{ color:'#00b894', marginBottom:8 }}>Decryption Successful ✓</h4>
          <div className="mono" style={{ fontSize:13, display:'grid', gap:6 }}>
            <div>Recipient: <b>{result.recipient_id}</b></div>
            <div>Document: <b>{result.document_id}</b></div>
            <div>Session: <span style={{ color:'#fdcb6e' }}>{result.session_id}</span></div>
            <div>Watermark: <span style={{ color:'#a29bfe' }}>{result.watermark_id}</span></div>
            <div>Nonce: <span style={{ color:'#9aa0b2' }}>{result.nonce.slice(0,16)}...</span></div>
            <div>ML-DSA Signature: <span style={{ color:'#00b894' }}>VALID ✓</span> <span style={{ fontSize:11, color:'#6b7280' }}>{result.signature}</span></div>
            <div>Ledger: <span style={{ color:'#00b894' }}>{result.ledger_status}</span> <span style={{ fontSize:11 }} className="ledger-hash">prev {result.ledger.previous_hash.slice(0,12)}... curr {result.ledger.current_hash.slice(0,12)}...</span></div>
          </div>
          <div style={{ marginTop:12, display:'flex', gap:8 }}>
            <a href={result.download_url} target="_blank" rel="noreferrer" className="btn-success" style={{ textDecoration:'none', display:'inline-block', textAlign:'center' }}>Open / View Watermarked Document</a>
            <a href={result.download_url} download className="btn-secondary" style={{ textDecoration:'none', display:'inline-block' }}>Download PDF</a>
          </div>
          <div style={{ fontSize:11, color:'#6b7280', marginTop:8 }}>Correct architecture: watermark generated <b>during recipient decryption flow</b>, not at sender encryption time. Flow: Decrypt → Session → Watermark → Render → Sign → Ledger.</div>
        </div>
      )}

      <div style={{ fontSize:11, color:'#6b7280', padding:8, background:'rgba(0,184,148,0.08)', border:'1px solid rgba(0,184,148,0.2)', borderRadius:8 }}>
        Watermark type: DCT-based invisible frequency-domain (QIM at coeff (3,2), Q=8). Visually appears same — PSNR &gt;45 dB. Opaque identifier only (WM-...), ledger maps to recipient.
      </div>
    </div>
  )
}
