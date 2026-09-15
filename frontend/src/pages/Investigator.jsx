import React, { useState } from 'react'
import { api } from '../services/api.js'

export function Investigator() {
  const [file, setFile] = useState(null)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleVerify = async () => {
    if (!file) { setError('Select a leaked PDF to investigate'); return; }
    setLoading(true); setError(''); setResult(null);
    try {
      const r = await api.verify(file)
      setResult(r)
    } catch(e){ setError(e.message) }
    finally{ setLoading(false) }
  }

  const pipelineSteps = result ? [
    { label: 'Watermark detected', ok: result.watermark_detected, value: result.watermark_id || 'None' },
    { label: 'Ledger match found', ok: result.ledger_match_found, value: result.document_id || 'No match' },
    { label: 'Signature verified', ok: result.signature_valid, value: result.signature_valid ? 'VALID ✓' : 'INVALID ✗' },
    { label: 'Ledger verified', ok: result.ledger_valid, value: result.ledger_valid ? 'VALID ✓' : 'FAILED ✗' },
    { label: 'Recipient identified', ok: !!result.recipient_id, value: result.recipient_id || 'Unknown' },
  ] : []

  return (
    <div className="grid" style={{ gap:16 }}>
      <div className="card">
        <h3>Investigator — Forensic Verification</h3>
        <p style={{ color:'#9aa0b2', fontSize:13, marginTop:4 }}>Upload a leaked PDF. System will: calculate hash → extract invisible DCT watermark → recover watermark ID → search ledger → verify ML-DSA signature → verify ledger chain → identify recipient/session.</p>

        <div style={{ marginTop:12, display:'grid', gap:12 }}>
          <div>
            <label style={{ fontSize:12, color:'#9aa0b2' }}>Upload leaked document (PDF)</label>
            <input type="file" accept="application/pdf" className="input" onChange={e=>setFile(e.target.files[0])} />
            {file && <div className="mono" style={{ fontSize:12, marginTop:6, color:'#a29bfe' }}>{file.name} — {(file.size/1024).toFixed(1)} KB</div>}
          </div>
          <button className="btn-primary" onClick={handleVerify} disabled={loading}>{loading ? 'Verifying...' : 'Verify Leaked Document'}</button>
          {error && <div style={{ color:'#ff7675', fontSize:13, background:'rgba(214,48,49,0.1)', padding:8, borderRadius:8 }}>{error}</div>}
        </div>
      </div>

      {result && (
        <div className="card" style={{ borderColor: result.status==='VERIFIED' ? '#00b894' : '#d63031' }}>
          <div className="pipeline" style={{ marginBottom:12 }}>
            {pipelineSteps.map((s,i)=>(
              <React.Fragment key={i}>
                <div className="pipeline-step" style={{ borderColor: s.ok ? '#00b894' : '#d63031', background: s.ok ? 'rgba(0,184,148,0.1)' : 'rgba(214,48,49,0.1)' }}>
                  <span className="dot" style={{ background: s.ok ? '#00b894' : '#d63031' }}></span>
                  {s.label}
                </div>
                {i < pipelineSteps.length-1 && <span className="pipeline-arrow">→</span>}
              </React.Fragment>
            ))}
          </div>

          {result.status==='VERIFIED' ? (
            <div style={{ background:'rgba(0,184,148,0.08)', border:'1px solid rgba(0,184,148,0.3)', borderRadius:12, padding:16 }}>
              <div style={{ textAlign:'center', marginBottom:12 }}>
                <div style={{ fontSize:22, fontWeight:800, color:'#00b894' }}>FORENSIC VERIFICATION</div>
                <div style={{ fontSize:14, fontWeight:700, color:'#00b894', letterSpacing: '0.1em' }}>Status: VERIFIED ✓</div>
              </div>
              <div className="mono" style={{ fontSize:13, display:'grid', gap:6, background:'#181b22', padding:12, borderRadius:8 }}>
                <div>Document: <b>{result.document_id}</b> <span style={{ color:'#9aa0b2' }}>(leaked hash {result.leaked_hash.slice(0,16)}...)</span></div>
                <div>Watermark: <span style={{ color:'#a29bfe' }}>{result.watermark_id}</span></div>
                <div>Recipient: <b style={{ color:'#fdcb6e' }}>{result.recipient_id}</b></div>
                <div>Session: {result.session_id}</div>
                <div>Decryption Time: {result.timestamp}</div>
                <div>ML-DSA Signature: <span style={{ color:'#00b894' }}>VALID ✓</span></div>
                <div>Ledger Integrity: <span style={{ color:'#00b894' }}>VALID ✓</span></div>
                <div style={{ marginTop:8, padding:8, background:'rgba(0,184,148,0.15)', borderRadius:8, textAlign:'center' }}>
                  Result: This leaked artifact matches <b>{result.recipient_id}</b>'s recorded decryption session.
                </div>
              </div>
            </div>
          ) : (
            <div style={{ background:'rgba(214,48,49,0.08)', border:'1px solid rgba(214,48,49,0.3)', borderRadius:12, padding:16 }}>
              <div style={{ textAlign:'center', marginBottom:12 }}>
                <div style={{ fontSize:18, fontWeight:800, color:'#ff7675' }}>VERIFICATION FAILED</div>
                <div style={{ fontSize:13, color:'#ff7675' }}>Status: {result.status}</div>
              </div>
              <div className="mono" style={{ fontSize:13, display:'grid', gap:6, background:'#181b22', padding:12, borderRadius:8 }}>
                {result.watermark_id && <div>Watermark: {result.watermark_id}</div>}
                {!result.watermark_detected && <div style={{ color:'#ff7675' }}>No forensic watermark detected. Possible unwatermarked original or fully stripped artifact.</div>}
                {result.watermark_detected && !result.ledger_match_found && <div style={{ color:'#ff7675' }}>Watermark {result.watermark_id} has NO VALID LEDGER MATCH — fake watermark or unrecorded session.</div>}
                {result.ledger_match_found && !result.signature_valid && <div style={{ color:'#ff7675' }}>ML-DSA SIGNATURE: INVALID — event tampering detected.</div>}
                {result.ledger_match_found && !result.ledger_valid && <div style={{ color:'#ff7675' }}>LEDGER INTEGRITY: FAILED — hash chain tampering detected.</div>}
                <div style={{ color:'#9aa0b2', marginTop:6 }}>{result.message}</div>
              </div>
            </div>
          )}

          <details style={{ marginTop:12 }}>
            <summary style={{ cursor:'pointer', color:'#9aa0b2', fontSize:12 }}>Raw verification output (for debugging)</summary>
            <pre className="mono" style={{ fontSize:11, color:'#9aa0b2', background:'#0f1115', padding:12, borderRadius:8, overflowX:'auto', marginTop:8 }}>{JSON.stringify(result, null, 2)}</pre>
          </details>
        </div>
      )}

      <div style={{ fontSize:11, color:'#6b7280', padding:8, background:'rgba(108,92,231,0.08)', border:'1px solid rgba(108,92,231,0.2)', borderRadius:8 }}>
        <b>What Investigator checks:</b> 1) document hash, 2) DCT watermark extraction (blind, no original), 3) watermark ID recovery, 4) ledger search, 5) ML-DSA signature verification, 6) ledger hash chain verification. Provides forensic attribution <b>only when leaked artifact retains fingerprint</b>. Does not prevent screenshots / photography / retyping.
      </div>
    </div>
  )
}
