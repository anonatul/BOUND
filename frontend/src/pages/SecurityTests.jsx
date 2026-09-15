import React, { useState } from 'react'
import { api } from '../services/api.js'

const tests = [
  { id:'different-recipients', label:'Test 1 — Different Recipients', desc:'Alice vs Bob watermarks must differ, visually identical', fn: ()=>api.test.differentRecipients() },
  { id:'attribution', label:'Test 2 — Attribution', desc:'Leak Alice’s doc → verify identifies Alice', fn: ()=>api.test.attribution() },
  { id:'signature-tampering', label:'Test 3 — Signature Tampering', desc:'Modify recipient in event → signature INVALID', fn: ()=>api.test.signatureTampering() },
  { id:'ledger-tampering', label:'Test 4 — Ledger Tampering', desc:'Modify ledger entry → integrity FAILED', fn: ()=>api.test.ledgerTampering() },
  { id:'fake-watermark', label:'Test 5 — Fake Watermark', desc:'Random watermark → NO LEDGER MATCH', fn: ()=>api.test.fakeWatermark() },
  { id:'end-to-end', label:'Test 6 — End-to-End', desc:'Full loop: encrypt → decrypt both → leak Alice → verify', fn: ()=>api.test.endToEnd() },
]

export function SecurityTests() {
  const [results, setResults] = useState({})
  const [loading, setLoading] = useState({})

  const run = async (t) => {
    setLoading(prev=>({...prev, [t.id]: true}))
    try {
      const r = await t.fn()
      setResults(prev=>({...prev, [t.id]: r}))
    } catch(e){
      setResults(prev=>({...prev, [t.id]: { error:e.message }}))
    } finally{
      setLoading(prev=>({...prev, [t.id]: false}))
    }
  }

  const runAll = async () => {
    for(const t of tests){ await run(t) }
  }

  return (
    <div className="grid" style={{ gap:16 }}>
      <div className="card">
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
          <h3>Security Demonstrations</h3>
          <button className="btn-primary" onClick={runAll}>Run All Tests</button>
        </div>
        <p style={{ color:'#9aa0b2', fontSize:12, marginTop:6 }}>Each button triggers a real backend check using actual PQC crypto, DCT watermark, ledger verification — no faked results.</p>
      </div>

      <div className="grid-2">
        {tests.map(t=>(
          <div key={t.id} className="card">
            <div style={{ fontWeight:700 }}>{t.label}</div>
            <div style={{ fontSize:12, color:'#9aa0b2', marginTop:4 }}>{t.desc}</div>
            <button className="btn-secondary" style={{ marginTop:8, width:'100%' }} onClick={()=>run(t)} disabled={loading[t.id]}>
              {loading[t.id] ? 'Running...' : 'Run Test'}
            </button>
            {results[t.id] && (
              <div style={{ marginTop:8, padding:8, borderRadius:8, background: results[t.id].passed ? 'rgba(0,184,148,0.1)' : results[t.id].error ? 'rgba(214,48,49,0.1)' : 'rgba(253,203,110,0.1)', border:`1px solid ${results[t.id].passed ? 'rgba(0,184,148,0.3)' : 'rgba(214,48,49,0.3)'}`, fontSize:12 }}>
                <div className="mono" style={{ wordBreak:'break-all', maxHeight:200, overflowY:'auto' }}>
                  <div style={{ fontWeight:700, color: results[t.id].passed ? '#00b894' : '#ff7675' }}>{results[t.id].passed ? 'PASSED ✓' : results[t.id].error ? 'ERROR' : 'FAILED'}</div>
                  <pre style={{ fontSize:10, whiteSpace:'pre-wrap', marginTop:6 }}>{JSON.stringify(results[t.id], null, 2).slice(0,1500)}</pre>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      <div style={{ fontSize:11, color:'#6b7280', padding:8, background:'rgba(214,48,49,0.08)', border:'1px solid rgba(214,48,49,0.2)', borderRadius:8 }}>
        <b>Security Limitations (Prototype):</b> This system <b>cannot prevent</b> screenshots, screen recording, phone photography, plaintext extraction from compromised endpoint, watermark removal by determined attacker, or copying content into a completely new document. The recipient controls their endpoint. Forensic attribution works only when leaked artifact retains the fingerprint.
      </div>
    </div>
  )
}
