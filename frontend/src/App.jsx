import React, { useState, useEffect } from 'react'
import { Sender } from './pages/Sender.jsx'
import { Recipients } from './pages/Recipients.jsx'
import { LedgerView } from './pages/LedgerView.jsx'
import { Investigator } from './pages/Investigator.jsx'
import { SecurityTests } from './pages/SecurityTests.jsx'
import { api } from './services/api.js'

export default function App() {
  const [tab, setTab] = useState('sender')
  const [health, setHealth] = useState(null)
  const [documents, setDocuments] = useState([])
  const [ledgerRefresh, setLedgerRefresh] = useState(0)

  const loadDocs = async () => {
    try {
      const r = await api.documents()
      setDocuments(r.documents || [])
    } catch(e){ console.error(e) }
  }

  useEffect(() => {
    api.health().then(setHealth).catch(()=>{})
    api.ensureRecipients().catch(()=>{})
    loadDocs()
  }, [])

  const handleEncrypted = () => {
    loadDocs()
    setLedgerRefresh(x=>x+1)
  }

  const tabs = [
    { id:'sender', label:'Sender' },
    { id:'recipients', label:'Recipients' },
    { id:'ledger', label:'Ledger' },
    { id:'investigator', label:'Investigator' },
    { id:'tests', label:'Demonstrations' },
  ]

  return (
    <div style={{ maxWidth:1200, margin:'0 auto', padding: '16px 20px' }}>
      {/* Header */}
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:16 }}>
        <div>
          <h1 style={{ fontSize:22, fontWeight:800 }}>Offline Post-Quantum Forensic Document Attribution</h1>
          <div style={{ fontSize:12, color:'#9aa0b2' }}>ML-KEM-768 · ML-DSA-65 · AES-256-GCM · DCT Watermark · 4-Node Ledger (quorum 3/4) · <span style={{ color:'#fdcb6e' }}>Prototype — not production security</span></div>
        </div>
        <div style={{ textAlign:'right' }}>
          <div className={`badge ${health ? 'badge-success' : 'badge-warn'}`}>{health ? 'Backend Connected ✓' : 'Connecting...'}</div>
          <div className="mono" style={{ fontSize:10, color:'#6b7280', marginTop:4 }}>{health?.pqc || 'pqcrypto real — not faked'}</div>
        </div>
      </div>

      {/* Arch diagram */}
      <div className="card" style={{ padding:12, marginBottom:16, background:'rgba(108,92,231,0.06)' }}>
        <div className="mono" style={{ fontSize:11, color:'#a29bfe', textAlign:'center' }}>
          Sender → Encrypt → Recipient → Decrypt → Generate session → Generate watermark → Watermark/render → Sign event → Ledger → Display
        </div>
        <div style={{ fontSize:10, color:'#6b7280', textAlign:'center', marginTop:4 }}>Watermark generated during recipient decryption, not at sender time. Opaque WM-... identifier, ledger maps to recipient.</div>
      </div>

      <div className="tabs">
        {tabs.map(t=>(
          <button key={t.id} className={`tab ${tab===t.id ? 'active' : ''}`} onClick={()=>setTab(t.id)}>{t.label}</button>
        ))}
        <div style={{ marginLeft:'auto', display:'flex', gap:8, alignItems:'center' }}>
          <span className="mono" style={{ fontSize:11, color:'#9aa0b2' }}>{documents.length} encrypted docs</span>
          <button className="btn-ghost" onClick={loadDocs} style={{ fontSize:12 }}>↻ Refresh</button>
        </div>
      </div>

      {tab==='sender' && <Sender onEncrypted={handleEncrypted} />}
      {tab==='recipients' && <Recipients documents={documents} />}
      {tab==='ledger' && <LedgerView key={ledgerRefresh} />}
      {tab==='investigator' && <Investigator />}
      {tab==='tests' && <SecurityTests />}

      <hr style={{ marginTop:24 }} />
      <div style={{ fontSize:11, color:'#6b7280', display:'grid', gap:6 }}>
        <div><b>Project Structure:</b> backend/app/crypto · watermark · ledger · forensic · identity · encryption | frontend/src/pages | ledger/node1..4 | storage/encrypted + watermarked | <span className="mono">Offline-first: works without Internet once deps installed</span></div>
        <div>Build order: PQC keys → AES+ML-KEM encryption → DCT watermark → ML-DSA signing → Ledger → Forensic → Frontend polish. All verification via real crypto, no faked signatures.</div>
        <div>Definition of Done: Upload → Encrypt → Alice decrypt (WM-A) → Bob decrypt (WM-B) → WM-A≠WM-B → Leak Alice → Investigator extracts WM-A → ledger match → ML-DSA VALID → ledger VALID → VERIFIED Alice.</div>
        <div style={{ display:'flex', gap:12, marginTop:6 }}>
          <a href="/api/health" target="_blank">API Health</a>
          <a href="/api/ledger" target="_blank">Ledger JSON</a>
          <a href="/api/documents" target="_blank">Documents JSON</a>
          <a href="/api/recipients" target="_blank">Recipients</a>
        </div>
      </div>
    </div>
  )
}
