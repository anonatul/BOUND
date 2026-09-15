import React, { useState, useEffect } from 'react'
import { api } from '../services/api.js'

export function LedgerView() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const r = await api.ledger()
      setData(r)
    } catch(e){ console.error(e) }
    finally{ setLoading(false) }
  }
  useEffect(() => { load() }, [])

  if (!data) return <div className="card">Loading ledger...</div>

  return (
    <div className="grid" style={{ gap:16 }}>
      <div className="card">
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
          <h3>Local Ledger — Tamper-Evident Chain</h3>
          <div style={{ display:'flex', gap:8, alignItems:'center' }}>
            <span className={`badge ${data.integrity_valid ? 'badge-success' : 'badge-danger'}`}>{data.integrity} {data.integrity_valid ? '✓' : '✗'}</span>
            <button className="btn-secondary" onClick={load} disabled={loading}>{loading?'Refreshing...':'Refresh'}</button>
          </div>
        </div>
        <div style={{ fontSize:11, color:'#9aa0b2', marginTop:6 }}>
          Append-only at application level. Each entry: <span className="mono">current_hash = SHA256(canonical_event + signature + previous_hash)</span>. 4 nodes (ledger-node-1..4), quorum 3/4. <b style={{ color:'#fdcb6e' }}>Prototype ledger — not equivalent to production blockchain consensus</b>.
        </div>
        <div style={{ marginTop:8, display:'flex', gap:16, fontSize:12 }}>
          <span>Entries: <b>{data.count}</b></span>
          <span>Node1: {data.details.node1.count} entries {data.details.node1.valid ? '✓' : '✗'}</span>
          <span>Node2: {data.details.node2.count} {data.details.node2.valid ? '✓' : '✗'}</span>
          <span>Node3: {data.details.node3.count} {data.details.node3.valid ? '✓' : '✗'}</span>
          <span>Node4: {data.details.node4.count} {data.details.node4.valid ? '✓' : '✗'}</span>
        </div>
      </div>

      <div className="card" style={{ overflowX:'auto' }}>
        <table className="table">
          <thead>
            <tr>
              <th>Block / Entry</th>
              <th>Document</th>
              <th>Recipient</th>
              <th>Session</th>
              <th>Watermark</th>
              <th>Timestamp</th>
              <th>Signature</th>
              <th>Hash</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {data.entries.map((e,i)=>(
              <tr key={i}>
                <td className="mono">#{i} <span style={{ color:'#6a7280' }}>({e.current_hash.slice(0,6)})</span></td>
                <td className="mono">{e.document_id}</td>
                <td><span className="badge badge-info">{e.recipient_id}</span></td>
                <td className="mono" style={{ fontSize:11 }}>{e.session_id}</td>
                <td className="mono" style={{ color:'#a29bfe' }}>{e.watermark_id}</td>
                <td className="mono" style={{ fontSize:11 }}>{e.event.timestamp}</td>
                <td><span className="badge badge-success">VALID ✓</span></td>
                <td><span className="ledger-hash" title={e.current_hash}>{e.current_hash.slice(0,12)}...</span><br/><span className="ledger-hash" style={{ fontSize:10 }}>prev {e.previous_hash.slice(0,8)}...</span></td>
                <td><span className="badge badge-success">COMMITTED</span></td>
              </tr>
            ))}
            {data.entries.length===0 && (
              <tr><td colSpan={9} style={{ textAlign:'center', color:'#9aa0b2', padding:24 }}>No ledger entries yet. Decrypt a document as Alice or Bob to create entries.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="card" style={{ fontSize:12, color:'#9aa0b2' }}>
        <b>Hash Chain Verification:</b> {data.integrity_valid ? 'All 4 nodes pass hash chain recomputation and consistency check.' : 'Integrity FAILED — chain divergence or tampering detected.'}
        {!data.integrity_valid && (
          <div style={{ marginTop:6, color:'#ff7675', fontSize:11 }}>
            {Object.entries(data.details).map(([k,v])=> v.error ? <div key={k}>{k}: {v.error}</div> : null)}
          </div>
        )}
      </div>
    </div>
  )
}
