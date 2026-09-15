import React from 'react'

export function RecipientCard({ recipient, selected, onSelect }) {
  return (
    <div
      className="card"
      style={{
        borderColor: selected ? '#6c5ce7' : undefined,
        background: selected ? 'rgba(108,92,231,0.08)' : undefined,
        cursor: 'pointer'
      }}
      onClick={() => onSelect(recipient.recipient_id)}
    >
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
        <div>
          <div style={{ fontWeight:700, fontSize:18 }}>{recipient.display_name}</div>
          <div className="mono" style={{ fontSize:12, color:'#9aa0b2' }}>{recipient.recipient_id}</div>
        </div>
        <div className={`badge ${selected ? 'badge-info' : 'badge-success'}`}>{selected ? 'Selected' : 'Ready'}</div>
      </div>
      <hr />
      <div className="mono" style={{ fontSize:12, display:'grid', gap:6 }}>
        <div style={{ display:'flex', justifyContent:'space-between' }}>
          <span style={{ color:'#9aa0b2' }}>ML-DSA</span>
          <span style={{ color:'#00b894' }}>Registered ✓ (ML-DSA-65)</span>
        </div>
        <div style={{ display:'flex', justifyContent:'space-between' }}>
          <span style={{ color:'#9aa0b2' }}>ML-KEM</span>
          <span style={{ color:'#00b894' }}>Registered ✓ (ML-KEM-768)</span>
        </div>
        <div style={{ marginTop:6, fontSize:10, color:'#6b7280', wordBreak:'break-all' }}>
          PK preview: {recipient.mldsa_pk_b64}
        </div>
      </div>
    </div>
  )
}
