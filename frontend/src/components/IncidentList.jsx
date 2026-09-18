import React, { useState } from 'react';
import { Search, Filter, AlertTriangle, ArrowRight, ShieldCheck, Flame, Zap, ShieldAlert, Server, Copy, Check } from 'lucide-react';

export default function IncidentList({ 
  incidents = [], 
  selectedId, 
  onSelectIncident 
}) {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterTier, setFilterTier] = useState('ALL');
  const [escalatedOnly, setEscalatedOnly] = useState(false);
  const [copiedId, setCopiedId] = useState(null);

  // Filter counts
  const countAll = incidents.length;
  const countCrit = incidents.filter(i => (i.dynamic_risk_label || '').toLowerCase() === 'critical').length;
  const countHigh = incidents.filter(i => (i.dynamic_risk_label || '').toLowerCase() === 'high').length;
  const countEsc = incidents.filter(i => i.is_escalated).length;

  // Filter logic
  const filtered = incidents.filter(inc => {
    const term = searchTerm.toLowerCase();
    const matchSearch = 
      (inc.incident_id || '').toLowerCase().includes(term) ||
      (inc.title || '').toLowerCase().includes(term) ||
      (inc.target_resource || '').toLowerCase().includes(term) ||
      (inc.attacker_ip || '').toLowerCase().includes(term);

    const matchTier = filterTier === 'ALL' || (inc.dynamic_risk_label || '').toUpperCase() === filterTier;
    const matchEscalated = !escalatedOnly || inc.is_escalated;

    return matchSearch && matchTier && matchEscalated;
  });

  const handleCopyId = (e, id) => {
    e.stopPropagation();
    navigator.clipboard.writeText(id);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  return (
    <aside className="glass-panel incident-list-panel" style={{ background: '#050505', border: '1px solid #1c1c1c' }}>
      {/* Header & Search */}
      <div style={{ padding: '12px 14px 10px 14px', borderBottom: '1px solid #1c1c1c', background: '#080808' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
          <h2 style={{ fontSize: '13px', fontWeight: '800', color: '#ffffff', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <ShieldAlert size={14} color="#38bdf8" />
            Security Incident Queue
          </h2>
          <span style={{ fontSize: '10.5px', color: '#888888', fontFamily: 'var(--font-mono)' }}>
            <strong>{filtered.length}</strong> / {incidents.length} Records
          </span>
        </div>

        {/* Search Input */}
        <div style={{ position: 'relative', marginBottom: '8px' }}>
          <Search size={12} color="#666666" style={{ position: 'absolute', left: '9px', top: '8px' }} />
          <input
            type="text"
            placeholder="Search by ticket ID, asset, IP, title..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              width: '100%',
              padding: '5px 8px 5px 26px',
              background: '#000000',
              border: '1px solid #262626',
              borderRadius: '5px',
              color: '#ffffff',
              fontSize: '11px',
              outline: 'none',
              fontFamily: 'inherit'
            }}
          />
        </div>

        {/* Filter Chips */}
        <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
          {[
            { id: 'ALL', label: `All (${countAll})` },
            { id: 'CRITICAL', label: `Critical (${countCrit})` },
            { id: 'HIGH', label: `High (${countHigh})` }
          ].map(f => (
            <button
              key={f.id}
              onClick={() => { setFilterTier(f.id); setEscalatedOnly(false); }}
              style={{
                padding: '2px 6px',
                borderRadius: '4px',
                fontSize: '9.5px',
                fontWeight: '700',
                cursor: 'pointer',
                border: '1px solid',
                background: filterTier === f.id && !escalatedOnly ? '#0284c7' : '#000000',
                borderColor: filterTier === f.id && !escalatedOnly ? '#38bdf8' : '#262626',
                color: filterTier === f.id && !escalatedOnly ? '#ffffff' : '#888888',
                transition: 'all 0.15s ease'
              }}
            >
              {f.label}
            </button>
          ))}
          
          <button
            onClick={() => { setEscalatedOnly(!escalatedOnly); setFilterTier('ALL'); }}
            style={{
              padding: '2px 6px',
              borderRadius: '4px',
              fontSize: '9.5px',
              fontWeight: '700',
              cursor: 'pointer',
              border: '1px solid',
              display: 'flex',
              alignItems: 'center',
              gap: '3px',
              background: escalatedOnly ? 'rgba(255, 51, 102, 0.2)' : '#000000',
              borderColor: escalatedOnly ? '#ff3366' : '#262626',
              color: escalatedOnly ? '#ff6b8b' : '#ff3366',
            }}
          >
            <Zap size={9} />
            Escalated ({countEsc})
          </button>
        </div>
      </div>

      {/* Incident Scrollable List */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '8px', background: '#050505' }}>
        {filtered.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '30px 14px', color: '#666666' }}>
            <p style={{ fontSize: '11.5px' }}>No matching security incidents found.</p>
          </div>
        ) : (
          filtered.map(inc => {
            const isSelected = inc.incident_id === selectedId;
            const dynamicScore = inc.dynamic_ml_risk_score ?? 0;
            const staticSev = inc.sentinel_static_severity || 'Medium';
            const riskLabel = (inc.dynamic_risk_label || 'Medium').toLowerCase();
            const delta = inc.severity_delta || 0;

            const badgeClass = `badge-${riskLabel}`;

            return (
              <div
                key={inc.incident_id}
                onClick={() => onSelectIncident(inc.incident_id)}
                style={{
                  padding: '9px 11px',
                  borderRadius: '6px',
                  marginBottom: '6px',
                  cursor: 'pointer',
                  background: isSelected ? '#111827' : '#0a0a0a',
                  border: isSelected ? '1px solid #0284c7' : '1px solid #1a1a1a',
                  boxShadow: isSelected ? '0 0 12px rgba(2, 132, 199, 0.3)' : 'none',
                  transition: 'all 0.15s ease'
                }}
              >
                {/* Card Top: Ticket ID + Copy + Severity Badge */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '3px', gap: '4px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <span className="mono" style={{ fontSize: '10.5px', fontWeight: '800', color: '#38bdf8' }}>
                      {inc.incident_id}
                    </span>
                    <button
                      onClick={(e) => handleCopyId(e, inc.incident_id)}
                      title="Copy Incident ID"
                      style={{ background: 'none', border: 'none', color: '#666666', cursor: 'pointer', display: 'flex', padding: '1px' }}
                    >
                      {copiedId === inc.incident_id ? <Check size={10} color="#00e676" /> : <Copy size={10} />}
                    </button>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px', flexWrap: 'wrap' }}>
                    {inc.is_escalated && (
                      <span className="badge badge-escalated" title="Dynamic ML score escalated above Sentinel baseline">
                        <Flame size={8} /> +{delta} pts
                      </span>
                    )}
                    <span className={`badge ${badgeClass}`}>
                      {inc.dynamic_risk_label} ({dynamicScore})
                    </span>
                  </div>
                </div>

                {/* Card Title */}
                <div style={{ fontSize: '11.5px', fontWeight: '600', color: '#ffffff', lineHeight: '1.3', marginBottom: '5px' }}>
                  {inc.title}
                </div>

                {/* Severity Comparison: Static Sentinel vs Dynamic ML */}
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '5px',
                  background: '#000000',
                  border: '1px solid #1c1c1c',
                  padding: '3px 6px',
                  borderRadius: '4px',
                  marginBottom: '5px',
                  fontSize: '9.5px'
                }}>
                  <span style={{ color: '#888888' }}>Sentinel: <strong style={{ color: '#cccccc' }}>{staticSev}</strong></span>
                  <ArrowRight size={9} color="#666666" />
                  <span style={{ color: '#888888' }}>Dynamic: <strong style={{ color: '#ffffff' }}>{dynamicScore}/100</strong></span>
                </div>

                {/* Resource Target & Time */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '9.5px', color: '#666666', gap: '6px' }}>
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={inc.target_resource}>
                    {inc.target_resource?.split('/').pop() || inc.target_resource}
                  </span>
                  <span className="mono" style={{ flexShrink: 0 }}>
                    {inc.created_at ? new Date(inc.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Live'}
                  </span>
                </div>
              </div>
            );
          })
        )}
      </div>
    </aside>
  );
}
