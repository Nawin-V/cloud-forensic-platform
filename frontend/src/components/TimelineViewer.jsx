import React from 'react';
import { Clock, ShieldAlert, Cpu, Database, Key, Server, Terminal, AlertTriangle } from 'lucide-react';

export default function TimelineViewer({ timeline = [] }) {
  if (!timeline || timeline.length === 0) {
    return (
      <div style={{ textAlign: 'center', padding: '40px', color: '#666666' }}>
        <Clock size={32} style={{ marginBottom: '12px', opacity: 0.5 }} />
        <p>No timeline events recorded for this incident yet.</p>
      </div>
    );
  }

  const getEventIcon = (type = '', source = '') => {
    const t = type.toLowerCase();
    const s = source.toLowerCase();
    if (t.includes('sentinel') || s.includes('sentinel')) return ShieldAlert;
    if (t.includes('ml') || t.includes('scoring')) return Cpu;
    if (t.includes('iam') || t.includes('role') || t.includes('auth')) return Key;
    if (t.includes('storage') || t.includes('blob')) return Database;
    if (t.includes('imds') || t.includes('vm')) return Server;
    return Terminal;
  };

  const getEventColor = (type = '') => {
    const t = type.toLowerCase();
    if (t.includes('sentinel')) return '#38bdf8';
    if (t.includes('ml')) return '#c084fc';
    if (t.includes('escalation') || t.includes('role') || t.includes('privilege')) return '#ff3366';
    if (t.includes('harvest') || t.includes('imds') || t.includes('secret')) return '#ff9100';
    return '#00e676';
  };

  return (
    <div style={{ padding: '8px 0' }}>
      <div style={{ position: 'relative', paddingLeft: '32px' }}>
        {/* Continuous Vertical Line */}
        <div style={{
          position: 'absolute',
          left: '11px',
          top: '16px',
          bottom: '24px',
          width: '2px',
          background: 'linear-gradient(to bottom, #0284c7, #7c3aed, #222222)'
        }} />

        {timeline.map((ev, idx) => {
          const Icon = getEventIcon(ev.event_type || ev.event, ev.source);
          const accentColor = getEventColor(ev.event_type || ev.event);

          return (
            <div 
              key={idx} 
              style={{
                position: 'relative',
                marginBottom: '20px',
                display: 'flex',
                flexDirection: 'column',
                gap: '5px'
              }}
            >
              {/* Timeline Dot with Glow */}
              <div style={{
                position: 'absolute',
                left: '-32px',
                top: '2px',
                width: '22px',
                height: '22px',
                borderRadius: '50%',
                background: '#000000',
                border: `2px solid ${accentColor}`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: `0 0 10px ${accentColor}44`,
                zIndex: 2
              }}>
                <Icon size={11} color={accentColor} />
              </div>

              {/* Event Header: Timestamp, Title, Source, MITRE Tag */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                <span className="mono" style={{
                  fontSize: '10.5px',
                  fontWeight: '700',
                  color: '#38bdf8',
                  background: 'rgba(56, 189, 248, 0.1)',
                  padding: '1px 6px',
                  borderRadius: '3px',
                  border: '1px solid rgba(56, 189, 248, 0.25)'
                }}>
                  {ev.timestamp || ev.time || 'T-00:00'}
                </span>

                <strong style={{ fontSize: '13px', color: '#ffffff' }}>
                  {ev.event_type || ev.event}
                </strong>

                <span style={{
                  fontSize: '10px',
                  color: '#888888',
                  background: '#111111',
                  border: '1px solid #222222',
                  padding: '1px 6px',
                  borderRadius: '3px'
                }}>
                  {ev.source || 'Telemetry'}
                </span>

                {ev.mitre_tactic && (
                  <span style={{
                    fontSize: '10px',
                    fontWeight: '600',
                    color: '#c084fc',
                    background: 'rgba(192, 132, 252, 0.1)',
                    border: '1px solid rgba(192, 132, 252, 0.3)',
                    padding: '1px 6px',
                    borderRadius: '3px'
                  }}>
                    MITRE: {ev.mitre_tactic}
                  </span>
                )}
              </div>

              {/* Event Description Card */}
              <div style={{
                background: '#080808',
                border: '1px solid #1c1c1c',
                borderRadius: '6px',
                padding: '9px 12px',
                fontSize: '12px',
                color: '#d4d4d4',
                lineHeight: '1.5'
              }}>
                {ev.description}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
