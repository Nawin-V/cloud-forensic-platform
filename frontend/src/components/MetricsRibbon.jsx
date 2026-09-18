import React from 'react';
import { AlertOctagon, ArrowUpRight, ShieldAlert, Activity, CheckCircle2, Zap, TrendingUp } from 'lucide-react';

export default function MetricsRibbon({ incidents = [] }) {
  const total = incidents.length;
  const critical = incidents.filter(i => (i.dynamic_risk_label || '').toLowerCase() === 'critical').length;
  const high = incidents.filter(i => (i.dynamic_risk_label || '').toLowerCase() === 'high').length;
  const escalated = incidents.filter(i => i.is_escalated).length;
  
  const avgScore = total > 0 
    ? (incidents.reduce((acc, curr) => acc + (curr.dynamic_ml_risk_score || 0), 0) / total).toFixed(1)
    : '0.0';

  const cards = [
    {
      label: 'Active Incident Queue',
      value: total,
      sub: 'Ingested & Normalized',
      icon: ShieldAlert,
      color: '#38bdf8',
      bg: 'rgba(56, 189, 248, 0.1)',
      border: '#222222',
      trend: '100% Ingested'
    },
    {
      label: 'Critical Risk Level',
      value: critical,
      sub: 'Dynamic Score >= 85.0',
      icon: AlertOctagon,
      color: '#ff3366',
      bg: 'rgba(255, 51, 102, 0.1)',
      border: '#2a1a20',
      trend: 'Immediate Action'
    },
    {
      label: 'High Threat Severity',
      value: high,
      sub: 'Dynamic Score 65.0 - 84.9',
      icon: Activity,
      color: '#ff9100',
      bg: 'rgba(255, 145, 0, 0.1)',
      border: '#2a2218',
      trend: 'Investigating'
    },
    {
      label: 'Dynamic Escalations',
      value: escalated,
      sub: 'Sentinel Static ➔ ML Critical',
      icon: ArrowUpRight,
      color: '#c084fc',
      bg: 'rgba(192, 132, 252, 0.1)',
      border: '#281c30',
      highlight: true,
      trend: `+${escalated} Multi-Vector`
    },
    {
      label: 'Mean Risk Index',
      value: `${avgScore} / 100`,
      sub: 'Multi-Vector ML Assessment',
      icon: CheckCircle2,
      color: '#00e676',
      bg: 'rgba(0, 230, 118, 0.1)',
      border: '#182820',
      trend: 'Ensemble Baseline'
    }
  ];

  return (
    <div className="metrics-grid">
      {cards.map((c, idx) => {
        const Icon = c.icon;
        return (
          <div 
            key={idx} 
            className="glass-panel" 
            style={{ 
              padding: '10px 14px', 
              display: 'flex', 
              flexDirection: 'column',
              justifyContent: 'space-between',
              border: `1px solid ${c.border}`,
              background: '#080808',
              minWidth: 0,
              gap: '6px'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: '10.5px', color: '#888888', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: '700', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {c.label}
              </span>
              <div style={{
                background: c.bg,
                padding: '4px',
                borderRadius: '4px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0
              }}>
                <Icon size={14} color={c.color} />
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
              <div style={{ fontSize: '20px', fontWeight: '800', color: '#ffffff', fontFamily: 'var(--font-mono)', lineHeight: '1' }}>
                {c.value}
              </div>
              <span style={{ fontSize: '9.5px', color: c.highlight ? '#c084fc' : '#666666', fontWeight: '600' }}>
                {c.trend}
              </span>
            </div>

            <div style={{ fontSize: '10px', color: '#666666', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {c.sub}
            </div>
          </div>
        );
      })}
    </div>
  );
}
