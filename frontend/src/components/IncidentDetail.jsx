import React, { useState } from 'react';
import { 
  ShieldAlert, Clock, Cpu, FileText, Server, User, Globe, 
  Flame, ArrowRight, Activity, Radio, Layers, CheckCircle2, 
  ExternalLink, Hash, ShieldCheck, Download
} from 'lucide-react';
import EvidenceInspector from './EvidenceInspector';
import TimelineViewer from './TimelineViewer';
import RiskScoreExplainer from './RiskScoreExplainer';
import ReportViewer from './ReportViewer';

export default function IncidentDetail({ 
  incident, 
  mlMetrics, 
  onRescore, 
  isRescoring,
  onOpenNewIncident
}) {
  const [activeTab, setActiveTab] = useState('GRAPHS');

  if (!incident) {
    return (
      <main className="glass-panel incident-detail-panel" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#666666', padding: '40px 20px', background: '#080808', border: '1px solid #1c1c1c' }}>
        <div style={{ textAlign: 'center', maxWidth: '480px' }}>
          <div style={{
            width: '64px',
            height: '64px',
            borderRadius: '50%',
            background: 'rgba(56, 189, 248, 0.08)',
            border: '1px solid rgba(56, 189, 248, 0.25)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 16px auto'
          }}>
            <Radio size={30} color="#38bdf8" style={{ animation: 'pulse 2s infinite' }} />
          </div>
          <h3 style={{ fontSize: '16px', color: '#ffffff', fontWeight: '800', marginBottom: '6px' }}>
            Queue Clean & Ready
          </h3>
          <p style={{ fontSize: '12px', color: '#888888', lineHeight: '1.5', marginBottom: '18px' }}>
            All mock data removed. The platform is actively listening for live Microsoft Sentinel incident webhooks on <code className="mono" style={{ color: '#38bdf8' }}>/api/sentinel/webhook</code>.
          </p>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '10px' }}>
            <button 
              onClick={onOpenNewIncident}
              className="btn btn-primary"
              style={{ fontSize: '11px', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <Activity size={13} />
              Simulate Live Ingestion Alert
            </button>
          </div>
        </div>
      </main>
    );
  }


  const dynamicScore = incident.dynamic_ml_risk_score ?? 50;
  const staticSev = incident.sentinel_static_severity || 'Medium';
  const riskLabel = (incident.dynamic_risk_label || 'Medium').toUpperCase();
  const delta = incident.severity_delta || 0;

  const getScoreColor = (score) => {
    if (score >= 85) return '#ff3366';
    if (score >= 65) return '#ff9100';
    if (score >= 40) return '#ffd600';
    return '#00e676';
  };

  const scoreColor = getScoreColor(dynamicScore);

  return (
    <main className="glass-panel incident-detail-panel" style={{ background: '#080808', border: '1px solid #1c1c1c' }}>
      {/* Top Corporate Header: Case ID, Metadata & Dynamic ML Gauge */}
      <div style={{
        padding: '14px 18px',
        borderBottom: '1px solid #1c1c1c',
        background: '#050505'
      }}>
        <div className="incident-header-top" style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '14px' }}>
          
          {/* Left Metadata & Investigation Target */}
          <div style={{ flex: 1, minWidth: 0 }}>
            {/* Breadcrumb & Case Meta */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px', flexWrap: 'wrap' }}>
              <span className="mono" style={{ fontSize: '11.5px', fontWeight: '800', color: '#38bdf8', background: 'rgba(56, 189, 248, 0.12)', padding: '1px 6px', borderRadius: '4px', border: '1px solid rgba(56, 189, 248, 0.3)' }}>
                CASE #{incident.incident_id}
              </span>
              <span className="badge" style={{ background: '#141414', color: '#888888', border: '1px solid #262626' }}>
                TLP:AMBER
              </span>
              <span className="badge" style={{ background: '#141414', color: '#cccccc', border: '1px solid #262626' }}>
                Status: {incident.status || 'Active Investigation'}
              </span>
              {incident.incident_type && (
                <span className="badge" style={{ background: 'rgba(192, 132, 252, 0.12)', color: '#c084fc', border: '1px solid rgba(192, 132, 252, 0.3)' }}>
                  Vector: {incident.incident_type.replace(/_/g, ' ')}
                </span>
              )}
              {incident.is_escalated && (
                <span className="badge badge-escalated">
                  <Flame size={9} /> Sentinel Recalibrated (+{delta} pts)
                </span>
              )}
            </div>

            {/* Case Title */}
            <h2 style={{ fontSize: '15px', fontWeight: '800', color: '#ffffff', lineHeight: '1.3', marginBottom: '8px' }}>
              {incident.title}
            </h2>

            {/* Entity Metadata Badges */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap', fontSize: '10.5px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: '#888888' }}>
                <Server size={11} color="#38bdf8" />
                <span>Asset:</span>
                <strong style={{ color: '#ffffff' }} className="mono" title={incident.target_resource}>
                  {incident.target_resource?.split('/').pop() || incident.target_resource}
                </strong>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: '#888888' }}>
                <User size={11} color="#c084fc" />
                <span>Compromised User:</span>
                <strong style={{ color: '#ffffff' }}>{incident.affected_user || 'svc-managed-identity'}</strong>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: '#888888' }}>
                <Globe size={11} color="#ff3366" />
                <span>Threat Origin IP:</span>
                <strong style={{ color: '#ffffff' }} className="mono">{incident.attacker_ip || '198.51.100.74'}</strong>
              </div>
            </div>
          </div>

          {/* Right: Dynamic ML Score Gauge */}
          <div className="score-gauge-box" style={{
            background: '#000000',
            border: `1px solid ${scoreColor}55`,
            borderRadius: '6px',
            padding: '8px 14px',
            textAlign: 'center',
            minWidth: '135px',
            boxShadow: `0 0 16px ${scoreColor}22`,
            flexShrink: 0
          }}>
            <div style={{ fontSize: '9.5px', color: '#888888', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: '700' }}>
              ML Dynamic Severity
            </div>
            <div style={{ fontSize: '24px', fontWeight: '900', color: scoreColor, lineHeight: '1.1', margin: '2px 0', fontFamily: 'var(--font-mono)' }}>
              {dynamicScore}
              <span style={{ fontSize: '12px', color: '#555555', fontWeight: '500' }}>/100</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '4px' }}>
              <span className={`badge badge-${riskLabel.toLowerCase()}`}>
                {riskLabel} Risk
              </span>
            </div>
          </div>

        </div>

        {/* Corporate Tab Navigation */}
        <div className="tabs-scroll-bar" style={{ marginTop: '12px' }}>
          {[
            { id: 'GRAPHS', label: 'Threat Graphs & ML Studio', icon: Radio, badge: '2 Graphs' },
            { id: 'EVIDENCE', label: 'Cloud Posture & What-If Rescorer', icon: ShieldAlert },
            { id: 'TIMELINE', label: 'MITRE ATT&CK Chronological Timeline', icon: Clock },
            { id: 'REPORT', label: 'Executive Forensic Report & Playbook', icon: FileText }
          ].map(tab => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '5px',
                  padding: '5px 11px',
                  borderRadius: '5px',
                  fontSize: '11px',
                  fontWeight: '700',
                  cursor: 'pointer',
                  border: '1px solid',
                  background: isActive ? '#0284c7' : '#000000',
                  borderColor: isActive ? '#38bdf8' : '#222222',
                  color: isActive ? '#ffffff' : '#888888',
                  transition: 'all 0.15s ease',
                  whiteSpace: 'nowrap',
                  flexShrink: 0
                }}
              >
                <Icon size={12} />
                {tab.label}
                {tab.badge && (
                  <span style={{
                    fontSize: '9px',
                    padding: '1px 4px',
                    borderRadius: '3px',
                    background: isActive ? 'rgba(255, 255, 255, 0.25)' : 'rgba(56, 189, 248, 0.2)',
                    color: isActive ? '#ffffff' : '#38bdf8',
                    fontFamily: 'var(--font-mono)'
                  }}>
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Tab Content Body */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '14px 18px', background: '#000000' }}>
        {activeTab === 'GRAPHS' && (
          <RiskScoreExplainer incident={incident} mlMetrics={mlMetrics} />
        )}

        {activeTab === 'EVIDENCE' && (
          <EvidenceInspector 
            incident={incident} 
            onRescore={onRescore} 
            isRescoring={isRescoring} 
          />
        )}

        {activeTab === 'TIMELINE' && (
          <TimelineViewer timeline={incident.timeline} />
        )}

        {activeTab === 'REPORT' && (
          <ReportViewer incident={incident} />
        )}
      </div>

    </main>
  );
}
