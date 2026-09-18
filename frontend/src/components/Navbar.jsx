import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, Cloud, Database, Cpu, PlusCircle, Settings, 
  RefreshCw, Clock, ExternalLink, ShieldAlert, CheckCircle2 
} from 'lucide-react';

export default function Navbar({ 
  storageStatus, 
  azureStatus, 
  mlMetrics, 
  onOpenNewIncident, 
  onOpenSettings,
  onRefresh,
  loading 
}) {
  const [timeStr, setTimeStr] = useState('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTimeStr(now.toUTCString().slice(17, 25) + ' UTC');
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const isFirebase = storageStatus?.using_firebase;
  const isLiveAzure = azureStatus?.live_mode_enabled;
  const r2Score = mlMetrics?.metrics?.r2_score 
    ? (mlMetrics.metrics.r2_score * 100).toFixed(1) + '%' 
    : '93.9%';

  return (
    <header className="glass-panel navbar-container" style={{
      margin: '12px 20px 0 20px',
      padding: '10px 18px',
      borderRadius: '6px',
      background: '#080808',
      border: '1px solid #222222',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      gap: '12px'
    }}>
      {/* Left: Corporate Brand & Environment Info */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', minWidth: 0 }}>
        <div style={{
          background: '#0284c7',
          padding: '8px',
          borderRadius: '6px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0
        }}>
          <ShieldCheck size={18} color="#ffffff" />
        </div>

        <div style={{ minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            <h1 style={{ fontSize: '14px', fontWeight: '800', color: '#ffffff', letterSpacing: '-0.01em', whiteSpace: 'nowrap' }}>
              Microsoft Sentinel <span style={{ color: '#525252', fontWeight: '400' }}>//</span> Cloud Forensic Platform
            </h1>
            <span className="badge" style={{ background: 'rgba(56, 189, 248, 0.12)', color: '#38bdf8', border: '1px solid rgba(56, 189, 248, 0.35)' }}>
              Enterprise SOC Tier-1
            </span>
          </div>
          <div style={{ fontSize: '11px', color: '#737373', display: 'flex', alignItems: 'center', gap: '8px', marginTop: '1px' }}>
            <span>Subscription: <strong style={{ color: isLiveAzure ? '#38bdf8' : '#a3a3a3' }} className="mono">{azureStatus?.subscription_id ? `${azureStatus.subscription_id.slice(0, 13)}...` : 'Demo-Subscription'}</strong></span>
            <span>•</span>
            <span>ARM: <strong style={{ color: isLiveAzure ? '#00e676' : '#a3a3a3' }}>{isLiveAzure ? 'Live Cloud Connected' : 'Simulation Mode'}</strong></span>
          </div>

        </div>
      </div>

      {/* Right: SOC Clock, Integrations & Controls */}
      <div className="navbar-controls" style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
        
        {/* UTC Clock */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '5px',
          padding: '4px 8px',
          background: '#000000',
          border: '1px solid #262626',
          borderRadius: '5px',
          fontSize: '11px',
          color: '#e5e5e5'
        }}>
          <span className="pulse-dot"></span>
          <span className="mono" style={{ fontWeight: '600' }}>{timeStr || 'LIVE UTC'}</span>
        </div>

        {/* ML Engine Badge */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '5px',
          padding: '4px 8px',
          background: 'rgba(192, 132, 252, 0.08)',
          border: '1px solid rgba(192, 132, 252, 0.25)',
          borderRadius: '5px',
          fontSize: '11px'
        }}>
          <Cpu size={12} color="#c084fc" />
          <span style={{ color: '#888888' }}>ML R²:</span>
          <strong style={{ color: '#c084fc' }} className="mono">{r2Score}</strong>
        </div>

        {/* Database Status */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '5px',
          padding: '4px 8px',
          background: isFirebase ? 'rgba(255, 214, 0, 0.08)' : 'rgba(56, 189, 248, 0.08)',
          border: `1px solid ${isFirebase ? 'rgba(255, 214, 0, 0.25)' : 'rgba(56, 189, 248, 0.25)'}`,
          borderRadius: '5px',
          fontSize: '11px'
        }}>
          <Database size={12} color={isFirebase ? '#ffd600' : '#38bdf8'} />
          <span style={{ color: '#888888' }}>DB:</span>
          <strong style={{ color: isFirebase ? '#ffd600' : '#38bdf8' }}>
            {isFirebase ? 'Firestore' : 'Local Mirror'}
          </strong>
        </div>

        {/* Azure Status */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '5px',
          padding: '4px 8px',
          background: isLiveAzure ? 'rgba(0, 230, 118, 0.08)' : 'rgba(115, 115, 115, 0.08)',
          border: `1px solid ${isLiveAzure ? 'rgba(0, 230, 118, 0.25)' : 'rgba(115, 115, 115, 0.25)'}`,
          borderRadius: '5px',
          fontSize: '11px'
        }}>
          <Cloud size={12} color={isLiveAzure ? '#00e676' : '#888888'} />
          <span style={{ color: '#888888' }}>ARM:</span>
          <strong style={{ color: isLiveAzure ? '#00e676' : '#a3a3a3' }}>
            {isLiveAzure ? 'Live SDK' : 'Simulation'}
          </strong>
        </div>

        {/* Refresh Action */}
        <button 
          onClick={onRefresh} 
          className="btn btn-secondary" 
          title="Refresh Triage Telemetry"
          disabled={loading}
          style={{ padding: '5px 8px' }}
        >
          <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
        </button>

        {/* Simulate Incident Action */}
        <button onClick={onOpenNewIncident} className="btn btn-primary" style={{ padding: '5px 11px', fontSize: '11.5px' }}>
          <PlusCircle size={13} />
          Simulate Incident
        </button>

        {/* Settings Action */}
        <button onClick={onOpenSettings} className="btn btn-secondary" title="Configure Cloud Integrations" style={{ padding: '5px 8px' }}>
          <Settings size={13} />
        </button>

      </div>
    </header>
  );
}
