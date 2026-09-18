import React from 'react';
import { X, Cloud, Database, Key, ShieldCheck, CheckCircle2 } from 'lucide-react';

export default function SettingsModal({ 
  isOpen, 
  onClose, 
  storageStatus, 
  azureStatus 
}) {
  if (!isOpen) return null;

  return (
    <div style={{
      position: 'fixed',
      top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(0, 0, 0, 0.85)',
      backdropFilter: 'blur(10px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 9999
    }}>
      <div className="glass-panel" style={{
        width: '560px',
        maxWidth: '92%',
        background: '#080808',
        border: '1px solid #222222',
        borderRadius: '8px',
        overflow: 'hidden',
        boxShadow: '0 20px 60px rgba(0, 0, 0, 0.9)'
      }}>
        {/* Header */}
        <div style={{
          padding: '14px 18px',
          borderBottom: '1px solid #1c1c1c',
          background: '#050505',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between'
        }}>
          <h3 style={{ fontSize: '15px', fontWeight: '800', color: '#ffffff', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Cloud size={16} color="#38bdf8" />
            Cloud & Storage Integrations
          </h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#888888', cursor: 'pointer' }}>
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '14px', background: '#080808' }}>
          
          {/* Azure Live Connection Status */}
          <div style={{
            background: '#000000',
            border: '1px solid #1c1c1c',
            borderRadius: '6px',
            padding: '14px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Cloud size={15} color="#38bdf8" />
                <strong style={{ fontSize: '13px', color: '#ffffff' }}>Microsoft Azure Connection</strong>
              </div>
              <span className={`badge ${azureStatus?.live_mode_enabled ? 'badge-low' : 'badge-medium'}`}>
                {azureStatus?.mode || 'Simulation Mode'}
              </span>
            </div>
            <p style={{ fontSize: '11.5px', color: '#888888', marginBottom: '8px' }}>
              When credentials are supplied in <code className="mono" style={{ color: '#38bdf8' }}>backend/.env</code>, the platform automatically connects to your Azure Tenant via Service Principal.
            </p>
            <div style={{ fontSize: '11px', color: '#666666' }}>
              Active Subscription: <span className="mono" style={{ color: '#cccccc' }}>{azureStatus?.subscription_id || 'sub-prod-eastus-01'}</span>
            </div>
          </div>

          {/* Firebase Cloud Firestore Status */}
          <div style={{
            background: '#000000',
            border: '1px solid #1c1c1c',
            borderRadius: '6px',
            padding: '14px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Database size={15} color="#ffd600" />
                <strong style={{ fontSize: '13px', color: '#ffffff' }}>Database & Persistence Engine</strong>
              </div>
              <span className={`badge ${storageStatus?.using_firebase ? 'badge-low' : 'badge-low'}`}>
                {storageStatus?.storage_mode || 'Cloud Firestore'}
              </span>
            </div>
            <p style={{ fontSize: '11.5px', color: '#888888' }}>
              {storageStatus?.using_firebase 
                ? '🔥 Real-time Firestore sync active. All incident updates stream across connected clients.'
                : '📁 Operating in Local Persistence Mode (backend/app/data/incidents/). Place serviceAccountKey.json to enable Cloud Firestore.'}
            </p>
          </div>

          {/* Purge & Reset Queue */}
          <div style={{
            background: '#000000',
            border: '1px solid rgba(255, 51, 102, 0.3)',
            borderRadius: '6px',
            padding: '14px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <strong style={{ fontSize: '13px', color: '#ff6b8b' }}>Data Reset & Clean Slate</strong>
              </div>
              <button
                onClick={() => {
                  if (window.confirm("Are you sure you want to remove all incidents? This will clear Firestore and local incident records so you can work with fresh incoming data.")) {
                    onPurgeAll();
                    onClose();
                  }
                }}
                className="btn btn-danger"
                style={{ fontSize: '11px', padding: '4px 10px' }}
              >
                Purge All Incidents
              </button>
            </div>
            <p style={{ fontSize: '11.5px', color: '#888888', margin: 0 }}>
              Wipes all seeded and cached incidents from Firestore and local disk, allowing the platform to start with a clean slate for upcoming live Sentinel alerts.
            </p>
          </div>

        </div>

        {/* Footer */}
        <div style={{
          padding: '10px 18px',
          borderTop: '1px solid #1c1c1c',
          background: '#050505',
          display: 'flex',
          justifyContent: 'flex-end'
        }}>
          <button onClick={onClose} className="btn btn-secondary">
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

