import React, { useState, useEffect } from 'react';
import { 
  Key, ShieldAlert, Database, Server, Network, FileWarning, 
  Lock, RefreshCw, CheckCircle2, AlertOctagon, HelpCircle 
} from 'lucide-react';

export default function EvidenceInspector({ 
  incident, 
  onRescore, 
  isRescoring 
}) {
  const [evidence, setEvidence] = useState(incident?.evidence_snapshot || {});
  const [hasChanges, setHasChanges] = useState(false);

  useEffect(() => {
    setEvidence(incident?.evidence_snapshot || {});
    setHasChanges(false);
  }, [incident]);

  const handleToggle = (key, value) => {
    const updated = { ...evidence, [key]: value };
    setEvidence(updated);
    setHasChanges(true);
    // Instant re-score triggers ML inference on backend
    onRescore(incident.incident_id, updated);
  };

  const handleSliderChange = (key, value) => {
    const updated = { ...evidence, [key]: parseFloat(value) || 0 };
    setEvidence(updated);
    setHasChanges(true);
  };

  const handleSliderRelease = () => {
    if (hasChanges) {
      onRescore(incident.incident_id, evidence);
    }
  };

  return (
    <div>
      {/* Description Banner */}
      <div style={{
        background: '#080808',
        border: '1px solid #222222',
        borderRadius: '6px',
        padding: '10px 14px',
        marginBottom: '16px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '8px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <ShieldAlert size={16} color="#38bdf8" style={{ flexShrink: 0 }} />
          <span style={{ fontSize: '12px', color: '#e5e5e5' }}>
            <strong>Interactive Cloud Forensic Posture Matrix:</strong> Toggle any evidence flag below to observe real-time ML dynamic score recalculation.
          </span>
        </div>
        {isRescoring && (
          <span style={{ fontSize: '11px', color: '#38bdf8', display: 'flex', alignItems: 'center', gap: '5px' }}>
            <RefreshCw size={11} className="animate-spin" /> Recalibrating ML Model...
          </span>
        )}
      </div>

      {/* Grid of Evidence Vector Cards with Responsive Auto-Fit */}
      <div className="matrix-grid">
        
        {/* Category 1: IAM & Privilege Posture */}
        <div className="glass-panel" style={{ padding: '14px', background: '#080808', border: '1px solid #1f1f1f' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '7px', marginBottom: '12px', borderBottom: '1px solid #1c1c1c', paddingBottom: '6px' }}>
            <Key size={15} color="#c084fc" />
            <h3 style={{ fontSize: '12px', fontWeight: '700', color: '#ffffff', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Identity & IAM Privilege Posture
            </h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {/* IAM Role Elevation */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
              <div>
                <div style={{ fontSize: '12px', fontWeight: '600', color: '#ffffff' }}>Recent Role Elevation</div>
                <div style={{ fontSize: '10.5px', color: '#888888' }}>Identity escalated to Owner/Contributor</div>
              </div>
              <label className="switch">
                <input 
                  type="checkbox" 
                  checked={!!evidence.iam_recent_role_elevation} 
                  onChange={(e) => handleToggle('iam_recent_role_elevation', e.target.checked ? 1 : 0)}
                />
                <span className="slider"></span>
              </label>
            </div>

            {/* Custom Wildcard Role */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
              <div>
                <div style={{ fontSize: '12px', fontWeight: '600', color: '#ffffff' }}>Custom Role with Wildcard (*)</div>
                <div style={{ fontSize: '10.5px', color: '#888888' }}>Unrestricted actions granted via custom role</div>
              </div>
              <label className="switch">
                <input 
                  type="checkbox" 
                  checked={!!evidence.custom_role_wildcard_perm} 
                  onChange={(e) => handleToggle('custom_role_wildcard_perm', e.target.checked ? 1 : 0)}
                />
                <span className="slider"></span>
              </label>
            </div>

            {/* MFA Bypassed */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
              <div>
                <div style={{ fontSize: '12px', fontWeight: '600', color: '#ffffff' }}>MFA / Conditional Access Bypass</div>
                <div style={{ fontSize: '10.5px', color: '#888888' }}>Sign-in authenticated via legacy protocol</div>
              </div>
              <label className="switch">
                <input 
                  type="checkbox" 
                  checked={!!evidence.mfa_bypassed} 
                  onChange={(e) => handleToggle('mfa_bypassed', e.target.checked ? 1 : 0)}
                />
                <span className="slider"></span>
              </label>
            </div>

            {/* IAM Scope Selector */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px', paddingTop: '2px', flexWrap: 'wrap' }}>
              <div>
                <div style={{ fontSize: '12px', fontWeight: '600', color: '#ffffff' }}>Privilege Blast Radius Scope</div>
                <div style={{ fontSize: '10.5px', color: '#888888' }}>Hierarchy level of assigned permission</div>
              </div>
              <select
                value={evidence.iam_scope_level_code || 0}
                onChange={(e) => handleToggle('iam_scope_level_code', parseInt(e.target.value))}
                style={{
                  background: '#000000',
                  border: '1px solid #262626',
                  color: '#ffffff',
                  padding: '4px 7px',
                  borderRadius: '4px',
                  fontSize: '11px',
                  fontFamily: 'inherit',
                  outline: 'none'
                }}
              >
                <option value={0}>Resource (Level 0)</option>
                <option value={1}>Resource Group (Level 1)</option>
                <option value={2}>Subscription (Level 2)</option>
                <option value={3}>Tenant (Level 3)</option>
              </select>
            </div>
          </div>
        </div>

        {/* Category 2: Data & Storage Security */}
        <div className="glass-panel" style={{ padding: '14px', background: '#080808', border: '1px solid #1f1f1f' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '7px', marginBottom: '12px', borderBottom: '1px solid #1c1c1c', paddingBottom: '6px' }}>
            <Database size={15} color="#38bdf8" />
            <h3 style={{ fontSize: '12px', fontWeight: '700', color: '#ffffff', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Storage & Data Security Posture
            </h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {/* Public Storage */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
              <div>
                <div style={{ fontSize: '12px', fontWeight: '600', color: '#ffffff' }}>Storage Public Blob Access</div>
                <div style={{ fontSize: '10.5px', color: '#888888' }}>allowBlobPublicAccess: true enabled</div>
              </div>
              <label className="switch">
                <input 
                  type="checkbox" 
                  checked={!!evidence.storage_public_access_enabled} 
                  onChange={(e) => handleToggle('storage_public_access_enabled', e.target.checked ? 1 : 0)}
                />
                <span className="slider"></span>
              </label>
            </div>

            {/* Unrestricted SAS */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
              <div>
                <div style={{ fontSize: '12px', fontWeight: '600', color: '#ffffff' }}>Unrestricted SAS Token</div>
                <div style={{ fontSize: '10.5px', color: '#888888' }}>Account SAS generated with Read/Write</div>
              </div>
              <label className="switch">
                <input 
                  type="checkbox" 
                  checked={!!evidence.storage_sas_unrestricted} 
                  onChange={(e) => handleToggle('storage_sas_unrestricted', e.target.checked ? 1 : 0)}
                />
                <span className="slider"></span>
              </label>
            </div>

            {/* Contains PII */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
              <div>
                <div style={{ fontSize: '12px', fontWeight: '600', color: '#ffffff' }}>Contains Sensitive / PII Data</div>
                <div style={{ fontSize: '10.5px', color: '#888888' }}>Target blob contains customer secrets</div>
              </div>
              <label className="switch">
                <input 
                  type="checkbox" 
                  checked={!!evidence.contains_sensitive_pii_flag} 
                  onChange={(e) => handleToggle('contains_sensitive_pii_flag', e.target.checked ? 1 : 0)}
                />
                <span className="slider"></span>
              </label>
            </div>

            {/* Data Exfiltration Volume Slider */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '3px' }}>
                <span style={{ fontSize: '12px', fontWeight: '600', color: '#ffffff' }}>Exfiltrated Egress Volume</span>
                <span className="mono" style={{ fontSize: '11px', color: '#38bdf8', fontWeight: '700' }}>
                  {evidence.exfiltrated_data_mb || 0} MB
                </span>
              </div>
              <input
                type="range"
                min="0"
                max="2500"
                step="25"
                value={evidence.exfiltrated_data_mb || 0}
                onChange={(e) => handleSliderChange('exfiltrated_data_mb', e.target.value)}
                onMouseUp={handleSliderRelease}
                onTouchEnd={handleSliderRelease}
                style={{ width: '100%', accentColor: '#0284c7' }}
              />
            </div>
          </div>
        </div>

        {/* Category 3: Compute & VM Posture */}
        <div className="glass-panel" style={{ padding: '14px', background: '#080808', border: '1px solid #1f1f1f' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '7px', marginBottom: '12px', borderBottom: '1px solid #1c1c1c', paddingBottom: '6px' }}>
            <Server size={15} color="#00e676" />
            <h3 style={{ fontSize: '12px', fontWeight: '700', color: '#ffffff', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Compute, VM & Metadata Posture
            </h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {/* IMDS Token Access */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
              <div>
                <div style={{ fontSize: '12px', fontWeight: '600', color: '#ffffff' }}>IMDS Token Harvested</div>
                <div style={{ fontSize: '10.5px', color: '#888888' }}>169.254.169.254 queried for token</div>
              </div>
              <label className="switch">
                <input 
                  type="checkbox" 
                  checked={!!evidence.imds_token_accessed} 
                  onChange={(e) => handleToggle('imds_token_accessed', e.target.checked ? 1 : 0)}
                />
                <span className="slider"></span>
              </label>
            </div>

            {/* NSG Inbound Open 0.0.0.0/0 */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
              <div>
                <div style={{ fontSize: '12px', fontWeight: '600', color: '#ffffff' }}>NSG Open to Internet (0.0.0.0/0)</div>
                <div style={{ fontSize: '10.5px', color: '#888888' }}>Unrestricted ingress rule open</div>
              </div>
              <label className="switch">
                <input 
                  type="checkbox" 
                  checked={!!evidence.nsg_unrestricted_inbound_any} 
                  onChange={(e) => handleToggle('nsg_unrestricted_inbound_any', e.target.checked ? 1 : 0)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
        </div>

        {/* Category 4: Secrets & Threat Intel */}
        <div className="glass-panel" style={{ padding: '14px', background: '#080808', border: '1px solid #1f1f1f' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '7px', marginBottom: '12px', borderBottom: '1px solid #1c1c1c', paddingBottom: '6px' }}>
            <Lock size={15} color="#ff9100" />
            <h3 style={{ fontSize: '12px', fontWeight: '700', color: '#ffffff', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Secrets & Threat Geolocation
            </h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {/* Key Vault Secret Access */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
              <div>
                <div style={{ fontSize: '12px', fontWeight: '600', color: '#ffffff' }}>Key Vault Secret Retrieval</div>
                <div style={{ fontSize: '10.5px', color: '#888888' }}>Bulk secret or certificate dumping</div>
              </div>
              <label className="switch">
                <input 
                  type="checkbox" 
                  checked={!!evidence.keyvault_secret_accessed} 
                  onChange={(e) => handleToggle('keyvault_secret_accessed', e.target.checked ? 1 : 0)}
                />
                <span className="slider"></span>
              </label>
            </div>

            {/* Unusual Geo IP */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
              <div>
                <div style={{ fontSize: '12px', fontWeight: '600', color: '#ffffff' }}>Anomalous Geo IP / TOR Sign-in</div>
                <div style={{ fontSize: '10.5px', color: '#888888' }}>Sign-in from untrusted geographic region</div>
              </div>
              <label className="switch">
                <input 
                  type="checkbox" 
                  checked={!!evidence.unusual_geo_ip} 
                  onChange={(e) => handleToggle('unusual_geo_ip', e.target.checked ? 1 : 0)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
