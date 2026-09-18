import React, { useState } from 'react';
import { X, PlusCircle, ShieldAlert, Zap, Server, Database, Key } from 'lucide-react';
import { api } from '../services/api';

const SCENARIO_PRESETS = [
  {
    title: "VM IMDS Token Theft & Key Vault Access",
    static_sev: "Low",
    target: "/subscriptions/sub-prod-01/resourceGroups/App-RG/providers/Microsoft.Compute/virtualMachines/vm-prod-api-01",
    user: "svc-api-identity",
    ip: "185.220.101.99",
    evidence: {
      sentinel_static_severity_code: 1,
      iam_recent_role_elevation: 1,
      iam_scope_level_code: 2,
      mfa_bypassed: 1,
      unusual_geo_ip: 1,
      storage_public_access_enabled: 0,
      storage_sas_unrestricted: 0,
      exfiltrated_data_mb: 28.5,
      nsg_unrestricted_inbound_any: 1,
      imds_token_accessed: 1,
      keyvault_secret_accessed: 1,
      contains_sensitive_pii_flag: 0,
      custom_role_wildcard_perm: 0
    }
  },
  {
    title: "Storage Account Public Blob Exposure & Mass Download",
    static_sev: "Low",
    target: "/subscriptions/sub-prod-01/resourceGroups/Storage-RG/providers/Microsoft.Storage/storageAccounts/financerecords2026",
    user: "anonymous-user",
    ip: "194.26.29.50",
    evidence: {
      sentinel_static_severity_code: 1,
      iam_recent_role_elevation: 0,
      iam_scope_level_code: 0,
      mfa_bypassed: 0,
      unusual_geo_ip: 1,
      storage_public_access_enabled: 1,
      storage_sas_unrestricted: 1,
      exfiltrated_data_mb: 1250.0,
      nsg_unrestricted_inbound_any: 0,
      imds_token_accessed: 0,
      keyvault_secret_accessed: 0,
      contains_sensitive_pii_flag: 1,
      custom_role_wildcard_perm: 0
    }
  },
  {
    title: "Tenant-Wide Custom Role Wildcard (*) Escalation",
    static_sev: "High",
    target: "/providers/Microsoft.Management/managementGroups/CoreTenant",
    user: "temp-consultant@corp.azure.com",
    ip: "91.240.118.14",
    evidence: {
      sentinel_static_severity_code: 3,
      iam_recent_role_elevation: 1,
      iam_scope_level_code: 3,
      mfa_bypassed: 1,
      unusual_geo_ip: 1,
      storage_public_access_enabled: 0,
      storage_sas_unrestricted: 0,
      exfiltrated_data_mb: 180.0,
      nsg_unrestricted_inbound_any: 0,
      imds_token_accessed: 0,
      keyvault_secret_accessed: 1,
      contains_sensitive_pii_flag: 1,
      custom_role_wildcard_perm: 1
    }
  }
];

export default function NewIncidentModal({ 
  isOpen, 
  onClose, 
  onIncidentCreated 
}) {
  const [selectedPreset, setSelectedPreset] = useState(0);
  const [loading, setLoading] = useState(false);

  if (!isOpen) return null;

  const handleSimulate = async () => {
    setLoading(true);
    try {
      const preset = SCENARIO_PRESETS[selectedPreset];
      const payload = {
        title: preset.title,
        sentinel_static_severity: preset.static_sev,
        target_resource: preset.target,
        affected_user: preset.user,
        attacker_ip: preset.ip,
        status: "Active Threat",
        evidence_snapshot: preset.evidence,
        remediation_playbook: [
          `az ad user update --id ${preset.user} --account-enabled false`,
          "az network nsg rule create -g ProdRG --nsg-name ProdNSG -n BlockThreat --priority 100 --source-address-prefixes " + preset.ip + " --access Deny"
        ]
      };

      const newInc = await api.createIncident(payload);
      onIncidentCreated(newInc);
      onClose();
    } catch (err) {
      console.error(err);
      alert('Error simulating incident: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

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
        width: '600px',
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
            <Zap size={16} color="#ff3366" />
            Simulate Cloud Attack Incident
          </h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#888888', cursor: 'pointer' }}>
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '12px', background: '#080808' }}>
          <p style={{ fontSize: '11.5px', color: '#888888' }}>
            Select an Azure attack scenario to test deep ARM evidence bundling, dynamic severity recalibration, and forensic report generation.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {SCENARIO_PRESETS.map((p, idx) => (
              <div
                key={idx}
                onClick={() => setSelectedPreset(idx)}
                style={{
                  padding: '12px 14px',
                  borderRadius: '6px',
                  cursor: 'pointer',
                  background: selectedPreset === idx ? '#111827' : '#000000',
                  border: selectedPreset === idx ? '1px solid #0284c7' : '1px solid #1c1c1c',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between'
                }}
              >
                <div>
                  <div style={{ fontSize: '12.5px', fontWeight: '700', color: '#ffffff', marginBottom: '2px' }}>
                    {p.title}
                  </div>
                  <div style={{ fontSize: '10.5px', color: '#888888' }}>
                    Sentinel Static: <strong style={{ color: '#cccccc' }}>{p.static_sev}</strong> | Target: {p.target.split('/').pop()}
                  </div>
                </div>

                <span className="badge" style={{ background: '#141414', color: '#38bdf8', border: '1px solid #262626' }}>
                  Preset {idx + 1}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div style={{
          padding: '10px 18px',
          borderTop: '1px solid #1c1c1c',
          background: '#050505',
          display: 'flex',
          justifyContent: 'flex-end',
          gap: '8px'
        }}>
          <button onClick={onClose} className="btn btn-secondary">
            Cancel
          </button>
          <button onClick={handleSimulate} className="btn btn-primary" disabled={loading}>
            <PlusCircle size={13} />
            {loading ? 'Ingesting & Scoring...' : 'Trigger Incident & Rescore'}
          </button>
        </div>
      </div>
    </div>
  );
}
