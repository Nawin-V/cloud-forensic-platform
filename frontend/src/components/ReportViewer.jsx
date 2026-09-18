import React, { useState, useEffect } from 'react';
import { Download, FileText, Code2, Copy, Check, ExternalLink, ShieldCheck, FileSpreadsheet, Lock } from 'lucide-react';
import { api } from '../services/api';

export default function ReportViewer({ incident }) {
  const [reportMarkdown, setReportMarkdown] = useState('');
  const [loading, setLoading] = useState(false);
  const [copiedIdx, setCopiedIdx] = useState(null);

  useEffect(() => {
    if (!incident?.incident_id) return;
    setLoading(true);
    api.getReportMarkdown(incident.incident_id)
      .then(text => setReportMarkdown(text))
      .catch(err => console.error(err))
      .finally(() => setLoading(false));
  }, [incident?.incident_id, incident?.dynamic_ml_risk_score]);

  const handleCopyCommand = (cmd, idx) => {
    navigator.clipboard.writeText(cmd);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 2000);
  };

  const pdfUrl = incident?.incident_id ? api.getReportPdfUrl(incident.incident_id) : '#';

  const playbook = incident?.remediation_playbook || [
    "az ad user update --id compromised-identity@corp.com --account-enabled false",
    "az storage account update --name targetstorage --allow-blob-public-access false",
    "az network nsg rule create -g ProdRG --nsg-name ProdNSG -n BlockThreat --priority 100 --source-address-prefixes 198.51.100.74 --access Deny"
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      
      {/* Executive Action Header: Download PDF & Audit Case Hash */}
      <div className="glass-panel" style={{
        padding: '12px 16px',
        background: '#080808',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '12px',
        border: '1px solid #1f1f1f'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            background: 'rgba(56, 189, 248, 0.12)',
            padding: '8px',
            borderRadius: '5px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0
          }}>
            <FileText size={18} color="#38bdf8" />
          </div>
          <div>
            <h3 style={{ fontSize: '13.5px', fontWeight: '800', color: '#ffffff' }}>
              Executive Forensic Audit & Incident Investigation Report
            </h3>
            <p style={{ fontSize: '11px', color: '#888888' }}>
              Case File Reference: <span className="mono" style={{ color: '#38bdf8' }}>FOR-{incident?.incident_id}</span> | Audit Level: Certified Forensics
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <a 
            href={pdfUrl} 
            download={`${incident?.incident_id}_forensic_report.pdf`}
            className="btn btn-primary"
            style={{ textDecoration: 'none', padding: '6px 12px', fontSize: '11.5px' }}
          >
            <Download size={13} />
            Download PDF Report
          </a>
        </div>
      </div>

      {/* Containment Playbook CLI Quick-Actions */}
      <div className="glass-panel" style={{ padding: '14px 16px', background: '#080808', border: '1px solid #1f1f1f' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
          <h4 style={{ fontSize: '12px', fontWeight: '700', color: '#00e676', textTransform: 'uppercase', letterSpacing: '0.04em', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Code2 size={14} color="#00e676" />
            Automated Azure CLI Remediation Commands
          </h4>
          <span style={{ fontSize: '10.5px', color: '#666666' }}>
            Zero-Trust Isolation Scripts
          </span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          {playbook.map((cmd, idx) => (
            <div 
              key={idx}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                background: '#000000',
                border: '1px solid #222222',
                padding: '6px 10px',
                borderRadius: '4px',
                gap: '8px'
              }}
            >
              <code className="mono" style={{ fontSize: '11px', color: '#86efac', overflowX: 'auto', whiteSpace: 'nowrap' }}>
                $ {cmd}
              </code>
              <button
                onClick={() => handleCopyCommand(cmd, idx)}
                style={{
                  background: copiedIdx === idx ? 'rgba(0, 230, 118, 0.2)' : '#111111',
                  border: '1px solid',
                  borderColor: copiedIdx === idx ? '#00e676' : '#2a2a2a',
                  borderRadius: '4px',
                  color: copiedIdx === idx ? '#00e676' : '#888888',
                  padding: '3px 7px',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                  fontSize: '10.5px',
                  flexShrink: 0
                }}
              >
                {copiedIdx === idx ? <Check size={11} /> : <Copy size={11} />}
                {copiedIdx === idx ? 'Copied' : 'Copy'}
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Markdown Full Report Text Box */}
      <div className="glass-panel" style={{ padding: '16px', background: '#000000', border: '1px solid #1f1f1f' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px', borderBottom: '1px solid #1c1c1c', paddingBottom: '8px' }}>
          <span style={{ fontSize: '11.5px', fontWeight: '700', color: '#888888', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            Investigation Narrative & Audit Telemetry Preview
          </span>
          <span style={{ fontSize: '10.5px', color: '#555555' }}>
            SIEM Format: Markdown / RFC 5424
          </span>
        </div>

        {loading ? (
          <div style={{ padding: '30px', textAlign: 'center', color: '#666666', fontSize: '12px' }}>
            Compiling certified forensic report...
          </div>
        ) : (
          <pre style={{
            background: 'transparent',
            color: '#e5e5e5',
            fontFamily: 'var(--font-mono)',
            fontSize: '11px',
            lineHeight: '1.6',
            whiteSpace: 'pre-wrap',
            maxHeight: '380px',
            overflowY: 'auto'
          }}>
            {reportMarkdown}
          </pre>
        )}
      </div>

    </div>
  );
}
