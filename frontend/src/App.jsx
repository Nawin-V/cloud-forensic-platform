import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import MetricsRibbon from './components/MetricsRibbon';
import IncidentList from './components/IncidentList';
import IncidentDetail from './components/IncidentDetail';
import SettingsModal from './components/SettingsModal';
import NewIncidentModal from './components/NewIncidentModal';
import { api } from './services/api';

export default function App() {
  const [incidents, setIncidents] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [mlMetrics, setMlMetrics] = useState(null);
  const [storageStatus, setStorageStatus] = useState(null);
  const [azureStatus, setAzureStatus] = useState(null);
  
  const [loading, setLoading] = useState(true);
  const [isRescoring, setIsRescoring] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isNewIncidentOpen, setIsNewIncidentOpen] = useState(false);

  // Initial load
  const loadData = async () => {
    setLoading(true);
    try {
      const [incs, metrics, store, azure] = await Promise.all([
        api.getIncidents().catch(err => {
          console.error('Failed to fetch incidents', err);
          return [];
        }),
        api.getMLMetrics().catch(() => null),
        api.getStorageStatus().catch(() => null),
        api.getAzureStatus().catch(() => null)
      ]);

      setIncidents(incs || []);
      setMlMetrics(metrics);
      setStorageStatus(store);
      setAzureStatus(azure);

      // Automatically select and load the first incident
      if (incs && incs.length > 0) {
        const first = incs[0];
        setSelectedId(first.incident_id);
        setSelectedIncident(first);

        // Fetch deep detail in background
        api.getIncident(first.incident_id)
          .then(detail => {
            if (detail) setSelectedIncident(detail);
          })
          .catch(() => {});
      }
    } catch (err) {
      console.error('Error loading platform data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  // Handle selecting an incident
  const handleSelectIncident = async (id) => {
    setSelectedId(id);
    
    // Instantly set from existing list so detail view appears with zero delay
    const local = incidents.find(i => i.incident_id === id);
    if (local) {
      setSelectedIncident(local);
    }

    // Then fetch complete deep evidence detail from API
    try {
      const detail = await api.getIncident(id);
      if (detail) {
        setSelectedIncident(detail);
      }
    } catch (err) {
      console.warn('Using local incident data for', id, err);
    }
  };

  // Handle interactive live rescoring
  const handleRescore = async (id, updatedEvidence) => {
    setIsRescoring(true);
    try {
      const rescored = await api.rescoreIncident(id, updatedEvidence);
      if (rescored) {
        setSelectedIncident(rescored);

        // Update incident item in left list as well
        setIncidents(prev => prev.map(item => 
          item.incident_id === id ? { ...item, ...rescored } : item
        ));
      }
    } catch (err) {
      console.error('Error re-scoring incident:', err);
    } finally {
      setIsRescoring(false);
    }
  };

  // Handle purge / clear all incidents
  const handlePurgeAll = async () => {
    try {
      setLoading(true);
      await api.purgeIncidents();
      setIncidents([]);
      setSelectedId(null);
      setSelectedIncident(null);
      await loadData();
    } catch (err) {
      console.error('Error purging incidents:', err);
    } finally {
      setLoading(false);
    }
  };

  // Handle new incident created
  const handleIncidentCreated = (newInc) => {
    setIncidents(prev => [newInc, ...prev]);
    setSelectedId(newInc.incident_id);
    setSelectedIncident(newInc);
  };

  return (
    <div className="app-container" style={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden' }}>
      {/* 1. Header Navbar */}
      <Navbar
        storageStatus={storageStatus}
        azureStatus={azureStatus}
        mlMetrics={mlMetrics}
        onOpenNewIncident={() => setIsNewIncidentOpen(true)}
        onOpenSettings={() => setIsSettingsOpen(true)}
        onRefresh={loadData}
        loading={loading}
      />

      {/* 2. Top Summary Metrics Ribbon */}
      <MetricsRibbon incidents={incidents} />

      {/* 3. Main Split View */}
      <div className="main-content" style={{ display: 'flex', flex: 1, overflow: 'hidden', padding: '14px 24px', gap: '16px' }}>
        <IncidentList
          incidents={incidents}
          selectedId={selectedId}
          onSelectIncident={handleSelectIncident}
        />

        <IncidentDetail
          incident={selectedIncident}
          mlMetrics={mlMetrics}
          onRescore={handleRescore}
          isRescoring={isRescoring}
          onOpenNewIncident={() => setIsNewIncidentOpen(true)}
        />
      </div>

      {/* Modals */}
      <SettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        storageStatus={storageStatus}
        azureStatus={azureStatus}
        onPurgeAll={handlePurgeAll}
      />

      <NewIncidentModal
        isOpen={isNewIncidentOpen}
        onClose={() => setIsNewIncidentOpen(false)}
        onIncidentCreated={handleIncidentCreated}
      />
    </div>
  );
}

