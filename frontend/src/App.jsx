import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import Overview from './components/Overview';
import IncidentList from './components/IncidentList';
import RotationConsole from './components/RotationConsole';
import VaultViewer from './components/VaultViewer';
import IntelligencePanel from './components/IntelligencePanel';
import IncidentDetailModal from './components/IncidentDetailModal';
import { api } from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [incidents, setIncidents] = useState([]);
  const [stats, setStats] = useState(null);
  const [health, setHealth] = useState({
    backend: 'checking',
    postgres: 'healthy',
    vault: 'checking',
    vaultVersion: null,
  });
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(new Date());

  const loadData = async () => {
    setIsRefreshing(true);
    try {
      // 1. Fetch Backend Health
      let backendStatus = 'unreachable';
      try {
        const be = await api.getBackendHealth();
        backendStatus = be.status === 'healthy' ? 'healthy' : 'degraded';
      } catch {
        backendStatus = 'unreachable';
      }

      // 2. Fetch Vault Health
      let vaultStatus = 'unreachable';
      let vaultVer = null;
      try {
        const vh = await api.getVaultHealth();
        vaultStatus = vh.status === 'healthy' ? 'healthy' : 'unhealthy';
        vaultVer = vh.version || null;
      } catch {
        vaultStatus = 'unreachable';
      }

      setHealth({
        backend: backendStatus,
        postgres: 'healthy', // Managed via docker on 5434
        vault: vaultStatus,
        vaultVersion: vaultVer,
      });

      // 3. Fetch Incidents
      try {
        const incData = await api.getIncidents({ limit: 100 });
        setIncidents(incData.incidents || []);
      } catch (err) {
        console.error('Error fetching incidents:', err);
      }

      // 4. Fetch Stats
      try {
        const statData = await api.getStats();
        setStats(statData);
      } catch (err) {
        console.error('Error fetching stats:', err);
      }

      setLastUpdated(new Date());
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
    // Auto-refresh every 30 seconds
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleTriggerRotate = async (incidentId, payload = {}) => {
    const res = await api.rotateCredential(incidentId, payload);
    await loadData();
    // update selected incident if open
    if (selectedIncident && selectedIncident.incident_id === incidentId) {
      const updated = await api.getIncident(incidentId);
      setSelectedIncident(updated);
    }
    return res;
  };

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col font-sans">
      <Header
        health={health}
        onRefresh={loadData}
        isRefreshing={isRefreshing}
      />

      {/* Main Container */}
      <main className="max-w-7xl mx-auto w-full px-6 py-6 flex-1 space-y-6">
        {/* Navigation Tabs */}
        <div className="flex items-center gap-2 border-b border-slate-800 pb-2 overflow-x-auto">
          <button
            onClick={() => setActiveTab('overview')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold tracking-wide transition-all flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'overview'
                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <span>🛡️</span>
            <span>Security Overview</span>
          </button>

          <button
            onClick={() => setActiveTab('incidents')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold tracking-wide transition-all flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'incidents'
                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <span>📋</span>
            <span>Incident Audit Log</span>
            <span className="bg-slate-800 text-slate-300 font-mono text-[10px] px-1.5 py-0.5 rounded-full">
              {incidents.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('rotation')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold tracking-wide transition-all flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'rotation'
                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <span>🔄</span>
            <span>Credential Rotation Console</span>
          </button>

          <button
            onClick={() => setActiveTab('vault')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold tracking-wide transition-all flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'vault'
                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <span>🔒</span>
            <span>HashiCorp Vault Inspector</span>
          </button>

          <button
            onClick={() => setActiveTab('intelligence')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold tracking-wide transition-all flex items-center gap-2 whitespace-nowrap ${
              activeTab === 'intelligence'
                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <span>🧠</span>
            <span>Intelligence & History</span>
          </button>
        </div>

        {/* Tab Content */}
        {activeTab === 'overview' && (
          <Overview
            stats={stats}
            incidents={incidents}
            onSelectTab={setActiveTab}
            onSelectIncident={setSelectedIncident}
          />
        )}

        {activeTab === 'incidents' && (
          <IncidentList
            incidents={incidents}
            onSelectIncident={setSelectedIncident}
            onTriggerRotate={handleTriggerRotate}
          />
        )}

        {activeTab === 'rotation' && (
          <RotationConsole
            incidents={incidents}
            onTriggerRotate={handleTriggerRotate}
            onSelectIncident={setSelectedIncident}
          />
        )}

        {activeTab === 'vault' && (
          <VaultViewer
            health={health}
            incidents={incidents}
          />
        )}

        {activeTab === 'intelligence' && (
          <IntelligencePanel
            onRefreshIncidents={loadData}
          />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 py-4 px-6 text-center text-xs font-mono text-slate-500">
        GitOps Secret Shield · DevSecOps Lab · Preventing Credential Leaks with Auto-Rotation · Last updated: {lastUpdated.toLocaleTimeString()}
      </footer>

      {/* Incident Detail Modal */}
      {selectedIncident && (
        <IncidentDetailModal
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onRefresh={loadData}
          onTriggerRotate={handleTriggerRotate}
        />
      )}
    </div>
  );
}
