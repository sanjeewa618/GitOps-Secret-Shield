import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

export default function VaultViewer({ health, incidents }) {
  const [vaultSecrets, setVaultSecrets] = useState({});
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [activeSecretData, setActiveSecretData] = useState(null);
  const [isLoadingSecret, setIsLoadingSecret] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [fetchError, setFetchError] = useState(null);

  const vaultIncidents = incidents.filter((inc) => inc.vault_secret_path);

  const handleInspectSecret = async (inc) => {
    setSelectedIncident(inc);
    setIsLoadingSecret(true);
    setFetchError(null);
    setActiveSecretData(null);
    setShowPassword(false);

    try {
      const data = await api.getVaultSecret(inc.incident_id);
      setActiveSecretData(data.secret_data);
    } catch (err) {
      setFetchError(err.message || 'Failed to retrieve secret from Vault');
    } finally {
      setIsLoadingSecret(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Vault Server Status Banner */}
      <div className="glass-panel p-6 border border-slate-800 rounded-xl bg-slate-900/60 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </span>
            <h2 className="text-lg font-bold text-white tracking-tight">
              HashiCorp Vault KV v2 Secrets Inspector
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-2 max-w-2xl">
            All rotated credentials are cryptographically stored in HashiCorp Vault under the structured path convention:
            <code className="text-amber-300 ml-1 bg-amber-950/40 px-1.5 py-0.5 rounded font-mono">
              secret/data/gitops-secret-shield/{'{repository}'}/{'{incident_id}'}
            </code>
          </p>
        </div>

        <div className="flex items-center gap-3 font-mono text-xs">
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <div className="text-slate-400 text-[10px] uppercase">Engine Status</div>
            <div className="text-emerald-400 font-bold mt-0.5">
              {health.vault === 'healthy' ? 'Unsealed (Active)' : 'Unreachable'}
            </div>
          </div>
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <div className="text-slate-400 text-[10px] uppercase">Engine Type</div>
            <div className="text-amber-400 font-bold mt-0.5">KV v2 (Versioned)</div>
          </div>
        </div>
      </div>

      {/* Vault Path Explorer & Secret Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Vault Paths List */}
        <div className="glass-panel p-5 border border-slate-800 rounded-xl bg-slate-900/50 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">Stored Vault Secrets</h3>
            <span className="text-xs font-mono text-slate-400">
              {vaultIncidents.length} credential(s) in Vault
            </span>
          </div>

          {vaultIncidents.length === 0 ? (
            <div className="p-8 text-center text-slate-500 text-xs font-mono border border-dashed border-slate-800 rounded-lg">
              No credentials have been rotated into Vault yet.
              <p className="text-[11px] text-slate-400 mt-1 font-sans">
                Trigger rotation on a PostgreSQL incident to generate and store credentials.
              </p>
            </div>
          ) : (
            <div className="space-y-2 max-h-[400px] overflow-y-auto pr-1">
              {vaultIncidents.map((inc) => {
                const isSelected = selectedIncident?.incident_id === inc.incident_id;
                return (
                  <div
                    key={inc.incident_id}
                    onClick={() => handleInspectSecret(inc)}
                    className={`p-3 rounded-lg border cursor-pointer font-mono text-xs transition-all ${
                      isSelected
                        ? 'bg-amber-950/40 border-amber-500/60 shadow-lg shadow-amber-500/10'
                        : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white">{inc.incident_id}</span>
                      <span className="text-[10px] bg-slate-800 px-2 py-0.5 rounded text-amber-300">
                        KV v2 Path
                      </span>
                    </div>
                    <div className="text-[11px] text-amber-400/90 truncate mt-1">
                      {inc.vault_secret_path}
                    </div>
                    <div className="text-[10px] text-slate-500 mt-1 flex justify-between">
                      <span>{inc.detector_name}</span>
                      <span>{new Date(inc.updated_at).toLocaleTimeString()}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Live Vault Secret Data Viewer */}
        <div className="glass-panel p-5 border border-slate-800 rounded-xl bg-slate-900/50 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">Vault Secret Payload</h3>
            {activeSecretData && (
              <button
                onClick={() => setShowPassword(!showPassword)}
                className="text-xs font-mono text-amber-400 hover:text-amber-300 flex items-center gap-1"
              >
                {showPassword ? '🔒 Mask Passwords' : '👁️ Reveal Passwords'}
              </button>
            )}
          </div>

          {!selectedIncident ? (
            <div className="p-12 text-center text-slate-500 text-xs font-mono border border-dashed border-slate-800 rounded-lg">
              Select an incident from the left to inspect its decrypted Vault payload.
            </div>
          ) : isLoadingSecret ? (
            <div className="p-12 text-center text-slate-400 text-xs font-mono flex items-center justify-center gap-2">
              <svg className="w-4 h-4 animate-spin text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              Decrypting and reading from HashiCorp Vault...
            </div>
          ) : fetchError ? (
            <div className="p-4 rounded-lg bg-rose-950/60 border border-rose-500/40 text-rose-300 text-xs font-mono">
              Error fetching from Vault: {fetchError}
            </div>
          ) : activeSecretData ? (
            <div className="space-y-3 font-mono text-xs">
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                <div className="text-[10px] text-slate-500 uppercase">Vault Path</div>
                <div className="text-amber-300 break-all mt-0.5">{selectedIncident.vault_secret_path}</div>
              </div>

              <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
                <div className="text-[10px] text-slate-400 uppercase font-bold border-b border-slate-800 pb-1">
                  Stored Key-Value Pairs
                </div>
                {Object.entries(activeSecretData).map(([key, val]) => {
                  const isPass = key.toLowerCase().includes('password') || key.toLowerCase().includes('secret');
                  return (
                    <div key={key} className="flex flex-col sm:flex-row sm:items-center justify-between py-1 border-b border-slate-800/40 text-xs gap-1">
                      <span className="text-slate-400">{key}:</span>
                      <span className="text-emerald-400 font-bold break-all">
                        {isPass && !showPassword ? '••••••••••••••••••••••••••••••••' : String(val)}
                      </span>
                    </div>
                  );
                })}
              </div>

              <div className="text-[10px] text-slate-500">
                Authenticated with HashiCorp Vault API · Token: root (Dev Mode)
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
