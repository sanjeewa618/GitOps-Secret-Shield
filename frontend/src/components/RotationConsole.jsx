import React, { useState } from 'react';

export default function RotationConsole({ incidents, onTriggerRotate, onSelectIncident }) {
  const [selectedIncidentId, setSelectedIncidentId] = useState('');
  const [dbUser, setDbUser] = useState('app_service_user');
  const [rotationResult, setRotationResult] = useState(null);
  const [isRotating, setIsRotating] = useState(false);

  // Candidates for rotation
  const rotatableIncidents = incidents.filter(
    (inc) => inc.status !== 'resolved'
  );

  const handleExecuteRotation = async (incId) => {
    const targetId = incId || selectedIncidentId;
    if (!targetId) return;

    setIsRotating(true);
    setRotationResult(null);

    try {
      const res = await onTriggerRotate(targetId, { db_user: dbUser });
      setRotationResult(res);
    } catch (err) {
      setRotationResult({
        success: false,
        error: err.message || 'Rotation execution failed',
      });
    } finally {
      setIsRotating(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Console Header Banner */}
      <div className="glass-panel p-6 border border-slate-800 rounded-xl bg-gradient-to-r from-slate-900 via-slate-900 to-emerald-950/30">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
              </span>
              <h2 className="text-lg font-bold text-white tracking-tight">
                Automated Credential Rotation & Remediation Console
              </h2>
            </div>
            <p className="text-xs text-slate-400 mt-2 max-w-2xl">
              Zero-touch automated rotation for supported providers (PostgreSQL) with 32-character high-entropy password generation, database user synchronization, and secure storage in HashiCorp Vault KV v2.
            </p>
          </div>

          <div className="flex items-center gap-3 font-mono text-xs">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-slate-400 text-[10px] uppercase">Automated Provider</div>
              <div className="text-emerald-400 font-bold mt-0.5">PostgreSQL Active</div>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-slate-400 text-[10px] uppercase">Target Vault</div>
              <div className="text-amber-400 font-bold mt-0.5">KV v2 Mount Active</div>
            </div>
          </div>
        </div>
      </div>

      {/* Interactive Trigger Form */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="glass-panel p-5 border border-slate-800 rounded-xl bg-slate-900/50 lg:col-span-1 space-y-4">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <span>⚡</span> Trigger Rotation on Incident
          </h3>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1.5">Select Incident</label>
            <select
              value={selectedIncidentId}
              onChange={(e) => setSelectedIncidentId(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
            >
              <option value="">-- Choose Incident to Rotate --</option>
              {rotatableIncidents.map((inc) => (
                <option key={inc.incident_id} value={inc.incident_id}>
                  {inc.incident_id} [{inc.detector_name}] - {inc.status}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1.5">Target DB Username</label>
            <input
              type="text"
              value={dbUser}
              onChange={(e) => setDbUser(e.target.value)}
              placeholder="e.g. app_service_user"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
            />
            <p className="text-[10px] text-slate-500 mt-1">Applies to PostgreSQL credential findings.</p>
          </div>

          <button
            onClick={() => handleExecuteRotation()}
            disabled={!selectedIncidentId || isRotating}
            className="w-full py-2.5 px-4 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
          >
            {isRotating ? (
              <>
                <svg className="w-4 h-4 animate-spin text-slate-950" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
                Rotating & Storing in Vault...
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
                Execute Rotation Workflow
              </>
            )}
          </button>

          {/* Result Output */}
          {rotationResult && (
            <div className={`p-4 rounded-lg border text-xs font-mono ${
              rotationResult.success
                ? 'bg-emerald-950/60 text-emerald-300 border-emerald-500/40'
                : 'bg-rose-950/60 text-rose-300 border-rose-500/40'
            }`}>
              <div className="font-bold flex items-center gap-1.5 mb-2">
                <span>{rotationResult.success ? '✅ SUCCESS' : '⚠️ REMEDIATION NOTICE'}</span>
              </div>
              <div className="space-y-1 text-[11px]">
                <div><strong>Incident:</strong> {rotationResult.incident_id}</div>
                <div><strong>Status:</strong> {rotationResult.status || rotationResult.remediation_status}</div>
                {rotationResult.vault_secret_path && (
                  <div className="text-amber-300 truncate">
                    <strong>Vault:</strong> {rotationResult.vault_secret_path}
                  </div>
                )}
                {rotationResult.replacement_preview && (
                  <div>
                    <strong>New Password:</strong> {rotationResult.replacement_preview}
                  </div>
                )}
                <div className="text-slate-400 mt-2 text-[10px]">
                  {rotationResult.notes}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Rotation Queue & Provider Status */}
        <div className="glass-panel p-5 border border-slate-800 rounded-xl bg-slate-900/50 lg:col-span-2 space-y-4">
          <h3 className="text-sm font-semibold text-white flex items-center justify-between">
            <span>Remediation Work Queue</span>
            <span className="text-xs font-mono text-slate-400">
              {rotatableIncidents.length} pending / active items
            </span>
          </h3>

          <div className="space-y-2.5 max-h-[380px] overflow-y-auto pr-1">
            {rotatableIncidents.map((inc) => {
              const isDb = inc.detector_name.toLowerCase().includes('database') || inc.detector_name.toLowerCase().includes('postgres');
              return (
                <div
                  key={inc.incident_id}
                  className="p-3.5 bg-slate-950/60 border border-slate-800 rounded-lg flex items-center justify-between gap-4 font-mono text-xs"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-white">{inc.incident_id}</span>
                      <span className={`text-[10px] px-2 py-0.5 rounded font-semibold ${
                        isDb ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-slate-800 text-slate-300'
                      }`}>
                        {isDb ? '⚡ Auto-Supported (PostgreSQL)' : '🛠️ Manual Remediation (Cloud/API)'}
                      </span>
                    </div>
                    <div className="text-slate-400 text-[11px] truncate mt-1">
                      {inc.detector_name} · <span className="text-cyan-400">{inc.file_path}:{inc.line_number}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 whitespace-nowrap">
                    {isDb && inc.status !== 'rotated' ? (
                      <button
                        onClick={() => handleExecuteRotation(inc.incident_id)}
                        disabled={isRotating}
                        className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs rounded transition-colors"
                      >
                        Auto-Rotate
                      </button>
                    ) : (
                      <button
                        onClick={() => onSelectIncident(inc)}
                        className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded text-xs transition-colors"
                      >
                        View Guide
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
