import React, { useState } from 'react';
import { api } from '../services/api';

export default function IncidentDetailModal({ incident, onClose, onRefresh, onTriggerRotate }) {
  const [isRotating, setIsRotating] = useState(false);
  const [rotationMsg, setRotationMsg] = useState(null);
  const [newStatus, setNewStatus] = useState(incident.status);
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);

  if (!incident) return null;

  const isDbSecret =
    incident.detector_name.toLowerCase().includes('database') ||
    incident.detector_name.toLowerCase().includes('postgres');

  const handleRotate = async () => {
    setIsRotating(true);
    setRotationMsg(null);
    try {
      const res = await onTriggerRotate(incident.incident_id);
      setRotationMsg({
        success: res.success,
        text: res.notes || (res.success ? 'Rotation successful!' : 'Rotation notice generated.'),
      });
      onRefresh();
    } catch (err) {
      setRotationMsg({ success: false, text: err.message });
    } finally {
      setIsRotating(false);
    }
  };

  const handleUpdateStatus = async () => {
    setIsUpdatingStatus(true);
    try {
      await api.updateIncident(incident.incident_id, { status: newStatus });
      onRefresh();
      onClose();
    } catch (err) {
      alert(`Error updating status: ${err.message}`);
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto shadow-2xl p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <span className="p-2 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-bold">
              🛡️
            </span>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-extrabold text-white font-mono">
                  {incident.incident_id}
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-rose-950 text-rose-400 border border-rose-800">
                  {incident.severity}
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Commit: <span className="text-cyan-400">{incident.commit_sha?.slice(0, 10)}</span> by {incident.author}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            ✕
          </button>
        </div>

        {/* Metadata Grid */}
        <div className="grid grid-cols-2 gap-4 font-mono text-xs">
          <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800">
            <div className="text-[10px] text-slate-500 uppercase">Detector Rule</div>
            <div className="text-slate-200 font-bold mt-0.5">{incident.detector_name}</div>
          </div>
          <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800">
            <div className="text-[10px] text-slate-500 uppercase">Masked Secret Value</div>
            <div className="text-rose-400 font-bold mt-0.5">{incident.secret_masked}</div>
          </div>
          <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800">
            <div className="text-[10px] text-slate-500 uppercase">Repository</div>
            <div className="text-cyan-400 font-bold mt-0.5 truncate">{incident.repository}</div>
          </div>
          <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800">
            <div className="text-[10px] text-slate-500 uppercase">File & Line Location</div>
            <div className="text-slate-200 font-bold mt-0.5 truncate">{incident.file_path}:{incident.line_number}</div>
          </div>
          <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800">
            <div className="text-[10px] text-slate-500 uppercase">Incident Status</div>
            <div className="text-emerald-400 font-bold mt-0.5">{incident.status}</div>
          </div>
          <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800">
            <div className="text-[10px] text-slate-500 uppercase">Remediation Status</div>
            <div className="text-amber-400 font-bold mt-0.5">{incident.remediation_status}</div>
          </div>
        </div>

        {/* Vault Secret Path (if any) */}
        {incident.vault_secret_path && (
          <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-500/40 font-mono text-xs">
            <div className="text-[10px] text-amber-400 uppercase font-bold">HashiCorp Vault Secret Path</div>
            <div className="text-amber-300 mt-0.5 break-all">{incident.vault_secret_path}</div>
          </div>
        )}

        {/* Audit Log Notes */}
        <div className="p-4 rounded-lg bg-slate-950/80 border border-slate-800 space-y-2">
          <div className="text-[11px] font-mono text-slate-400 uppercase font-bold flex items-center justify-between">
            <span>Remediation Notes & Audit Log</span>
            <span className="text-[10px] text-slate-500">
              Recorded: {new Date(incident.created_at).toLocaleString()}
            </span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed font-sans">
            {incident.remediation_notes || 'No special notes recorded.'}
          </p>
        </div>

        {/* Dynamic Remediation Playbook */}
        <div className="p-4 rounded-lg border border-slate-800 bg-slate-950 space-y-3">
          <div className="text-xs font-bold text-white flex items-center gap-2">
            <span>🛡️</span> Security Remediation Playbook
          </div>

          {isDbSecret ? (
            <div className="space-y-3">
              <p className="text-xs text-slate-400">
                This is a database credential leak. Our automated rotation engine can directly generate a new 32-character high-entropy password, alter the database role, and store the updated secret in HashiCorp Vault.
              </p>
              <button
                onClick={handleRotate}
                disabled={isRotating || incident.status === 'rotated'}
                className="w-full py-2 px-4 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs rounded-lg transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
              >
                {isRotating
                  ? 'Executing Automated Rotation...'
                  : incident.status === 'rotated'
                  ? 'Already Rotated & Secured in Vault'
                  : 'Trigger Zero-Touch Auto-Rotation'}
              </button>
            </div>
          ) : (
            <div className="space-y-2 text-xs text-slate-300 font-mono">
              <p className="text-[11px] text-slate-400 font-sans">
                Automated rotation is not currently enabled for {incident.detector_name}. Execute the manual remediation steps below:
              </p>
              <div className="p-3 bg-slate-900 rounded border border-slate-800 text-[11px] text-slate-300 space-y-1">
                <div>1. Log into your {incident.detector_name} provider management console.</div>
                <div>2. Locate the exposed key ending in <code>{incident.secret_masked.slice(-4)}</code>.</div>
                <div>3. Immediately deactivate and permanently revoke the compromised credential.</div>
                <div>4. Generate a new key and update your CI/CD pipeline secrets.</div>
              </div>
            </div>
          )}

          {rotationMsg && (
            <div className={`p-3 rounded text-xs font-mono ${
              rotationMsg.success ? 'bg-emerald-950 text-emerald-300' : 'bg-rose-950 text-rose-300'
            }`}>
              {rotationMsg.text}
            </div>
          )}
        </div>

        {/* Change Status Action */}
        <div className="border-t border-slate-800 pt-4 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-slate-400">Update Status:</span>
            <select
              value={newStatus}
              onChange={(e) => setNewStatus(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-xs text-slate-200"
            >
              <option value="detected">detected</option>
              <option value="investigating">investigating</option>
              <option value="rotation_required">rotation_required</option>
              <option value="rotation_in_progress">rotation_in_progress</option>
              <option value="rotated">rotated</option>
              <option value="resolved">resolved</option>
            </select>
            <button
              onClick={handleUpdateStatus}
              disabled={isUpdatingStatus}
              className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs border border-slate-700 font-sans"
            >
              Save
            </button>
          </div>

          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
