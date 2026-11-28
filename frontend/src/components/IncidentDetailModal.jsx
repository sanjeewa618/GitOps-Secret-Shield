import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

export default function IncidentDetailModal({ incident, onClose, onRefresh, onTriggerRotate }) {
  const [isRotating, setIsRotating] = useState(false);
  const [rotationMsg, setRotationMsg] = useState(null);
  const [newStatus, setNewStatus] = useState(incident.status);
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);

  // Phase 3 state
  const [correlated, setCorrelated] = useState(null);
  const [remediationPlan, setRemediationPlan] = useState(null);
  const [remediationAudit, setRemediationAudit] = useState([]);
  const [fpReason, setFpReason] = useState('');
  const [fpLoading, setFpLoading] = useState(false);

  useEffect(() => {
    if (!incident) return;
    api.getCorrelatedIncidents(incident.incident_id).then(setCorrelated).catch(() => {});
    api.getRemediationPlan(incident.incident_id).then(setRemediationPlan).catch(() => {});
    api.getRemediationAudit(incident.incident_id).then((d) => setRemediationAudit(d.audit_logs || [])).catch(() => {});
  }, [incident?.incident_id]);

  if (!incident) return null;

  const isDbSecret =
    incident.detector_name.toLowerCase().includes('database') ||
    incident.detector_name.toLowerCase().includes('postgres') ||
    incident.detector_name.toLowerCase().includes('mysql') ||
    incident.detector_name.toLowerCase().includes('redis') ||
    incident.detector_name.toLowerCase().includes('mongo');

  let parsedRiskFactors = null;
  try {
    parsedRiskFactors = incident.risk_factors ? JSON.parse(incident.risk_factors) : null;
  } catch {
    parsedRiskFactors = null;
  }

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

  const handleDryRun = async () => {
    setIsRotating(true);
    setRotationMsg(null);
    try {
      const res = await api.executeRemediation(incident.incident_id, { dry_run: true, approved: false });
      setRotationMsg({ success: true, text: `DRY-RUN: ${res.plan?.proposed_action || res.message}` });
      const auditRes = await api.getRemediationAudit(incident.incident_id);
      setRemediationAudit(auditRes.audit_logs || []);
    } catch (err) {
      setRotationMsg({ success: false, text: `Dry-run error (requires admin sign-in): ${err.message}` });
    } finally {
      setIsRotating(false);
    }
  };

  const handleApprovedExecute = async () => {
    setIsRotating(true);
    setRotationMsg(null);
    try {
      const res = await api.executeRemediation(incident.incident_id, { dry_run: false, approved: true });
      setRotationMsg({
        success: Boolean(res.success),
        text: res.notes || (res.success ? 'Approved remediation executed & verified!' : 'Remediation requires manual action or metadata.'),
      });
      onRefresh();
      const auditRes = await api.getRemediationAudit(incident.incident_id);
      setRemediationAudit(auditRes.audit_logs || []);
    } catch (err) {
      setRotationMsg({ success: false, text: `Execution error: ${err.message}` });
    } finally {
      setIsRotating(false);
    }
  };

  const handleToggleFalsePositive = async () => {
    setFpLoading(true);
    try {
      const nextState = !incident.is_false_positive;
      await api.markIncidentFalsePositive(incident.incident_id, {
        is_false_positive: nextState,
        reason: fpReason || (nextState ? 'Verified non-production placeholder' : 'Reopened for investigation'),
      });
      setFpReason('');
      onRefresh();
      onClose();
    } catch (err) {
      alert(`False-positive update failed (admin sign-in required): ${err.message}`);
    } finally {
      setFpLoading(false);
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
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-base font-extrabold text-white font-mono">
                  {incident.incident_id}
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-rose-950 text-rose-400 border border-rose-800">
                  {incident.severity} · Risk {incident.risk_score ?? 75}/100
                </span>
                {incident.is_false_positive && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-slate-800 text-slate-300 border border-slate-700">
                    FALSE POSITIVE
                  </span>
                )}
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
            <div className="text-[10px] text-slate-500 uppercase">Detector & Category</div>
            <div className="text-slate-200 font-bold mt-0.5">
              {incident.detector_name} ({incident.secret_category || 'generic_secret'})
            </div>
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
            <div className="text-[10px] text-slate-500 uppercase">Correlation & Occurrences</div>
            <div className="text-amber-400 font-bold mt-0.5">
              {incident.occurrence_count || 1}x ({incident.correlation_group_id || 'Single'})
            </div>
          </div>
        </div>

        {/* Risk Factors Breakdown (Phase 3) */}
        {parsedRiskFactors && (
          <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 font-mono text-[11px] space-y-1">
            <div className="text-[10px] text-slate-400 uppercase font-bold">
              Risk Scoring Breakdown ({parsedRiskFactors.risk_assessment_type})
            </div>
            <div className="text-slate-300">
              Base: {parsedRiskFactors.base_sensitivity_score} · Location: {parsedRiskFactors.location_factor} ({parsedRiskFactors.location_adjustment >= 0 ? '+' : ''}{parsedRiskFactors.location_adjustment}) · Verification: {parsedRiskFactors.verification_fact}
            </div>
          </div>
        )}

        {/* Correlated Incidents (Phase 3) */}
        {correlated && correlated.related && correlated.related.length > 0 && (
          <div className="p-3 rounded-lg bg-cyan-950/20 border border-cyan-500/30 font-mono text-xs space-y-1.5">
            <div className="text-[10px] text-cyan-400 uppercase font-bold">
              Correlated Exposures ({correlated.related.length} related)
            </div>
            {correlated.related.map((r) => (
              <div key={r.incident_id} className="text-[11px] text-slate-300 flex justify-between">
                <span>{r.incident_id} · {r.file_path}:{r.line_number}</span>
                <span className="text-slate-400">{r.status}</span>
              </div>
            ))}
          </div>
        )}

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

        {/* Dynamic Remediation Playbook + Dry-Run & Approval (Phase 3) */}
        <div className="p-4 rounded-lg border border-slate-800 bg-slate-950 space-y-3">
          <div className="text-xs font-bold text-white flex items-center gap-2">
            <span>🛡️</span> Security Remediation Playbook & Workflow
          </div>

          {remediationPlan && (
            <p className="text-xs text-slate-300 leading-relaxed">
              {remediationPlan.proposed_action}
            </p>
          )}

          <div className="flex flex-wrap gap-2">
            <button
              onClick={handleDryRun}
              disabled={isRotating}
              className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-500/30 font-bold text-xs rounded-lg transition-colors disabled:opacity-50"
            >
              Dry-Run Preview
            </button>
            <button
              onClick={handleApprovedExecute}
              disabled={isRotating || incident.status === 'rotated'}
              className="px-3 py-2 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs rounded-lg transition-colors disabled:opacity-50"
            >
              {incident.status === 'rotated' ? 'Already Rotated' : 'Approve & Execute Remediation'}
            </button>
            {isDbSecret && (
              <button
                onClick={handleRotate}
                disabled={isRotating || incident.status === 'rotated'}
                className="px-3 py-2 bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold text-xs rounded-lg transition-colors disabled:opacity-50"
              >
                Quick Auto-Rotate
              </button>
            )}
          </div>

          {rotationMsg && (
            <div className={`p-3 rounded text-xs font-mono ${
              rotationMsg.success ? 'bg-emerald-950 text-emerald-300' : 'bg-rose-950 text-rose-300'
            }`}>
              {rotationMsg.text}
            </div>
          )}

          {remediationAudit.length > 0 && (
            <div className="pt-2 border-t border-slate-800/80 space-y-1">
              <div className="text-[10px] font-mono text-slate-400 uppercase">Remediation Audit Trail</div>
              {remediationAudit.slice(0, 4).map((a) => (
                <div key={a.id} className="text-[11px] font-mono text-slate-400 flex justify-between">
                  <span>{a.action_type} ({a.status}) by {a.approved_by || 'system'}</span>
                  <span>{a.verified ? 'verified' : a.dry_run ? 'dry-run' : 'unverified'}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* False Positive Control (Phase 3) */}
        <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/60 flex flex-col sm:flex-row gap-2 items-center justify-between">
          <input
            type="text"
            value={fpReason}
            onChange={(e) => setFpReason(e.target.value)}
            placeholder="Reason to mark/unmark as false positive..."
            className="flex-1 w-full bg-slate-900 border border-slate-800 rounded px-2.5 py-1.5 text-xs font-mono text-slate-200"
          />
          <button
            onClick={handleToggleFalsePositive}
            disabled={fpLoading}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded text-xs font-mono whitespace-nowrap"
          >
            {incident.is_false_positive ? 'Clear False Positive' : 'Mark False Positive'}
          </button>
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
