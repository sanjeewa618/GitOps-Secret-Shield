import React, { useState } from 'react';

export default function IncidentList({ incidents, onSelectIncident, onTriggerRotate }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  const filtered = incidents.filter((inc) => {
    const matchesSearch =
      searchTerm === '' ||
      inc.incident_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      inc.repository.toLowerCase().includes(searchTerm.toLowerCase()) ||
      inc.detector_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      inc.file_path.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (inc.author && inc.author.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesStatus =
      statusFilter === 'ALL' ||
      inc.status === statusFilter ||
      inc.remediation_status === statusFilter;

    const matchesSeverity =
      severityFilter === 'ALL' || inc.severity === severityFilter;

    return matchesSearch && matchesStatus && matchesSeverity;
  });

  const getStatusBadge = (status, remediation) => {
    if (status === 'rotated') {
      return (
        <span className="px-2.5 py-1 text-[11px] font-mono font-bold rounded-md bg-emerald-950/80 text-emerald-400 border border-emerald-500/40">
          ROTATED
        </span>
      );
    }
    if (remediation === 'manual_remediation_required') {
      return (
        <span className="px-2.5 py-1 text-[11px] font-mono font-bold rounded-md bg-purple-950/80 text-purple-400 border border-purple-500/40">
          MANUAL REMEDIATION
        </span>
      );
    }
    if (status === 'rotation_required') {
      return (
        <span className="px-2.5 py-1 text-[11px] font-mono font-bold rounded-md bg-amber-950/80 text-amber-400 border border-amber-500/40">
          ROTATION REQ
        </span>
      );
    }
    if (status === 'rotation_in_progress') {
      return (
        <span className="px-2.5 py-1 text-[11px] font-mono font-bold rounded-md bg-cyan-950/80 text-cyan-400 border border-cyan-500/40 animate-pulse">
          IN PROGRESS
        </span>
      );
    }
    if (status === 'investigating') {
      return (
        <span className="px-2.5 py-1 text-[11px] font-mono font-bold rounded-md bg-blue-950/80 text-blue-400 border border-blue-500/40">
          INVESTIGATING
        </span>
      );
    }
    return (
      <span className="px-2.5 py-1 text-[11px] font-mono font-bold rounded-md bg-slate-800 text-slate-300 border border-slate-700">
        {status.toUpperCase()}
      </span>
    );
  };

  return (
    <div className="space-y-4">
      {/* Search and Filters Bar */}
      <div className="glass-panel p-4 border border-slate-800 rounded-xl bg-slate-900/60 flex flex-col sm:flex-row gap-3 items-center justify-between">
        <div className="relative w-full sm:w-96">
          <input
            type="text"
            placeholder="Search incident ID, detector, repo, file, author..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 transition-colors"
          />
          {searchTerm && (
            <button
              onClick={() => setSearchTerm('')}
              className="absolute right-2.5 top-2.5 text-slate-500 hover:text-slate-300 text-xs"
            >
              ✕
            </button>
          )}
        </div>

        <div className="flex items-center gap-2.5 w-full sm:w-auto">
          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-300 focus:outline-none focus:border-emerald-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="rotation_required">Rotation Required</option>
            <option value="rotated">Rotated (Secured)</option>
            <option value="manual_remediation_required">Manual Remediation Required</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
          </select>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-300 focus:outline-none focus:border-emerald-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
          </select>
        </div>
      </div>

      {/* Incidents Table */}
      <div className="glass-panel border border-slate-800 rounded-xl bg-slate-900/50 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/80 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-4">Incident ID</th>
                <th className="py-3 px-4">Detector Rule</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Masked Secret</th>
                <th className="py-3 px-4">Location (File:Line)</th>
                <th className="py-3 px-4">Committer</th>
                <th className="py-3 px-4">Remediation Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500 font-sans">
                    No matching security incidents found.
                  </td>
                </tr>
              ) : (
                filtered.map((inc) => (
                  <tr
                    key={inc.incident_id}
                    className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                    onClick={() => onSelectIncident(inc)}
                  >
                    {/* Incident ID */}
                    <td className="py-3.5 px-4 font-bold text-white whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span className="text-emerald-400">🛡️</span>
                        <span>{inc.incident_id}</span>
                      </div>
                    </td>

                    {/* Detector Rule */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[11px]">
                        {inc.detector_name}
                      </span>
                      {inc.is_false_positive && (
                        <span className="ml-1.5 px-1.5 py-0.5 rounded bg-slate-700 text-slate-300 text-[10px]">
                          FP
                        </span>
                      )}
                    </td>

                    {/* Risk Score */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className={`font-bold ${
                        (inc.risk_score ?? 75) >= 80
                          ? 'text-rose-400'
                          : (inc.risk_score ?? 75) >= 60
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                      }`}>
                        {inc.risk_score ?? 75}
                      </span>
                      <span className="text-[10px] text-slate-500 ml-1">
                        ({inc.severity})
                      </span>
                    </td>

                    {/* Masked Secret */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <code className="text-rose-400 bg-rose-950/40 px-2 py-0.5 rounded border border-rose-900/40">
                        {inc.secret_masked}
                      </code>
                    </td>

                    {/* Location */}
                    <td className="py-3.5 px-4 text-slate-400 max-w-xs truncate" title={inc.file_path}>
                      <span className="text-cyan-400">{inc.file_path}</span>
                      <span className="text-slate-500">:{inc.line_number}</span>
                    </td>

                    {/* Author */}
                    <td className="py-3.5 px-4 text-slate-300 whitespace-nowrap">
                      {inc.author || 'unknown'}
                    </td>

                    {/* Status Badge */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {getStatusBadge(inc.status, inc.remediation_status)}
                    </td>

                    {/* Actions */}
                    <td className="py-3.5 px-4 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-2">
                        {inc.status !== 'rotated' && (
                          <button
                            onClick={() => onTriggerRotate(inc.incident_id)}
                            className="px-2.5 py-1 text-[11px] font-sans font-semibold bg-emerald-600 hover:bg-emerald-500 text-slate-950 rounded transition-colors"
                          >
                            Rotate
                          </button>
                        )}
                        <button
                          onClick={() => onSelectIncident(inc)}
                          className="px-2.5 py-1 text-[11px] font-sans bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded transition-colors"
                        >
                          Details
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="px-4 py-3 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between text-xs text-slate-400 font-mono">
          <span>Showing {filtered.length} of {incidents.length} incidents</span>
          <span>Deduplication & HMAC Verified</span>
        </div>
      </div>
    </div>
  );
}
