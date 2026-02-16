import React, { useEffect, useState } from 'react';
import RuleBuilder, { RuleDraft } from '../../../components/RuleBuilder';
import SigmaImport from '../../../components/SigmaImport';

const API_BASE = import.meta.env.VITE_API_BASE || '';

interface RuleItem {
  id: string;
  name: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  enabled: boolean;
  hit_count: number;
  source?: string | null;
}

const templates: RuleDraft[] = [
  { name: 'C2 Beaconing', description: 'Repeated outbound checks to same destination', severity: 'high', enabled: true, logic: 'AND', conditions: [{ field: 'duration', operator: 'lt', value: '2' }, { field: 'dst_port', operator: 'in', value: '80,443' }], actions: ['alert', 'tag'] },
  { name: 'DNS Tunneling', description: 'Long query names indicate potential tunneling', severity: 'high', enabled: true, logic: 'AND', conditions: [{ field: 'dns_query', operator: 'regex', value: '^[a-zA-Z0-9]{40,}\\.' }], actions: ['alert', 'add_to_hunt'] },
  { name: 'Large Data Exfil', description: 'High bytes response volume', severity: 'critical', enabled: true, logic: 'AND', conditions: [{ field: 'bytes_resp', operator: 'gt', value: '10000000' }], actions: ['alert', 'set_severity'] },
  { name: 'Port Scanning', description: 'Source targeting many destination ports', severity: 'medium', enabled: true, logic: 'OR', conditions: [{ field: 'dst_port', operator: 'in', value: '21,22,23,25,53,80,443,3389' }], actions: ['tag'] },
  { name: 'Suspicious User-Agent', description: 'Command-line tooling user agents', severity: 'medium', enabled: true, logic: 'OR', conditions: [{ field: 'user_agent', operator: 'contains', value: 'curl' }, { field: 'user_agent', operator: 'contains', value: 'wget' }, { field: 'user_agent', operator: 'contains', value: 'python-requests' }], actions: ['alert'] },
];

const severityClass: Record<RuleItem['severity'], string> = {
  low: 'bg-green-500/20 text-green-300',
  medium: 'bg-yellow-500/20 text-yellow-300',
  high: 'bg-orange-500/20 text-orange-300',
  critical: 'bg-red-500/20 text-red-300',
};

const Rules: React.FC = () => {
  const [rules, setRules] = useState<RuleItem[]>([]);
  const [selectedTemplate, setSelectedTemplate] = useState<number>(0);

  const fetchRules = async () => {
    const res = await fetch(`${API_BASE}/api/v1/rules`);
    if (!res.ok) return;
    const data = await res.json();
    setRules(data.rules || []);
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const saveRule = async (draft: RuleDraft) => {
    await fetch(`${API_BASE}/api/v1/rules`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(draft),
    });
    await fetchRules();
  };

  const testRule = async (draft: RuleDraft) => {
    const createRes = await fetch(`${API_BASE}/api/v1/rules`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...draft, enabled: false }),
    });
    const created = await createRes.json();
    const testRes = await fetch(`${API_BASE}/api/v1/rules/${created.id}/test`, { method: 'POST' });
    const testData = await testRes.json();
    await fetch(`${API_BASE}/api/v1/rules/${created.id}`, { method: 'DELETE' });
    return testData;
  };

  const toggleEnabled = async (rule: RuleItem) => {
    await fetch(`${API_BASE}/api/v1/rules/${rule.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: !rule.enabled }),
    });
    await fetchRules();
  };

  const deleteRule = async (ruleId: string) => {
    await fetch(`${API_BASE}/api/v1/rules/${ruleId}`, { method: 'DELETE' });
    await fetchRules();
  };

  const runTest = async (ruleId: string) => {
    await fetch(`${API_BASE}/api/v1/rules/${ruleId}/test`, { method: 'POST' });
    await fetchRules();
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-100">Rules</h1>
        <p className="text-sm text-gray-500 mt-1">Custom detection rules and Sigma imports</p>
      </div>

      <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <span className="text-sm text-gray-300">Template</span>
          <select
            value={selectedTemplate}
            onChange={(e) => setSelectedTemplate(Number(e.target.value))}
            className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-200"
          >
            {templates.map((tpl, idx) => <option key={tpl.name} value={idx}>{tpl.name}</option>)}
          </select>
        </div>
        <RuleBuilder initial={templates[selectedTemplate]} onSave={saveRule} onTest={testRule} />
      </div>

      <SigmaImport onImported={fetchRules} />

      <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5 overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-xs text-gray-500 border-b border-gray-700">
              <th className="text-left py-2">Name</th>
              <th className="text-left py-2">Severity</th>
              <th className="text-left py-2">Enabled</th>
              <th className="text-left py-2">Hits</th>
              <th className="text-left py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((rule) => (
              <tr key={rule.id} className="border-b border-gray-800/60">
                <td className="py-2 text-gray-200">
                  {rule.name}
                  {rule.source?.startsWith('sigma') && (
                    <span className="ml-2 text-[10px] uppercase px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300">Sigma</span>
                  )}
                </td>
                <td className="py-2">
                  <span className={`text-xs px-2 py-0.5 rounded ${severityClass[rule.severity]}`}>{rule.severity}</span>
                </td>
                <td className="py-2">
                  <input type="checkbox" checked={rule.enabled} onChange={() => toggleEnabled(rule)} className="accent-cyan-500" />
                </td>
                <td className="py-2 text-gray-400">{rule.hit_count}</td>
                <td className="py-2 space-x-2">
                  <button onClick={() => runTest(rule.id)} className="text-xs px-2 py-1 rounded bg-gray-800 border border-gray-700 text-gray-300">Test</button>
                  <button onClick={() => deleteRule(rule.id)} className="text-xs px-2 py-1 rounded bg-red-900/40 text-red-300">Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Rules;
