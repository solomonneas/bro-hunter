import React, { useMemo, useState } from 'react';

export type RuleSeverity = 'low' | 'medium' | 'high' | 'critical';
export type RuleLogic = 'AND' | 'OR';

export interface RuleCondition {
  field: string;
  operator: string;
  value: string;
}

export interface RuleDraft {
  name: string;
  description: string;
  severity: RuleSeverity;
  enabled: boolean;
  logic: RuleLogic;
  conditions: RuleCondition[];
  actions: string[];
}

interface RuleBuilderProps {
  initial?: RuleDraft;
  onSave: (draft: RuleDraft) => Promise<void> | void;
  onTest?: (draft: RuleDraft) => Promise<{ match_count: number; sample_matches: Array<Record<string, unknown>> }>;
}

const FIELDS = [
  'src_ip', 'dst_ip', 'src_port', 'dst_port', 'proto', 'conn_state', 'service',
  'dns_query', 'http_method', 'http_uri', 'http_status', 'user_agent', 'tls_server_name',
  'bytes_orig', 'bytes_resp', 'duration',
];

const OPERATORS = ['eq', 'neq', 'contains', 'regex', 'gt', 'lt', 'in', 'not_in', 'cidr_match'];

const ACTIONS = ['tag', 'set_severity', 'add_to_hunt', 'alert'];

const DEFAULT_RULE: RuleDraft = {
  name: '',
  description: '',
  severity: 'medium',
  enabled: true,
  logic: 'AND',
  conditions: [{ field: 'src_ip', operator: 'eq', value: '' }],
  actions: ['alert'],
};

const severityClass: Record<RuleSeverity, string> = {
  low: 'bg-green-500/20 text-green-300 border-green-500/40',
  medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40',
  high: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
  critical: 'bg-red-500/20 text-red-300 border-red-500/40',
};

const RuleBuilder: React.FC<RuleBuilderProps> = ({ initial, onSave, onTest }) => {
  const [draft, setDraft] = useState<RuleDraft>(initial ?? DEFAULT_RULE);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ match_count: number; sample_matches: Array<Record<string, unknown>> } | null>(null);

  const canSave = useMemo(() => draft.name.trim().length > 0 && draft.conditions.length > 0, [draft]);

  const updateCondition = (idx: number, patch: Partial<RuleCondition>) => {
    const next = [...draft.conditions];
    next[idx] = { ...next[idx], ...patch };
    setDraft({ ...draft, conditions: next });
  };

  const addCondition = () => {
    setDraft({
      ...draft,
      conditions: [...draft.conditions, { field: 'src_ip', operator: 'eq', value: '' }],
    });
  };

  const removeCondition = (idx: number) => {
    const next = draft.conditions.filter((_, i) => i !== idx);
    setDraft({ ...draft, conditions: next.length ? next : [{ field: 'src_ip', operator: 'eq', value: '' }] });
  };

  const toggleAction = (action: string) => {
    const has = draft.actions.includes(action);
    setDraft({
      ...draft,
      actions: has ? draft.actions.filter((a) => a !== action) : [...draft.actions, action],
    });
  };

  const runTest = async () => {
    if (!onTest) return;
    setTesting(true);
    try {
      const result = await onTest(draft);
      setTestResult(result);
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="space-y-4 bg-gray-900/50 border border-gray-800 rounded-xl p-5">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <input
          value={draft.name}
          onChange={(e) => setDraft({ ...draft, name: e.target.value })}
          placeholder="Rule name"
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200"
        />
        <input
          value={draft.description}
          onChange={(e) => setDraft({ ...draft, description: e.target.value })}
          placeholder="Description"
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200"
        />
      </div>

      <div className="flex flex-wrap gap-3 items-center">
        <select
          value={draft.severity}
          onChange={(e) => setDraft({ ...draft, severity: e.target.value as RuleSeverity })}
          className={`border rounded-lg px-3 py-2 text-sm ${severityClass[draft.severity]}`}
        >
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>

        <div className="flex items-center gap-2 text-sm text-gray-300">
          <span>Logic</span>
          <button
            onClick={() => setDraft({ ...draft, logic: draft.logic === 'AND' ? 'OR' : 'AND' })}
            className="px-3 py-1 rounded border border-gray-700 bg-gray-800"
          >
            {draft.logic}
          </button>
        </div>

        <label className="text-sm text-gray-300 flex items-center gap-2">
          <input
            type="checkbox"
            checked={draft.enabled}
            onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
            className="accent-cyan-500"
          />
          Enabled
        </label>
      </div>

      <div className="space-y-2">
        {draft.conditions.map((condition, idx) => (
          <div key={idx} className="grid grid-cols-12 gap-2 items-center">
            <select
              value={condition.field}
              onChange={(e) => updateCondition(idx, { field: e.target.value })}
              className="col-span-3 bg-gray-800 border border-gray-700 rounded px-2 py-2 text-xs text-gray-200"
            >
              {FIELDS.map((field) => <option key={field} value={field}>{field}</option>)}
            </select>
            <select
              value={condition.operator}
              onChange={(e) => updateCondition(idx, { operator: e.target.value })}
              className="col-span-2 bg-gray-800 border border-gray-700 rounded px-2 py-2 text-xs text-gray-200"
            >
              {OPERATORS.map((operator) => <option key={operator} value={operator}>{operator}</option>)}
            </select>
            <input
              value={condition.value}
              onChange={(e) => updateCondition(idx, { value: e.target.value })}
              placeholder="value"
              className="col-span-6 bg-gray-800 border border-gray-700 rounded px-2 py-2 text-xs text-gray-200"
            />
            <button
              onClick={() => removeCondition(idx)}
              className="col-span-1 text-xs px-2 py-2 rounded bg-red-900/40 text-red-300"
            >
              ×
            </button>
          </div>
        ))}
        <button onClick={addCondition} className="text-xs px-3 py-1.5 rounded bg-gray-800 border border-gray-700 text-gray-300">+ Add condition</button>
      </div>

      <div className="flex flex-wrap gap-3">
        {ACTIONS.map((action) => (
          <label key={action} className="text-sm text-gray-300 flex items-center gap-2">
            <input
              type="checkbox"
              checked={draft.actions.includes(action)}
              onChange={() => toggleAction(action)}
              className="accent-cyan-500"
            />
            {action}
          </label>
        ))}
      </div>

      <div className="flex gap-2">
        <button
          onClick={() => onSave(draft)}
          disabled={!canSave}
          className="px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-700 text-sm text-white"
        >
          Save Rule
        </button>
        {onTest && (
          <button
            onClick={runTest}
            disabled={testing}
            className="px-4 py-2 rounded bg-gray-800 border border-gray-700 text-sm text-gray-200"
          >
            {testing ? 'Testing…' : 'Test Rule'}
          </button>
        )}
      </div>

      {testResult && (
        <div className="mt-2 text-xs text-gray-300 bg-gray-800/60 border border-gray-700 rounded-lg p-3">
          <div className="font-medium text-gray-100">Matches: {testResult.match_count}</div>
          <pre className="mt-2 overflow-auto max-h-48 text-[11px]">{JSON.stringify(testResult.sample_matches.slice(0, 5), null, 2)}</pre>
        </div>
      )}
    </div>
  );
};

export default RuleBuilder;
