/**
 * FilterBar — Search + filter controls for data views.
 * Provides search input, severity multi-select, and score range.
 */
import React, { useState, useCallback } from 'react';
import { Search, Filter, X } from 'lucide-react';
import type { FilterState, ThreatLevel } from '../../types';

export interface FilterBarProps {
  filters: FilterState;
  onChange: (filters: FilterState) => void;
  showSeverity?: boolean;
  showScoreRange?: boolean;
  placeholder?: string;
  className?: string;
}

const SEVERITIES: { value: ThreatLevel; label: string; color: string }[] = [
  { value: 'critical' as ThreatLevel, label: 'Critical', color: 'bg-red-500' },
  { value: 'high' as ThreatLevel, label: 'High', color: 'bg-orange-500' },
  { value: 'medium' as ThreatLevel, label: 'Medium', color: 'bg-amber-500' },
  { value: 'low' as ThreatLevel, label: 'Low', color: 'bg-blue-500' },
  { value: 'info' as ThreatLevel, label: 'Info', color: 'bg-gray-500' },
];

export const defaultFilterState: FilterState = {
  search: '',
  severity: [],
  dateRange: { start: null, end: null },
  sourceIPs: [],
  destIPs: [],
  mitreTechniques: [],
  minScore: 0,
  maxScore: 100,
};

export const FilterBar: React.FC<FilterBarProps> = ({
  filters,
  onChange,
  showSeverity = true,
  showScoreRange = true,
  placeholder = 'Search by IP, domain, technique…',
  className = '',
}) => {
  const [expanded, setExpanded] = useState(false);

  const update = useCallback(
    (patch: Partial<FilterState>) => {
      onChange({ ...filters, ...patch });
    },
    [filters, onChange],
  );

  const toggleSeverity = useCallback(
    (sev: ThreatLevel) => {
      const current = filters.severity;
      const next = current.includes(sev)
        ? current.filter((s) => s !== sev)
        : [...current, sev];
      update({ severity: next });
    },
    [filters.severity, update],
  );

  const hasActiveFilters =
    filters.severity.length > 0 ||
    filters.minScore > 0 ||
    filters.maxScore < 100;

  return (
    <div className={`space-y-2 ${className}`}>
      {/* Main search row */}
      <div className="flex items-center gap-2">
        <div className="relative flex-1 max-w-md">
          <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-500" aria-hidden="true" />
          <input
            type="text"
            value={filters.search}
            onChange={(e) => update({ search: e.target.value })}
            placeholder={placeholder}
            aria-label="Search threats"
            className="w-full pl-8 pr-8 py-1.5 text-sm bg-background border border-gray-700 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-accent-cyan"
          />
          {filters.search && (
            <button
              onClick={() => update({ search: '' })}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
              aria-label="Clear search"
            >
              <X size={14} aria-hidden="true" />
            </button>
          )}
        </div>

        <button
          onClick={() => setExpanded(!expanded)}
          aria-expanded={expanded}
          aria-label={`${expanded ? 'Collapse' : 'Expand'} filters`}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-sm rounded border transition-colors ${
            expanded || hasActiveFilters
              ? 'border-accent-cyan/50 text-accent-cyan bg-accent-cyan/5'
              : 'border-gray-700 text-gray-400 hover:text-gray-300'
          }`}
        >
          <Filter size={14} aria-hidden="true" />
          Filters
          {hasActiveFilters && (
            <span className="w-4 h-4 rounded-full bg-accent-cyan text-background text-[10px] flex items-center justify-center font-bold" aria-label={`${filters.severity.length + (filters.minScore > 0 || filters.maxScore < 100 ? 1 : 0)} active filters`}>
              {filters.severity.length + (filters.minScore > 0 || filters.maxScore < 100 ? 1 : 0)}
            </span>
          )}
        </button>

        {hasActiveFilters && (
          <button
            onClick={() => onChange(defaultFilterState)}
            className="text-xs text-gray-500 hover:text-gray-300 underline"
            aria-label="Clear all filters"
          >
            Clear all
          </button>
        )}
      </div>

      {/* Expanded filters */}
      {expanded && (
        <div className="p-3 rounded-lg border border-gray-700/50 bg-surface/50 space-y-3" role="region" aria-label="Filter options">
          {/* Severity toggles */}
          {showSeverity && (
            <fieldset>
              <legend className="text-xs text-gray-500 mb-1.5">Severity</legend>
              <div className="flex flex-wrap gap-1.5" role="group" aria-label="Severity filter toggles">
                {SEVERITIES.map((sev) => {
                  const active = filters.severity.includes(sev.value);
                  return (
                    <button
                      key={sev.value}
                      onClick={() => toggleSeverity(sev.value)}
                      aria-pressed={active}
                      aria-label={`Filter by ${sev.label} severity`}
                      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs border transition-colors ${
                        active
                          ? 'border-gray-500 bg-gray-700/50 text-gray-200'
                          : 'border-gray-700 text-gray-500 hover:text-gray-400'
                      }`}
                    >
                      <span className={`w-2 h-2 rounded-full ${sev.color} ${active ? 'opacity-100' : 'opacity-40'}`} aria-hidden="true" />
                      {sev.label}
                    </button>
                  );
                })}
              </div>
            </fieldset>
          )}

          {/* Score range */}
          {showScoreRange && (
            <div>
              <p className="text-xs text-gray-500 mb-1.5" id="score-range-label">
                Score Range: {filters.minScore} – {filters.maxScore}
              </p>
              <div className="flex items-center gap-3">
                <input
                  type="range"
                  min={0}
                  max={100}
                  value={filters.minScore}
                  onChange={(e) => update({ minScore: Number(e.target.value) })}
                  className="flex-1 accent-accent-cyan"
                  aria-label={`Minimum score: ${filters.minScore}`}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={filters.minScore}
                />
                <input
                  type="range"
                  min={0}
                  max={100}
                  value={filters.maxScore}
                  onChange={(e) => update({ maxScore: Number(e.target.value) })}
                  className="flex-1 accent-accent-cyan"
                  aria-label={`Maximum score: ${filters.maxScore}`}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={filters.maxScore}
                />
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default FilterBar;
