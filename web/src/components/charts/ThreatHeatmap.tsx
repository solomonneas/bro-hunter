/**
 * ThreatHeatmap — Grid-style heatmap of threat activity.
 * Rows = hours of day, columns = days. Cell color = intensity.
 */
import React, { useMemo } from 'react';
import type { ChartTheme, ThreatTimelinePoint } from '../../types';
import { defaultChartTheme } from '../../data/mockData';
import { parseISO, getHours, format } from 'date-fns';

export interface ThreatHeatmapProps {
  data: ThreatTimelinePoint[];
  theme?: ChartTheme;
  cellSize?: number;
}

interface HeatmapCell {
  day: string;
  hour: number;
  value: number;
}

function interpolateColor(t: number, low: string, high: string): string {
  // t in [0, 1]
  const parse = (hex: string) => {
    const h = hex.replace('#', '');
    return [
      parseInt(h.slice(0, 2), 16),
      parseInt(h.slice(2, 4), 16),
      parseInt(h.slice(4, 6), 16),
    ];
  };
  const [r1, g1, b1] = parse(low);
  const [r2, g2, b2] = parse(high);
  const r = Math.round(r1 + (r2 - r1) * t);
  const g = Math.round(g1 + (g2 - g1) * t);
  const b = Math.round(b1 + (b2 - b1) * t);
  return `rgb(${r}, ${g}, ${b})`;
}

export const ThreatHeatmap: React.FC<ThreatHeatmapProps> = ({
  data,
  theme = defaultChartTheme,
  cellSize = 28,
}) => {
  const { cells, days, maxValue } = useMemo(() => {
    const cellMap = new Map<string, HeatmapCell>();
    const daySet = new Set<string>();

    data.forEach((point) => {
      const dt = parseISO(point.timestamp);
      const day = format(dt, 'MMM d');
      const hour = getHours(dt);
      daySet.add(day);
      const key = `${day}-${hour}`;
      const existing = cellMap.get(key);
      if (existing) {
        existing.value += point.total;
      } else {
        cellMap.set(key, { day, hour, value: point.total });
      }
    });

    const allCells = Array.from(cellMap.values());
    const max = Math.max(...allCells.map((c) => c.value), 1);
    return { cells: allCells, days: Array.from(daySet), maxValue: max };
  }, [data]);

  const hours = Array.from({ length: 24 }, (_, i) => i);
  const width = days.length * cellSize + 50;
  const height = 24 * cellSize + 30;

  return (
    <div style={{ overflowX: 'auto' }}>
      <svg width={width} height={height} style={{ fontFamily: theme.fonts.monoFamily }}>
        {/* Hour labels */}
        {hours.map((h) => (
          <text
            key={`h-${h}`}
            x={40}
            y={h * cellSize + cellSize / 2 + 4}
            textAnchor="end"
            fill={theme.colors.textSecondary}
            fontSize={theme.fonts.sizeSmall}
          >
            {String(h).padStart(2, '0')}
          </text>
        ))}

        {/* Day labels */}
        {days.map((d, di) => (
          <text
            key={`d-${d}`}
            x={50 + di * cellSize + cellSize / 2}
            y={24 * cellSize + 16}
            textAnchor="middle"
            fill={theme.colors.textSecondary}
            fontSize={theme.fonts.sizeSmall - 1}
          >
            {d}
          </text>
        ))}

        {/* Cells */}
        {cells.map((cell) => {
          const di = days.indexOf(cell.day);
          if (di === -1) return null;
          const intensity = cell.value / maxValue;
          return (
            <g key={`${cell.day}-${cell.hour}`}>
              <rect
                x={50 + di * cellSize}
                y={cell.hour * cellSize}
                width={cellSize - 2}
                height={cellSize - 2}
                rx={3}
                fill={interpolateColor(intensity, theme.colors.surface, theme.colors.danger)}
                opacity={0.3 + intensity * 0.7}
              >
                <title>
                  {cell.day} {String(cell.hour).padStart(2, '0')}:00 — {cell.value} threats
                </title>
              </rect>
            </g>
          );
        })}
      </svg>
    </div>
  );
};

export default ThreatHeatmap;
