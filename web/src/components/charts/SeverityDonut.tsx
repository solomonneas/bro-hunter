/**
 * SeverityDonut — Pie/donut chart of threat severity distribution.
 */
import React, { useMemo } from 'react';
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import type { ChartTheme, ThreatSeverityDistribution } from '../../types';
import { defaultChartTheme } from '../../data/mockData';

export interface SeverityDonutProps {
  data: ThreatSeverityDistribution[];
  theme?: ChartTheme;
  height?: number;
  showLegend?: boolean;
  innerRadius?: number;
  outerRadius?: number;
}

const SEVERITY_COLOR_MAP: Record<string, (t: ChartTheme) => string> = {
  critical: (t) => t.colors.danger,
  high: () => '#f97316',
  medium: (t) => t.colors.warning,
  low: (t) => t.colors.info,
  info: (t) => t.colors.textSecondary,
};

export const SeverityDonut: React.FC<SeverityDonutProps> = ({
  data,
  theme = defaultChartTheme,
  height = 300,
  showLegend = true,
  innerRadius = 60,
  outerRadius = 100,
}) => {
  const chartData = useMemo(
    () =>
      data.map((d) => ({
        name: d.severity.charAt(0).toUpperCase() + d.severity.slice(1),
        value: d.count,
        percentage: d.percentage,
        severity: d.severity,
      })),
    [data],
  );

  const getColor = (severity: string): string => {
    const fn = SEVERITY_COLOR_MAP[severity];
    return fn ? fn(theme) : theme.colors.textSecondary;
  };

  return (
    <ResponsiveContainer width="100%" height={height}>
      <PieChart>
        <Pie
          data={chartData}
          cx="50%"
          cy="50%"
          innerRadius={innerRadius}
          outerRadius={outerRadius}
          paddingAngle={2}
          dataKey="value"
          nameKey="name"
          label={({ name, percentage }) => `${name} ${percentage.toFixed(1)}%`}
          labelLine={{ stroke: theme.colors.textSecondary }}
        >
          {chartData.map((entry, index) => (
            <Cell
              key={`cell-${index}`}
              fill={getColor(entry.severity)}
              stroke={theme.colors.background}
              strokeWidth={2}
            />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{
            backgroundColor: theme.colors.surface,
            border: `1px solid ${theme.colors.gridLine}`,
            borderRadius: 6,
            color: theme.colors.text,
            fontSize: theme.fonts.sizeBase,
          }}
          formatter={(value: number, name: string) => [`${value} alerts`, name]}
        />
        {showLegend && (
          <Legend
            wrapperStyle={{ fontSize: theme.fonts.sizeSmall, color: theme.colors.textSecondary }}
          />
        )}
      </PieChart>
    </ResponsiveContainer>
  );
};

export default SeverityDonut;
