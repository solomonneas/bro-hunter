/**
 * ThreatTimeline — Area/line chart showing threat counts over time.
 * Stacked area chart with severity-colored bands.
 */
import React, { useMemo } from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import { format, parseISO } from 'date-fns';
import type { ChartTheme, ThreatTimelinePoint } from '../../types';
import { defaultChartTheme } from '../../data/mockData';

export interface ThreatTimelineProps {
  data: ThreatTimelinePoint[];
  theme?: ChartTheme;
  height?: number;
  showLegend?: boolean;
  stacked?: boolean;
}

export const ThreatTimeline: React.FC<ThreatTimelineProps> = ({
  data,
  theme = defaultChartTheme,
  height = 300,
  showLegend = true,
  stacked = true,
}) => {
  const formatted = useMemo(
    () =>
      data.map((d) => ({
        ...d,
        label: format(parseISO(d.timestamp), 'MMM d HH:mm'),
      })),
    [data],
  );

  const severityColors = {
    critical: theme.colors.danger,
    high: '#f97316', // orange-500
    medium: theme.colors.warning,
    low: theme.colors.info,
    info: theme.colors.textSecondary,
  };

  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart
        data={formatted}
        margin={{ top: 10, right: 10, left: 0, bottom: 0 }}
      >
        <CartesianGrid
          strokeDasharray="3 3"
          stroke={theme.colors.gridLine}
          vertical={false}
        />
        <XAxis
          dataKey="label"
          tick={{ fill: theme.colors.textSecondary, fontSize: theme.fonts.sizeSmall }}
          tickLine={false}
          axisLine={{ stroke: theme.colors.gridLine }}
          interval="preserveStartEnd"
        />
        <YAxis
          tick={{ fill: theme.colors.textSecondary, fontSize: theme.fonts.sizeSmall }}
          tickLine={false}
          axisLine={false}
          allowDecimals={false}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: theme.colors.surface,
            border: `1px solid ${theme.colors.gridLine}`,
            borderRadius: 6,
            color: theme.colors.text,
            fontSize: theme.fonts.sizeBase,
          }}
          labelStyle={{ color: theme.colors.primary }}
        />
        {showLegend && (
          <Legend
            wrapperStyle={{ fontSize: theme.fonts.sizeSmall, color: theme.colors.textSecondary }}
          />
        )}
        <Area
          type="monotone"
          dataKey="critical"
          stackId={stacked ? '1' : undefined}
          stroke={severityColors.critical}
          fill={severityColors.critical}
          fillOpacity={0.6}
        />
        <Area
          type="monotone"
          dataKey="high"
          stackId={stacked ? '1' : undefined}
          stroke={severityColors.high}
          fill={severityColors.high}
          fillOpacity={0.5}
        />
        <Area
          type="monotone"
          dataKey="medium"
          stackId={stacked ? '1' : undefined}
          stroke={severityColors.medium}
          fill={severityColors.medium}
          fillOpacity={0.4}
        />
        <Area
          type="monotone"
          dataKey="low"
          stackId={stacked ? '1' : undefined}
          stroke={severityColors.low}
          fill={severityColors.low}
          fillOpacity={0.3}
        />
        <Area
          type="monotone"
          dataKey="info"
          stackId={stacked ? '1' : undefined}
          stroke={severityColors.info}
          fill={severityColors.info}
          fillOpacity={0.2}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
};

export default ThreatTimeline;
