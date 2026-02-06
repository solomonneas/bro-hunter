/**
 * ScoreGauge — Gauge/meter for threat scores (0-100).
 * SVG-based semicircle gauge with animated fill.
 */
import React from 'react';
import type { ChartTheme } from '../../types';
import { defaultChartTheme } from '../../data/mockData';

export interface ScoreGaugeProps {
  score: number;
  label?: string;
  theme?: ChartTheme;
  size?: number;
  showValue?: boolean;
}

function scoreColor(score: number, theme: ChartTheme): string {
  if (score >= 85) return theme.colors.danger;
  if (score >= 65) return '#f97316'; // orange
  if (score >= 40) return theme.colors.warning;
  if (score >= 20) return theme.colors.info;
  return theme.colors.success;
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({
  score,
  label,
  theme = defaultChartTheme,
  size = 140,
  showValue = true,
}) => {
  const clampedScore = Math.max(0, Math.min(100, score));
  const radius = (size - 20) / 2;
  const cx = size / 2;
  const cy = size / 2 + 10;

  // Arc from 180° (left) to 0° (right) — semicircle
  const startAngle = Math.PI;
  const endAngle = Math.PI - (clampedScore / 100) * Math.PI;

  const bgArcEnd = 0;

  const describeArc = (start: number, end: number): string => {
    const x1 = cx + radius * Math.cos(start);
    const y1 = cy - radius * Math.sin(start);
    const x2 = cx + radius * Math.cos(end);
    const y2 = cy - radius * Math.sin(end);
    const largeArc = Math.abs(start - end) > Math.PI ? 1 : 0;
    return `M ${x1} ${y1} A ${radius} ${radius} 0 ${largeArc} 1 ${x2} ${y2}`;
  };

  const color = scoreColor(clampedScore, theme);

  return (
    <div style={{ display: 'inline-flex', flexDirection: 'column', alignItems: 'center' }}>
      <svg width={size} height={size * 0.65} viewBox={`0 0 ${size} ${size * 0.65}`}>
        {/* Background arc */}
        <path
          d={describeArc(startAngle, bgArcEnd)}
          fill="none"
          stroke={theme.colors.gridLine}
          strokeWidth={10}
          strokeLinecap="round"
        />
        {/* Score arc */}
        {clampedScore > 0 && (
          <path
            d={describeArc(startAngle, endAngle)}
            fill="none"
            stroke={color}
            strokeWidth={10}
            strokeLinecap="round"
          />
        )}
        {/* Score value */}
        {showValue && (
          <text
            x={cx}
            y={cy - 5}
            textAnchor="middle"
            fill={theme.colors.text}
            fontSize={theme.fonts.sizeLarge + 6}
            fontWeight={700}
            fontFamily={theme.fonts.monoFamily}
          >
            {Math.round(clampedScore)}
          </text>
        )}
      </svg>
      {label && (
        <span
          style={{
            color: theme.colors.textSecondary,
            fontSize: theme.fonts.sizeSmall,
            marginTop: 2,
          }}
        >
          {label}
        </span>
      )}
    </div>
  );
};

export default ScoreGauge;
