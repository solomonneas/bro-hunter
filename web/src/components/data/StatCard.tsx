/**
 * StatCard — Metric display card with icon, value, trend indicator.
 */
import React from 'react';
import { TrendingUp, TrendingDown, Minus } from 'lucide-react';

export interface StatCardProps {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  trend?: number; // percentage change; positive = up, negative = down
  trendLabel?: string;
  color?: string; // tailwind text-color class
  className?: string;
}

export const StatCard: React.FC<StatCardProps> = ({
  icon,
  label,
  value,
  trend,
  trendLabel,
  color = 'text-accent-cyan',
  className = '',
}) => {
  const trendIcon =
    trend === undefined || trend === 0 ? (
      <Minus size={12} className="text-gray-500" />
    ) : trend > 0 ? (
      <TrendingUp size={12} className="text-red-400" />
    ) : (
      <TrendingDown size={12} className="text-green-400" />
    );

  const trendColor =
    trend === undefined || trend === 0
      ? 'text-gray-500'
      : trend > 0
        ? 'text-red-400'
        : 'text-green-400';

  return (
    <div
      className={`rounded-lg border border-gray-700/50 bg-surface p-4 flex flex-col gap-2 ${className}`}
    >
      <div className="flex items-center justify-between">
        <span className={`${color}`}>{icon}</span>
        {trend !== undefined && (
          <span className={`flex items-center gap-1 text-[10px] ${trendColor}`}>
            {trendIcon}
            {Math.abs(trend).toFixed(1)}%
            {trendLabel && <span className="text-gray-500 ml-0.5">{trendLabel}</span>}
          </span>
        )}
      </div>
      <p className="text-2xl font-bold text-gray-100 font-mono">{value}</p>
      <p className="text-xs text-gray-500">{label}</p>
    </div>
  );
};

export default StatCard;
