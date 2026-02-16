import React from 'react';

interface LoadingSkeletonProps {
  className?: string;
  rows?: number;
}

const LoadingSkeleton: React.FC<LoadingSkeletonProps> = ({ className = '', rows = 3 }) => (
  <div className={`space-y-2 animate-pulse ${className}`}>
    {Array.from({ length: rows }).map((_, i) => (
      <div key={i} className="h-4 rounded bg-gray-700/40" />
    ))}
  </div>
);

export default LoadingSkeleton;
