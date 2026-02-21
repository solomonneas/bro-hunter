/**
 * Live events store: manages auto-refresh state for dashboard.
 * Handles polling, backoff on failures, and event deduplication.
 */

import { useState, useEffect, useCallback, useRef } from 'react';

const API_BASE = import.meta.env.VITE_API_BASE || '';
const POLL_INTERVAL_MS = 10000; // 10 seconds
const MAX_CONSECUTIVE_FAILURES = 3;

/** Event item from the live events API */
export interface LiveEvent {
  id: string;
  timestamp: string;
  event_type: 'conn' | 'dns' | 'alert' | string;
  source: 'zeek' | 'suricata' | string;
  data: Record<string, unknown>;
}

/** State for live refresh */
export interface LiveRefreshState {
  isEnabled: boolean;
  isLive: boolean;
  lastUpdateAt: Date | null;
  lastError: string | null;
  consecutiveFailures: number;
  events: LiveEvent[];
  eventIds: Set<string>; // For deduplication
}

/** Actions for live refresh */
export interface LiveRefreshActions {
  toggle: () => void;
  enable: () => void;
  disable: () => void;
  resetBackoff: () => void;
  getLatestTimestamp: () => string | null;
}

/** Hook return type */
export interface UseLiveRefreshReturn extends LiveRefreshState, LiveRefreshActions {}

/**
 * React hook for live dashboard auto-refresh.
 * Polls /api/v1/live/events every 10s and merges new events.
 * Implements backoff after 3 consecutive failures.
 */
export function useLiveRefresh(initialEnabled: boolean = true): UseLiveRefreshReturn {
  const [isEnabled, setIsEnabled] = useState<boolean>(initialEnabled);
  const [isLive, setIsLive] = useState<boolean>(false);
  const [lastUpdateAt, setLastUpdateAt] = useState<Date | null>(null);
  const [lastError, setLastError] = useState<string | null>(null);
  const [consecutiveFailures, setConsecutiveFailures] = useState<number>(0);
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const eventIdsRef = useRef<Set<string>>(new Set());

  const getLatestTimestamp = useCallback((): string | null => {
    if (events.length === 0) return null;
    // Find the most recent timestamp
    const timestamps = events.map(e => new Date(e.timestamp).getTime());
    const maxTime = Math.max(...timestamps);
    return new Date(maxTime).toISOString();
  }, [events]);

  const mergeEvents = useCallback((newEvents: LiveEvent[]): void => {
    setEvents(prev => {
      const merged = [...prev];
      for (const event of newEvents) {
        if (!eventIdsRef.current.has(event.id)) {
          eventIdsRef.current.add(event.id);
          merged.push(event);
        }
      }
      // Keep only last 500 events to prevent memory bloat
      if (merged.length > 500) {
        const toRemove = merged.slice(0, merged.length - 500);
        for (const e of toRemove) {
          eventIdsRef.current.delete(e.id);
        }
      }
      return merged.slice(-500);
    });
  }, []);

  const fetchEvents = useCallback(async (): Promise<void> => {
    if (!isEnabled) return;
    
    // Don't fetch if we've hit max failures
    if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
      setIsLive(false);
      return;
    }

    try {
      const since = getLatestTimestamp();
      const url = new URL(`${API_BASE}/api/v1/live/events`, window.location.origin);
      url.searchParams.set('limit', '200');
      if (since) {
        url.searchParams.set('since', since);
      }

      const response = await fetch(url.toString());
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      const newEvents: LiveEvent[] = data.events || [];
      
      mergeEvents(newEvents);
      setLastUpdateAt(new Date());
      setConsecutiveFailures(0);
      setLastError(null);
      setIsLive(true);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      setLastError(errorMsg);
      setConsecutiveFailures(prev => prev + 1);
      if (consecutiveFailures + 1 >= MAX_CONSECUTIVE_FAILURES) {
        setIsLive(false);
        setIsEnabled(false); // Auto-disable on persistent failures
      }
    }
  }, [isEnabled, consecutiveFailures, getLatestTimestamp, mergeEvents]);

  // Polling effect
  useEffect(() => {
    if (!isEnabled) {
      setIsLive(false);
      return;
    }

    // Initial fetch
    fetchEvents();

    const intervalId = setInterval(fetchEvents, POLL_INTERVAL_MS);
    return () => clearInterval(intervalId);
  }, [isEnabled, fetchEvents]);

  const toggle = useCallback(() => {
    setIsEnabled(prev => !prev);
    if (!isEnabled) {
      // Resetting when enabling
      setConsecutiveFailures(0);
      setLastError(null);
    }
  }, [isEnabled]);

  const enable = useCallback(() => {
    setIsEnabled(true);
    setConsecutiveFailures(0);
    setLastError(null);
  }, []);

  const disable = useCallback(() => {
    setIsEnabled(false);
    setIsLive(false);
  }, []);

  const resetBackoff = useCallback(() => {
    setConsecutiveFailures(0);
    setLastError(null);
    setIsEnabled(true);
  }, []);

  return {
    isEnabled,
    isLive,
    lastUpdateAt,
    lastError,
    consecutiveFailures,
    events,
    eventIds: eventIdsRef.current,
    toggle,
    enable,
    disable,
    resetBackoff,
    getLatestTimestamp,
  };
}

/** Format relative time for display */
export function formatLastUpdate(date: Date | null): string {
  if (!date) return 'Never';
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSec = Math.floor(diffMs / 1000);
  
  if (diffSec < 5) return 'Just now';
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  return `${diffHr}h ago`;
}
