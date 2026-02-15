/**
 * Notification store: lightweight pub/sub for toast notifications.
 * No external dependencies (avoids zustand).
 */

export type NotificationType = 'success' | 'error' | 'warning' | 'info';

export interface Notification {
  id: string;
  type: NotificationType;
  title: string;
  message?: string;
  createdAt: number;
}

type Listener = () => void;

const MAX_NOTIFICATIONS = 5;

let notifications: Notification[] = [];
const listeners: Set<Listener> = new Set();

function emit() {
  listeners.forEach((fn) => fn());
}

export const useNotificationStore = {
  getNotifications: () => notifications,

  subscribe: (fn: Listener) => {
    listeners.add(fn);
    return () => { listeners.delete(fn); };
  },

  add: (type: NotificationType, title: string, message?: string) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    const notification: Notification = { id, type, title, message, createdAt: Date.now() };
    notifications = [notification, ...notifications].slice(0, MAX_NOTIFICATIONS);
    emit();

    // Auto-dismiss after 5 seconds
    setTimeout(() => {
      useNotificationStore.dismiss(id);
    }, 5000);
  },

  dismiss: (id: string) => {
    notifications = notifications.filter((n) => n.id !== id);
    emit();
  },

  clear: () => {
    notifications = [];
    emit();
  },
};

/**
 * React hook to subscribe to notification changes.
 */
import { useState, useEffect } from 'react';

export function useNotifications() {
  const [, setTick] = useState(0);

  useEffect(() => {
    return useNotificationStore.subscribe(() => setTick((t) => t + 1));
  }, []);

  return {
    notifications: useNotificationStore.getNotifications(),
    dismiss: useNotificationStore.dismiss,
    add: useNotificationStore.add,
    clear: useNotificationStore.clear,
  };
}
