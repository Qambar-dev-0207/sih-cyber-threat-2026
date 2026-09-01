import { useEffect, useRef, useState, useCallback } from 'react';

export type ConnectionStatus = 'CONNECTING' | 'CONNECTED' | 'DISCONNECTED' | 'ERROR' | 'FALLBACK_POLLING';

interface UseWebSocketOptions<T> {
  url: string;
  enabled?: boolean;
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
  onMessage?: (data: T) => void;
  onOpen?: () => void;
  onClose?: () => void;
  onError?: (error: Event) => void;
  onFallback?: () => void;
}

export function useWebSocket<T = any>({
  url,
  enabled = true,
  reconnectInterval = 2500,
  maxReconnectAttempts = 5,
  onMessage,
  onOpen,
  onClose,
  onError,
  onFallback,
}: UseWebSocketOptions<T>) {
  const [status, setStatus] = useState<ConnectionStatus>('CONNECTING');
  const [lastMessage, setLastMessage] = useState<T | null>(null);
  const [reconnectCount, setReconnectCount] = useState(0);

  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const isUnmountedRef = useRef(false);

  const connect = useCallback(() => {
    if (!enabled || typeof window === 'undefined') return;

    try {
      // Determine protocol and host
      let wsUrl = url;
      if (!url.startsWith('ws://') && !url.startsWith('wss://')) {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host;
        wsUrl = `${protocol}//${host}${url.startsWith('/') ? '' : '/'}${url}`;
      }

      setStatus('CONNECTING');
      const ws = new WebSocket(wsUrl);
      socketRef.current = ws;

      ws.onopen = () => {
        if (isUnmountedRef.current) return;
        setStatus('CONNECTED');
        setReconnectCount(0);
        onOpen?.();
      };

      ws.onmessage = (event) => {
        if (isUnmountedRef.current) return;
        try {
          const parsed = JSON.parse(event.data) as T;
          setLastMessage(parsed);
          onMessage?.(parsed);
        } catch {
          // Non-JSON message
          setLastMessage(event.data as unknown as T);
          onMessage?.(event.data as unknown as T);
        }
      };

      ws.onerror = (error) => {
        if (isUnmountedRef.current) return;
        onError?.(error);
      };

      ws.onclose = () => {
        if (isUnmountedRef.current) return;
        socketRef.current = null;
        onClose?.();

        setReconnectCount((prev) => {
          const next = prev + 1;
          if (next > maxReconnectAttempts) {
            setStatus('FALLBACK_POLLING');
            onFallback?.();
          } else {
            setStatus('DISCONNECTED');
            // Schedule reconnect
            if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
            reconnectTimeoutRef.current = window.setTimeout(() => {
              connect();
            }, reconnectInterval * Math.min(next, 3));
          }
          return next;
        });
      };
    } catch {
      setStatus('FALLBACK_POLLING');
      onFallback?.();
    }
  }, [enabled, url, reconnectInterval, maxReconnectAttempts, onMessage, onOpen, onClose, onError, onFallback]);

  const sendMessage = useCallback((message: any) => {
    if (socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
      const data = typeof message === 'string' ? message : JSON.stringify(message);
      socketRef.current.send(data);
      return true;
    }
    return false;
  }, []);

  const manualReconnect = useCallback(() => {
    if (socketRef.current) {
      socketRef.current.close();
      socketRef.current = null;
    }
    setReconnectCount(0);
    connect();
  }, [connect]);

  useEffect(() => {
    isUnmountedRef.current = false;
    connect();

    return () => {
      isUnmountedRef.current = true;
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (socketRef.current) {
        socketRef.current.close();
        socketRef.current = null;
      }
    };
  }, [connect]);

  return {
    status,
    lastMessage,
    sendMessage,
    reconnect: manualReconnect,
    reconnectCount,
  };
}
