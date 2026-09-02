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

  // Store latest callbacks and options in refs so inline caller functions don't trigger reconnect cascades
  const callbacksRef = useRef({
    onMessage,
    onOpen,
    onClose,
    onError,
    onFallback,
  });
  callbacksRef.current = {
    onMessage,
    onOpen,
    onClose,
    onError,
    onFallback,
  };

  const configRef = useRef({
    reconnectInterval,
    maxReconnectAttempts,
  });
  configRef.current = {
    reconnectInterval,
    maxReconnectAttempts,
  };

  const connect = useCallback(() => {
    if (!enabled || typeof window === 'undefined' || isUnmountedRef.current) return;

    // Clean up any stale socket before opening a new connection
    if (socketRef.current) {
      try {
        socketRef.current.onopen = null;
        socketRef.current.onmessage = null;
        socketRef.current.onerror = null;
        socketRef.current.onclose = null;
        if (socketRef.current.readyState === WebSocket.OPEN || socketRef.current.readyState === WebSocket.CONNECTING) {
          socketRef.current.close(1000, 'Reconnecting');
        }
      } catch {
        // Ignore close error
      }
      socketRef.current = null;
    }

    try {
      // Determine protocol and host
      let wsUrl = url;
      if (!url.startsWith('ws://') && !url.startsWith('wss://')) {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const isViteDev = window.location.port === '5173';
        const host = isViteDev
          ? `${window.location.hostname}:8000`
          : window.location.host;
        wsUrl = `${protocol}//${host}${url.startsWith('/') ? '' : '/'}${url}`;
      }

      setStatus('CONNECTING');
      const ws = new WebSocket(wsUrl);
      socketRef.current = ws;

      ws.onopen = () => {
        if (isUnmountedRef.current || socketRef.current !== ws) return;
        setStatus('CONNECTED');
        setReconnectCount(0);
        callbacksRef.current.onOpen?.();
      };

      ws.onmessage = (event) => {
        if (isUnmountedRef.current || socketRef.current !== ws) return;
        try {
          const parsed = JSON.parse(event.data) as T;
          setLastMessage(parsed);
          callbacksRef.current.onMessage?.(parsed);
        } catch {
          // Non-JSON message
          setLastMessage(event.data as unknown as T);
          callbacksRef.current.onMessage?.(event.data as unknown as T);
        }
      };

      ws.onerror = (error) => {
        if (isUnmountedRef.current || socketRef.current !== ws) return;
        callbacksRef.current.onError?.(error);
      };

      ws.onclose = (event) => {
        if (isUnmountedRef.current || socketRef.current !== ws) return;
        socketRef.current = null;
        callbacksRef.current.onClose?.();

        // If closed intentionally via 1000 on unmount, do not reconnect
        if (event.code === 1000 && event.reason === 'Unmounted') {
          return;
        }

        setReconnectCount((prev) => {
          const next = prev + 1;
          if (next > configRef.current.maxReconnectAttempts) {
            setStatus('FALLBACK_POLLING');
            callbacksRef.current.onFallback?.();
          } else {
            setStatus('DISCONNECTED');
            // Schedule reconnect
            if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
            reconnectTimeoutRef.current = window.setTimeout(() => {
              if (!isUnmountedRef.current) {
                connect();
              }
            }, configRef.current.reconnectInterval * Math.min(next, 3));
          }
          return next;
        });
      };
    } catch {
      setStatus('FALLBACK_POLLING');
      callbacksRef.current.onFallback?.();
    }
  }, [enabled, url]);

  const sendMessage = useCallback((message: any) => {
    if (socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
      const data = typeof message === 'string' ? message : JSON.stringify(message);
      socketRef.current.send(data);
      return true;
    }
    return false;
  }, []);

  const manualReconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    setReconnectCount(0);
    connect();
  }, [connect]);

  useEffect(() => {
    isUnmountedRef.current = false;
    connect();

    return () => {
      isUnmountedRef.current = true;
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = null;
      }
      if (socketRef.current) {
        try {
          socketRef.current.onopen = null;
          socketRef.current.onmessage = null;
          socketRef.current.onerror = null;
          socketRef.current.onclose = null;
          socketRef.current.close(1000, 'Unmounted');
        } catch {
          // Ignore
        }
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
