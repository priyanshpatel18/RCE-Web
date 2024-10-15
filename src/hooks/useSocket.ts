import { HEARTBEAT } from "@/packages/messages";
import { useCallback, useEffect, useRef, useState } from "react";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL || "";
const HEARTBEAT_INTERVAL = 5000;
const RECONNECT_INTERVAL = 5000;
const MAX_RECONNECT_ATTEMPTS = 10;

interface useSocketProps {
  token: string | null;
}

export type ConnectionType = "2g" | "3g" | "4g" | "offline";

export function useSocket({ token }: useSocketProps) {
  const socketRef = useRef<WebSocket | null>(null);
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [reconnectAttempts, setReconnectAttempts] = useState<number>(0);
  const heartbeatIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const [connectionType, setConnectionType] = useState<ConnectionType | null>(
    null
  );

  function getConnectionInfo(): ConnectionType | null {
    if ("connection" in navigator) {
      const connection =
        navigator.connection ||
        (navigator as any).mozConnection ||
        (navigator as any).webkitConnection;

      if (connection && typeof connection === "object") {
        return connection.effectiveType || null;
      }
    }
    return isConnected ? "4g" : "offline";
  }

  const connect = useCallback(() => {
    if (!navigator.onLine) {
      window.addEventListener("online", handleOnline);
      return;
    }
    if (!token) {
      return;
    }

    if (token && reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
      // Connect
      const ws = new WebSocket(`${WS_URL}?token=${token}`);
      socketRef.current = ws;

      // Handle Connection Logic
      ws.onopen = () => {
        setIsConnected(true);
        setConnectionType(getConnectionInfo());
        setReconnectAttempts(0);

        // Start sending heartbeats
        heartbeatIntervalRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN && navigator.onLine) {
            setConnectionType(getConnectionInfo());
            ws.send(JSON.stringify({ type: HEARTBEAT }));
          } else if (!navigator.onLine) {
            setConnectionType("offline");
            ws.close();
          }
        }, HEARTBEAT_INTERVAL);
      };

      // Handle Received HEARTBEAT
      ws.onmessage = (event) => {
        const message = JSON.parse(event.data);
        if (message.type === HEARTBEAT) {
          // Received HEARTBEAT
        }
      };

      // Error Close Logic
      ws.onclose = () => {
        setIsConnected(false);
        if (heartbeatIntervalRef.current) {
          clearInterval(heartbeatIntervalRef.current);
        }
        attemptReconnect();
      };

      // Error Handling
      ws.onerror = (error) => {
        setConnectionType("offline");
        console.error("WebSocket error:", error);
        ws.close();
      };
    } else {
      console.error("Max Reconnect Attempts Reached");
    }
  }, [token, reconnectAttempts]);

  const attemptReconnect = useCallback(() => {
    // Clear Timeout if already exists
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }

    // Try Reconnection if user disconnects
    if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS && navigator.onLine) {
      setReconnectAttempts((prev) => prev + 1);
      reconnectTimeoutRef.current = setTimeout(() => {
        connect();
      }, RECONNECT_INTERVAL);
    } else if (!navigator.onLine) {
      // Wait For User To Go ONLINE
      setConnectionType("offline");
      window.addEventListener("online", handleOnline);
    } else {
      console.error("Max reconnect attempts reached");
    }
  }, [reconnectAttempts, connect]);

  const handleOnline = useCallback(() => {
    window.removeEventListener("online", handleOnline);
    setReconnectAttempts(0);
    connect();
  }, [connect]);

  useEffect(() => {
    connect();

    window.addEventListener("online", handleOnline);
    window.addEventListener("offline", () => {
      setConnectionType("offline");
      setIsConnected(false);
      if (socketRef.current) {
        socketRef.current.close();
      }
      if (heartbeatIntervalRef.current) {
        clearInterval(heartbeatIntervalRef.current);
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
    });

    return () => {
      if (socketRef.current) {
        socketRef.current.close();
      }
      if (heartbeatIntervalRef.current) {
        clearInterval(heartbeatIntervalRef.current);
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
    };
  }, [connect, handleOnline]);

  return {
    socket: socketRef.current,
    isConnected,
    connectionType,
    connect,
    attemptReconnect,
    handleOnline,
  };
}
