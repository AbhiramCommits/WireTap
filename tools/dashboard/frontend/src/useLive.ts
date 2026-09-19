import { useEffect, useRef, useState } from "react";
import type { WsPayload } from "./types";

export function useLive(url: string): { payload: WsPayload | null; connected: boolean } {
  const [payload, setPayload] = useState<WsPayload | null>(null);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    let closed = false;
    const connect = () => {
      const ws = new WebSocket(url);
      wsRef.current = ws;
      ws.onopen = () => !closed && setConnected(true);
      ws.onclose = () => {
        if (!closed) setConnected(false);
        setTimeout(() => !closed && connect(), 1000);
      };
      ws.onmessage = (ev) => {
        try {
          const data = JSON.parse(ev.data) as WsPayload;
          if (!closed) setPayload(data);
        } catch {
          /* skip malformed frame */
        }
      };
    };
    connect();
    return () => {
      closed = true;
      wsRef.current?.close();
    };
  }, [url]);

  return { payload, connected };
}
