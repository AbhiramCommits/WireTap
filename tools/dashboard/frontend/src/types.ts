export interface LatencyStats {
  count: number;
  p50: number;
  p90: number;
  p99: number;
  p99_9: number;
  p99_99: number;
  max: number;
}

export interface GapEvent {
  start: number;
  end: number;
  missing: number;
  healed: boolean;
  heal_ns: number;
}

export interface GapStats {
  detected: number;
  healed: number;
  lost: number;
  recovered: number;
  recent: GapEvent[];
}

export interface BookSide {
  bids: [number, number][];
  asks: [number, number][];
}

export interface LiveSnapshot {
  ts_ns: number;
  ring_drops: number;
  archive_drops: number;
  gaps: GapStats;
  queue_delay?: LatencyStats;
  decode_time?: LatencyStats;
  wire_to_book?: LatencyStats;
  histogram: { sec: number; buckets: [number, number][] };
  stats: { sec: number; messages: number; packets: number };
  books: Record<string, BookSide>;
}

export interface HistogramPayload {
  buckets: [number, number][];
  count: number;
  p50: number;
  p99: number;
  p99_9: number;
}

export interface WsPayload {
  live: LiveSnapshot | null;
  histogram: HistogramPayload;
}
