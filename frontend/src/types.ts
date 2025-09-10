export type UploadSummary = {
  id: number; filename: string; created_at: string;
  status?: 'uploaded'|'processing'|'done'|'failed'; progress?: number
};
export type Event = {
  id: number; ts: string | null; src_ip: string | null; user: string | null;
  url: string | null; action: string | null; status: string | null; bytes: number | null; user_agent: string | null; raw: string | null
}
export type Anomaly = { id: number; reason: string; score: number }
export type Analysis = {
  upload: UploadSummary
  events: Event[]
  timeline: { minute: string, count: number }[]
  anomalies: Anomaly[]
}
