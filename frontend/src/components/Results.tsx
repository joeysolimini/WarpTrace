import React, { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { getAnalysis, getStatus } from '../api'
import type { UploadSummary } from '../types'
import TimelineChart from './TimelineChart'
import WarpProgress from './WarpProgress'

type EventRow = {
  id: number
  ts: string | null
  src_ip: string | null
  user: string | null
  url: string | null
  action: string | null
  status: number | null
  bytes: number | null
  user_agent: string | null
  raw: string | null
}

type AnomalyGroup = {
  kind: string
  count: number
  reasons?: string[]
  users?: string[]
  src_ips?: string[]
  samples?: EventRow[]
}

type Analysis = {
  upload: { id: number; filename: string; created_at: string }
  events: EventRow[]
  timeline: Array<{ minute: string; count: number }>
  anomaly_groups: AnomalyGroup[]
  summary?: string | null
  status: 'uploaded' | 'processing' | 'summarizing' | 'done' | 'failed'
  progress: number
}

type StatusState = 'uploaded' | 'processing' | 'summarizing' | 'done' | 'failed'

/** Portal that renders above everything else, positioned from an anchor rect */
function SamplesPortal({
  open,
  rect,
  children,
  onEnter,
  onLeave,
}: {
  open: boolean
  rect: DOMRect | null
  children: React.ReactNode
  onEnter: () => void
  onLeave: () => void
}) {
  if (!open || !rect || typeof window === 'undefined') return null

  const gutter = 12
  const maxWidth = Math.min(window.innerWidth - gutter * 2, rect.width)
  const left = Math.max(gutter, Math.min(rect.left, window.innerWidth - gutter - maxWidth))
  const top = Math.min(rect.bottom + 8, window.innerHeight - gutter - 200)

  const style: React.CSSProperties = {
    position: 'fixed',
    zIndex: 999999,
    left,
    top,
    width: maxWidth,
  }

  return createPortal(
    <div
      style={style}
      onMouseEnter={onEnter}
      onMouseLeave={onLeave}
      className="rounded-xl border border-white/10 bg-[#0b0a12] p-3 shadow-2xl"
    >
      {children}
    </div>,
    document.body
  )
}

/** One finding row with hoverable samples (uses hooks safely inside a component) */
function FindingRow({ g }: { g: AnomalyGroup }) {
  const rowRef = useRef<HTMLLIElement>(null)
  const [hoverOpen, setHoverOpen] = useState(false)
  const [rect, setRect] = useState<DOMRect | null>(null)
  const closeTimer = useRef<any>(null)

  useEffect(() => {
    function recalc() {
      if (!hoverOpen || !rowRef.current) return
      setRect(rowRef.current.getBoundingClientRect())
    }
    if (hoverOpen) {
      recalc()
      window.addEventListener('scroll', recalc, true)
      window.addEventListener('resize', recalc)
      return () => {
        window.removeEventListener('scroll', recalc, true)
        window.removeEventListener('resize', recalc)
      }
    }
  }, [hoverOpen])

  const onEnterRow = () => {
    if (closeTimer.current) clearTimeout(closeTimer.current)
    setHoverOpen(true)
    if (rowRef.current) setRect(rowRef.current.getBoundingClientRect())
  }
  const onLeaveRow = () => {
    closeTimer.current = setTimeout(() => setHoverOpen(false), 120)
  }
  const onEnterPortal = () => {
    if (closeTimer.current) clearTimeout(closeTimer.current)
    setHoverOpen(true)
  }
  const onLeavePortal = () => setHoverOpen(false)

  return (
    <li
      ref={rowRef}
      className="p-4 relative group z-0"
      onMouseEnter={onEnterRow}
      onMouseLeave={onLeaveRow}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1">
          <div className="font-medium">
            {g.kind} <span className="text-white/50">({g.count})</span>
          </div>
          {g.reasons && g.reasons.length > 0 && (
            <div className="text-xs text-white/60">
              Examples: {g.reasons.slice(0, 3).join('; ')}
            </div>
          )}
          {(g.users?.length || g.src_ips?.length) ? (
            <div className="text-xs text-white/50">
              {g.users?.length ? <>Users: {g.users.slice(0, 3).join(', ')} </> : null}
              {g.src_ips?.length ? <>IPs: {g.src_ips.slice(0, 3).join(', ')}</> : null}
            </div>
          ) : null}
        </div>
        <div className="shrink-0 text-xs px-2 py-1 rounded-lg border border-white/10 bg-fuchsia-500/20 text-fuchsia-100">
          {g.count} events
        </div>
      </div>

      {g.samples && g.samples.length > 0 && (
        <SamplesPortal open={hoverOpen} rect={rect} onEnter={onEnterPortal} onLeave={onLeavePortal}>
          <div className="text-xs text-white/70 mb-2">Sample events</div>
          <div className="overflow-auto max-h-72">
            <table className="w-full text-xs">
              <thead className="text-white/60">
                <tr>
                  <th className="text-left pr-3 py-1">Time</th>
                  <th className="text-left pr-3 py-1">User</th>
                  <th className="text-left pr-3 py-1">IP</th>
                  <th className="text-left pr-3 py-1">Status</th>
                  <th className="text-left pr-3 py-1">URL</th>
                  <th className="text-left pr-3 py-1">UA</th>
                </tr>
              </thead>
              <tbody className="text-white/80">
                {g.samples.map((ev) => (
                  <tr key={ev.id}>
                    <td className="pr-3 py-1 whitespace-nowrap">
                      {ev.ts ? new Date(ev.ts).toLocaleString() : '-'}
                    </td>
                    <td className="pr-3 py-1">{ev.user || '-'}</td>
                    <td className="pr-3 py-1">{ev.src_ip || '-'}</td>
                    <td className="pr-3 py-1">{ev.status ?? '-'}</td>
                    <td className="pr-3 py-1 truncate max-w-[360px]" title={ev.url || ''}>
                      {ev.url || '-'}
                    </td>
                    <td className="pr-3 py-1 truncate max-w-[280px]" title={ev.user_agent || ''}>
                      {ev.user_agent || '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </SamplesPortal>
      )}
    </li>
  )
}

export default function Results({ token, upload }: { token: string; upload: UploadSummary }) {
  const initialState = (upload.status as StatusState) || 'uploaded'
  const [data, setData] = useState<Analysis | null>(null)
  const [status, setStatus] = useState<{ state: StatusState; progress: number }>({
    state: initialState,
    progress: upload.progress ?? 0,
  })
  const [open, setOpen] = useState(initialState !== 'done')

  useEffect(() => {
    if (!open) return
    let cancelled = false
    let t: any
    async function poll() {
      try {
        const s = await getStatus(token, upload.id)
        if (cancelled) return
        const newState = (s.status ?? 'uploaded') as StatusState
        setStatus({ state: newState, progress: s.progress ?? 0 })
        if (newState === 'done') {
          const a = await getAnalysis(token, upload.id)
          if (cancelled) return
          setData(a as any)
          return
        }
      } catch { /* keep polling */ }
      t = setTimeout(poll, 1100)
    }
    poll()
    return () => { cancelled = true; clearTimeout(t) }
  }, [open, token, upload.id])

  return (
    <div className="mt-3 relative z-0 hover:z-[200] focus-within:z-[200]">
      <div className="flex items-center justify-between mb-2">
        <div>
          <div className="font-semibold">{upload.filename}</div>
          <div className="text-xs text-white/50">{new Date(upload.created_at).toLocaleString()}</div>
        </div>
        <button
          className="text-sm underline decoration-warp-pink/60 hover:decoration-warp-pink"
          onClick={() => setOpen((s) => !s)}
        >
          {open ? 'Hide' : status.state !== 'done' ? 'View status' : 'View analysis'}
        </button>
      </div>

      {open && status.state !== 'done' && (
        <div className="mt-3">
          <WarpProgress progress={status.progress ?? 0} />
          {status.state === 'processing' && <p className="text-xs text-white/60 mt-2">Processing events…</p>}
          {status.state === 'summarizing' && <p className="text-xs text-white/60 mt-2">Summarizing with AI…</p>}
          {status.state === 'failed' && <p className="text-pink-300 text-sm mt-2">Processing failed. Try re-uploading.</p>}
        </div>
      )}

      {open && status.state === 'done' && data && (
        <div className="mx-auto w-full max-w-screen-2xl space-y-8">
          {data.summary && (
            <section className="col-span-full relative z-0">
              <h4 className="warp-section-title mb-2">AI Summary</h4>
              <div className="rounded-xl border border-white/10 bg-white/5 backdrop-blur-xs p-4 text-sm whitespace-pre-wrap">
                {data.summary}
              </div>
            </section>
          )}

          <section className="col-span-full relative z-0">
            <h4 className="warp-section-title mb-2">Timeline</h4>
            <div className="rounded-xl border border-white/10 bg-white/5 backdrop-blur-xs p-4">
              <TimelineChart data={data.timeline} />
            </div>
          </section>

          <section className="col-span-full relative isolate z-10">
            <h4 className="warp-section-title mb-2">Findings</h4>
            <div className="rounded-xl border border-white/10 bg-white/5 backdrop-blur-xs relative overflow-visible">
              <ul className="divide-y divide-white/10 overflow-visible relative z-0">
                {(data.anomaly_groups?.length ?? 0) === 0 && (
                  <li className="p-4 text-sm text-white/70">No findings detected.</li>
                )}
                {data.anomaly_groups?.map((g, i) => (
                  <FindingRow key={`${g.kind}-${i}`} g={g} />
                ))}
              </ul>
            </div>
          </section>
        </div>
      )}
    </div>
  )
}
