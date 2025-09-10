import React, { useId, useRef, useState } from 'react'
import { uploadFile, runAnalysis } from '../api'

export default function Uploader({
  token,
  onUploaded,
}: {
  token: string
  onUploaded: (u: { id: number; filename: string; created_at: string; status?: string; progress?: number }) => void
}) {
  const inputId = useId()
  const fileRef = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)

  const onPick = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0] || null
    setFile(f)
  }

  const clearSelection = () => {
    if (fileRef.current) fileRef.current.value = ''
    setFile(null)
  }

  const doUpload = async () => {
    if (!file) return
    setBusy(true)
    try {
      // 1) upload quickly
      const res = await uploadFile(token, file) // { upload_id, status: "uploaded", progress: 0 }

      // 2) show a tile immediately so it starts polling status/progress
      onUploaded({
        id: res.upload_id,
        filename: file.name,
        created_at: new Date().toISOString(),
        status: res.status,
        progress: res.progress,
      })

      // 3) kick off analysis (fire-and-forget)
      runAnalysis(token, res.upload_id).catch(() => {})
    } finally {
      setBusy(false)
      clearSelection()
    }
  }

  return (
    <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
      <div>
        <h3 className="font-display text-lg bg-clip-text text-transparent bg-gradient-to-r from-warp-pink to-warp-purple">
          Upload Logs
        </h3>
        <p className="warp-subtle">Choose a file—analysis starts instantly.</p>
      </div>

      <div className="flex items-center gap-2">
        <a
        href="/samples/warptrace_auth0_example_logs.zip"
        download
        className="warp-btn text-sm"
        title="Download Auth0 example logs"
      >
        Download sample Auth0 logs
      </a>

        {/* Hidden native input (prevents the browser’s “no file chosen” text) */}
        <input
          id={inputId}
          ref={fileRef}
          type="file"
          accept=".csv,.log,.txt,.json,.jsonl"
          onChange={onPick}
          className="sr-only"
        />

        {/* Warptrace “Choose file” button */}
        <label
          htmlFor={inputId}
          className="warp-btn text-sm cursor-pointer select-none"
          role="button"
          tabIndex={0}
        >
          {file ? 'Choose another' : 'Choose file'}
        </label>

        {/* Selected filename (only if present) */}
        {file && (
          <span
            className="max-w-[220px] truncate text-xs px-3 py-1 rounded-full border border-white/10 bg-white/5"
            title={file.name}
          >
            {file.name}
          </span>
        )}

        {/* Upload button */}
        <button
          className="warp-btn text-sm disabled:opacity-50"
          onClick={doUpload}
          disabled={!file || busy}
        >
          {busy ? 'Uploading…' : 'Upload'}
        </button>

        {/* Optional clear (small, subtle) */}
        {file && (
          <button
            onClick={clearSelection}
            className="text-xs px-2 py-1 rounded-lg border border-white/10 bg-white/5 hover:bg-white/10 transition"
            title="Clear selection"
          >
            Clear
          </button>
        )}
      </div>
    </div>
  )
}
