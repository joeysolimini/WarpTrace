import React, { useState } from 'react'
import { login } from '../api'

export default function Login({ onAuthed }: { onAuthed: (token: string) => void }) {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('changeme')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true); setError(null)
    try {
      const res = await login(username, password)
      onAuthed(res.token)
    } catch (e:any) {
      setError(e.message || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-6">
      <div className="w-full max-w-md warp-card p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-warp-pink to-warp-purple shadow-neon" />
          <h1 className="font-display text-2xl bg-clip-text text-transparent bg-gradient-to-r from-warp-pink via-warp-fuchsia to-warp-purple">Warptrace</h1>
        </div>
        <p className="warp-subtle mb-5">Sign in to analyze logs at warp speed.</p>
        <form onSubmit={onSubmit} className="space-y-3">
          <input className="w-full rounded-xl bg-white/5 border border-white/10 px-3 py-2 outline-none focus:ring-2 focus:ring-warp-glow" placeholder="Username" value={username} onChange={e=>setUsername(e.target.value)} />
          <input className="w-full rounded-xl bg-white/5 border border-white/10 px-3 py-2 outline-none focus:ring-2 focus:ring-warp-glow" type="password" placeholder="Password" value={password} onChange={e=>setPassword(e.target.value)} />
          {error && <div className="text-pink-300 text-sm">{error}</div>}
          <button className="warp-btn w-full disabled:opacity-60" disabled={loading}>{loading ? 'Warping…' : 'Enter Warptrace'}</button>
          <p className="warp-subtle">Demo creds pre-filled. Change in <code>.env</code>.</p>
        </form>
      </div>
    </div>
  )
}
