import React, { useEffect, useState } from 'react'
import Login from './components/Login'
import Uploader from './components/Uploader'
import Results from './components/Results'
import { getUploads } from './api'
import type { UploadSummary } from './types'
import Header from './components/Header'

export default function App() {
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'))
  const [uploads, setUploads] = useState<UploadSummary[]>([])

  useEffect(() => {
    if (!token) return;
    getUploads(token)
      .then(setUploads)
      .catch((err: any) => {
        if (err?.status === 401 || err?.message === "unauthorized") {
          localStorage.removeItem("token");
          setToken(null);
          setUploads([])
        }
      });
}, [token]);

  const handleLogout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setUploads([]);
  };

  if (!token) return <Login onAuthed={(t) => { localStorage.setItem('token', t); setToken(t) }} />

  return (
    <div className="min-h-screen">
      <div className="max-w-6xl mx-auto px-6 py-10">
        <Header loggedIn={!!token} onLogout={handleLogout} subtitle="futuristic log intelligence for SOCs" />
        <div className="warp-card p-5 md:p-6">
          <Uploader
            token={token}
            onUploaded={(u) =>
              setUploads((prev) => [
                {
                  ...u,
                  status: u.status as "processing" | "done" | "failed" | undefined,
                },
                ...prev,
              ])
            }
          />
        </div>

        <section className="mt-8">
          <h2 className="warp-section-title mb-3">Analyses</h2>
          <div className="grid grid-cols-1 gap-5">
            {uploads.map(u => (
              <div className="warp-card p-4" key={u.id}>
                <Results token={token!} upload={u} />
              </div>
            ))}
          </div>
        </section>

        <div className="mt-16 text-center text-white/40 text-xs">
          © {new Date().getFullYear()} Warptrace
        </div>
      </div>
    </div>
  )
}
