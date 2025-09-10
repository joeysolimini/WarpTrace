import React from 'react'
import { LineChart, Line, CartesianGrid, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'

export default function TimelineChart({ data }: { data: { minute: string, count: number }[] }) {
  return (
    <div className="h-48 text-warp-pink">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
          <XAxis dataKey="minute" tick={{ fontSize: 10, fill: 'rgba(255,255,255,0.7)' }} />
          <YAxis tick={{ fill: 'rgba(255,255,255,0.7)' }} />
          <Tooltip contentStyle={{ background: 'rgba(20, 15, 35, 0.9)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 12, color: '#fff' }} />
          <Line type="monotone" dataKey="count" dot={false} stroke="#ff2fa1" strokeWidth={2} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}
