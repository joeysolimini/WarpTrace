import React from 'react'
import type { Anomaly } from '../types'

export default function AnomalyTable({ anomalies }: { anomalies: Anomaly[] }) {
  if (!anomalies.length) return <p className="text-sm text-gray-600">No anomalies detected.</p>
  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="text-left border-b">
          <th className="py-1">Reason</th>
          <th className="py-1 w-24">Score</th>
        </tr>
      </thead>
      <tbody>
        {anomalies.map(a => (
          <tr key={a.id} className="border-b hover:bg-yellow-50">
            <td className="py-1 pr-3">{a.reason}</td>
            <td className="py-1">{a.score.toFixed(3)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
