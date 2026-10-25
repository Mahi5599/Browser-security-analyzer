import { CartesianGrid, ReferenceLine, ResponsiveContainer, Scatter, ScatterChart, Tooltip, XAxis, YAxis } from "recharts";
import { VERDICT_COLOR } from "../theme.js";

function Dot({ cx, cy, payload }) {
  const color = VERDICT_COLOR[payload.verdict] ?? "#6b7280";
  // URL = circle, file = square: shape carries the type, colour the verdict.
  return payload.kind === "File"
    ? <rect x={cx - 5} y={cy - 5} width={10} height={10} fill={color} />
    : <circle cx={cx} cy={cy} r={6} fill={color} />;
}

function Tip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div className="tip">
      <b>{p.kind}: {p.verdict} ({Math.round(p.score * 100)}%)</b>
      <div className="mono">{p.label}</div>
      <div>{new Date(p.t).toLocaleString()}</div>
    </div>
  );
}

export default function Timeline({ points }) {
  if (!points.length) return <p className="empty">No flagged URLs or files yet. Browse or download something suspicious.</p>;
  return (
    <div role="img" aria-label={`Risk timeline with ${points.length} flagged events`}>
      <ResponsiveContainer width="100%" height={260}>
        <ScatterChart margin={{ top: 8, right: 16, bottom: 8, left: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--grid)" />
          <XAxis dataKey="t" type="number" domain={["dataMin", "dataMax"]} scale="time"
                 tickFormatter={(t) => new Date(t).toLocaleTimeString()} stroke="var(--muted)" />
          <YAxis dataKey="score" type="number" domain={[0, 1.08]} ticks={[0, 0.25, 0.5, 0.75, 1]} tickFormatter={(v) => `${Math.round(v * 100)}%`} stroke="var(--muted)" />
          <ReferenceLine y={0.35} stroke={VERDICT_COLOR.suspicious} strokeDasharray="4 4" label={{ value: "suspicious", fill: "var(--muted)", fontSize: 11, position: "insideTopRight" }} />
          <ReferenceLine y={0.65} stroke={VERDICT_COLOR.phishing} strokeDasharray="4 4" label={{ value: "phishing / malicious", fill: "var(--muted)", fontSize: 11, position: "insideTopRight" }} />
          <Tooltip content={<Tip />} />
          <Scatter data={points} shape={<Dot />} isAnimationActive={false} />
        </ScatterChart>
      </ResponsiveContainer>
      <p className="legend"><span className="dot" /> URL &nbsp; <span className="sq" /> file &nbsp;·&nbsp;
        <i style={{ color: VERDICT_COLOR.suspicious }}>■</i> suspicious &nbsp;
        <i style={{ color: VERDICT_COLOR.phishing }}>■</i> phishing / malicious</p>
    </div>
  );
}
