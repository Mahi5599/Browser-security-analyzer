import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

export default function TrackerChart({ report }) {
  const nets = report?.top_networks ?? [];
  if (!nets.length) return <p className="empty">No tracker reports yet. Browse with the extension loaded.</p>;
  const fp = report.fingerprinting;
  return (
    <>
      <div role="img" aria-label={`Top ${nets.length} tracker networks by request count`}>
        <ResponsiveContainer width="100%" height={Math.max(180, nets.length * 28 + 40)}>
          <BarChart data={nets} layout="vertical" margin={{ top: 4, right: 16, bottom: 4, left: 8 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--grid)" horizontal={false} />
            <XAxis type="number" stroke="var(--muted)" allowDecimals={false} />
            <YAxis type="category" dataKey="network" width={150} stroke="var(--muted)" tick={{ fontSize: 12 }} />
            <Tooltip formatter={(v, n) => [v, n === "requests" ? "requests" : n]} />
            <Bar dataKey="requests" fill="var(--accent)" isAnimationActive={false} />
          </BarChart>
        </ResponsiveContainer>
      </div>
      <p className="muted">
        {report.totals.sessions ?? 0} page load{report.totals.sessions === 1 ? "" : "s"} on {report.totals.sites ?? 0} site{report.totals.sites === 1 ? "" : "s"} ·{" "}
        {report.totals.pixels ?? 0} pixels · {report.totals.beacons ?? 0} beacons ·{" "}
        <b>{fp.sessions}</b> canvas-fingerprinting page load{fp.sessions === 1 ? "" : "s"}
        {fp.sites.length ? ` (${fp.sites.join(", ")})` : ""}
      </p>
    </>
  );
}
