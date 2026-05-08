export default function LogsPanel() {
  return (
    <div className="panel">
      <h2>Recent Logs</h2>

      <div className="logs">
        <p>[INFO] Monitoring services...</p>
        <p>[INFO] Backend healthy</p>
        <p>[WARNING] CPU anomaly detected</p>
      </div>
    </div>
  );
}