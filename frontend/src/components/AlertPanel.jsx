export default function AlertPanel() {
  return (
    <div className="panel">
      <h2>AI Alerts</h2>

      <ul>
        <li>⚠ High CPU detected on backend</li>
        <li>⚠ Memory spike on Redis</li>
      </ul>
    </div>
  );
}