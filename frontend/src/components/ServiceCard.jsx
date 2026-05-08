export default function ServiceCard({ service }) {
  return (
    <div className="card">
      <h2>{service.name}</h2>

      <p>Status: {service.status}</p>

      <p>CPU: {service.cpu}%</p>

      <p>Memory: {service.memory}%</p>
    </div>
  );
}