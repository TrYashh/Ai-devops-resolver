import { useEffect, useState } from "react";

import Navbar from "../components/Navbar";
import ServiceCard from "../components/ServiceCard";
import AlertPanel from "../components/AlertPanel";
import LogsPanel from "../components/LogsPanel";
import MetricsChart from "../components/MetricsChart";

import { fetchServices } from "../api/api";

export default function Dashboard() {
  const [services, setServices] = useState([]);

  useEffect(() => {
    loadServices();

    const interval = setInterval(loadServices, 5000);

    return () => clearInterval(interval);
  }, []);

  async function loadServices() {
    const data = await fetchServices();

    if (data.length === 0) {
      setServices([
        {
          name: "Backend API",
          status: "Healthy",
          cpu: 32,
          memory: 41,
        },
        {
          name: "MCP Server",
          status: "Healthy",
          cpu: 21,
          memory: 38,
        },
        {
          name: "Redis",
          status: "Warning",
          cpu: 75,
          memory: 62,
        },
      ]);
    } else {
      setServices(data);
    }
  }

  return (
    <div className="dashboard">
      <Navbar />

      <div className="services-grid">
        {services.map((service, index) => (
          <ServiceCard key={index} service={service} />
        ))}
      </div>

      <div className="bottom-grid">
        <AlertPanel />
        <LogsPanel />
        <MetricsChart />
      </div>
    </div>
  );
}