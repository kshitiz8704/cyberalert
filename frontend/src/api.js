// Small wrapper around fetch for the backend REST API
export const getAlerts = (params) =>
  fetch('/api/alerts?' + new URLSearchParams(params)).then((r) => r.json());
export const getStats = () => fetch('/api/stats').then((r) => r.json());
