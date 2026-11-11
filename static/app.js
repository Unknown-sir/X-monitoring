
async function refreshServers() {
  const res = await fetch('/api/servers');
  const data = await res.json();
  const tbody = document.querySelector('#servers-tbody');
  tbody.innerHTML = '';
  for (const s of data) {
    const tr = document.createElement('tr');
    const remain = (s.limit || 0) - (s.usage || 0);
    let badge = '<span class="badge ok">OK</span>';
    if (s.limit && remain <= 200 && remain > 0) badge = '<span class="badge warn">LOW</span>';
    if (s.limit && remain <= 0) badge = '<span class="badge crit">EXCEEDED</span>';
    tr.innerHTML = `
      <td>${s.id}</td>
      <td><a href="/server/${s.id}">${s.name}</a> <small>(${s.ip})</small></td>
      <td>${(s.usage||0).toFixed(2)} / ${s.limit||0}</td>
      <td>${s.updated_at ? new Date(s.updated_at).toLocaleTimeString() : '-'}</td>
      <td>${s.active ? 'ON' : 'OFF'}</td>
      <td>${badge}</td>
    `;
    tbody.appendChild(tr);
  }
}
if (document.querySelector('#servers-tbody')) {
  refreshServers();
  setInterval(refreshServers, 1000);
}
