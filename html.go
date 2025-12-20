package main

const loginHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ContainerVault Enterprise</title>
  <style>
    :root { --bg:#0b1224; --panel:#0f172a; --accent:#38bdf8; --muted:#94a3b8; --line:rgba(255,255,255,0.1); }
    body { margin:0; font-family: "Space Grotesk", "Segoe UI", sans-serif; background:
      radial-gradient(circle at 15% 15%, rgba(56,189,248,0.18), transparent 40%),
      radial-gradient(circle at 85% 5%, rgba(14,165,233,0.12), transparent 35%),
      var(--bg);
      color:#e2e8f0; display:flex; align-items:center; justify-content:center; min-height:100vh; padding:24px; }
    .card { background:linear-gradient(160deg, rgba(15,23,42,0.96), rgba(2,6,23,0.96)); border:1px solid var(--line); border-radius:18px; padding:36px 40px; max-width:520px; width:100%; box-shadow:0 24px 70px rgba(0,0,0,0.4); }
    h1 { margin:0 0 12px; font-size:30px; color:var(--accent); }
    p { margin:8px 0; line-height:1.5; color:var(--muted); }
    form { display:grid; gap:14px; margin-top:18px; }
    label { font-size:13px; color:var(--muted); letter-spacing:0.3px; text-transform:uppercase; }
    input { background:#0b1224; border:1px solid var(--line); color:#e2e8f0; border-radius:10px; padding:10px 12px; font-size:15px; }
    button { border:0; border-radius:10px; padding:12px 14px; font-weight:600; background:var(--accent); color:#062238; cursor:pointer; }
  </style>
</head>
<body>
  <div class="card">
    <h1>ContainerVault Enterprise</h1>
    <p>Sign in to see your allowed namespaces and browse repository contents.</p>
    <form method="post" action="/login">
      <div>
        <label for="username">Username</label>
        <input id="username" name="username" autocomplete="username" required>
      </div>
      <div>
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required>
      </div>
      <button type="submit">Continue</button>
    </form>
  </div>
</body>
</html>
`

const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ContainerVault Enterprise</title>
  <style>
    :root { --bg:#0b1224; --panel:#0f172a; --accent:#38bdf8; --muted:#94a3b8; --line:rgba(255,255,255,0.1); --tree:#0b1224; }
    body { margin:0; font-family: "Space Grotesk", "Segoe UI", sans-serif; background:
      radial-gradient(circle at 10%% 20%%, rgba(56,189,248,0.16), transparent 40%%),
      radial-gradient(circle at 90%% 0%%, rgba(14,165,233,0.12), transparent 35%%),
      var(--bg);
      color:#e2e8f0; min-height:100vh; padding:32px; }
    h1 { margin:0 0 6px; font-size:28px; color:var(--accent); }
    p { margin:6px 0 18px; color:var(--muted); }
    .layout { display:grid; gap:18px; grid-template-columns: 320px 1fr; }
    .panel { border:1px solid var(--line); border-radius:16px; padding:16px; background:rgba(2,6,23,0.75); }
    .panel-title { font-size:12px; letter-spacing:0.3px; text-transform:uppercase; color:var(--muted); margin-bottom:12px; }
    .mono { font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace; color:#cbd5e1; }
    .topbar { display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; }
    .logout { border:1px solid var(--line); background:#0b1224; color:#e2e8f0; padding:8px 12px; border-radius:10px; cursor:pointer; }
    .tree { display:flex; flex-direction:column; gap:6px; }
    .node { width:100%%; text-align:left; border:1px solid var(--line); background:var(--tree); color:#e2e8f0; padding:8px 10px; border-radius:10px; display:flex; align-items:center; gap:8px; cursor:pointer; font-size:14px; }
    .node:hover { border-color:rgba(56,189,248,0.6); }
    .node.active { border-color:var(--accent); box-shadow:0 0 0 1px rgba(56,189,248,0.2) inset; }
    .node[data-type="namespace"] { background:rgba(56,189,248,0.14); color:#bae6fd; border-color:rgba(56,189,248,0.45); }
    .node[data-type="namespace"].active { border-color:var(--accent); }
    .node[data-type="folder"] { background:rgba(20,30,60,0.8); color:#e2e8f0; border-color:rgba(148,163,184,0.35); }
    .node[data-type="repo"] { background:rgba(15,23,42,0.8); color:#e2e8f0; }
    .node::before { content: ""; width:14px; height:14px; display:inline-flex; align-items:center; justify-content:center; font-size:12px; }
    .node[data-type="namespace"]::before { content: "◎"; color:#7dd3fc; }
    .node[data-type="folder"]::before { content: "▸"; color:#94a3b8; }
    .node[data-type="repo"]::before { content: "●"; color:#cbd5e1; }
    .node[data-depth="2"]::before { color:#a5b4fc; }
    .node[data-depth="3"]::before { color:#facc15; }
    .node[data-depth="4"]::before { color:#f97316; }
    .caret { width:16px; height:16px; display:inline-flex; align-items:center; justify-content:center; font-size:12px; color:var(--muted); }
    .branch { margin-left:20px; display:flex; flex-direction:column; gap:6px; }
    .leaf { border:1px dashed rgba(148,163,184,0.35); background:rgba(15,23,42,0.6); padding:6px 10px; border-radius:10px; font-size:13px; color:#cbd5e1; }
    .tags { margin-top:10px; display:flex; flex-wrap:wrap; gap:8px; }
    .tag { padding:6px 10px; border-radius:999px; background:rgba(56,189,248,0.12); color:#bae6fd; font-size:12px; }
    .ref { color:#cbd5e1; font-size:13px; margin-top:10px; word-break:break-all; display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
    .ref-text { font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace; }
    .copy-ref { border:1px solid rgba(56,189,248,0.6); background:rgba(56,189,248,0.16); color:#bae6fd; padding:4px 10px; border-radius:999px; font-size:12px; cursor:pointer; }
    .copy-ref:hover { border-color:rgba(56,189,248,0.9); background:rgba(56,189,248,0.28); color:#e0f2fe; }
    .detail { min-height:220px; }
    .taglist { display:grid; gap:10px; margin-top:12px; }
    .tagrow { border:1px solid var(--line); border-radius:12px; padding:10px 12px; background:rgba(15,23,42,0.6); cursor:pointer; }
    .tagrow-header { display:flex; align-items:center; justify-content:space-between; gap:12px; }
    .tagname { font-weight:600; color:#e2e8f0; }
    .tagstats { display:flex; gap:12px; flex-wrap:wrap; font-size:12px; color:var(--muted); }
    .stat { padding:4px 8px; border-radius:999px; background:rgba(148,163,184,0.12); }
    .details-toggle { border:1px solid rgba(56,189,248,0.6); background:rgba(56,189,248,0.18); color:#bae6fd; padding:4px 10px; border-radius:999px; font-size:12px; cursor:pointer; }
    .details-toggle:hover { border-color:rgba(56,189,248,0.9); background:rgba(56,189,248,0.28); color:#e0f2fe; }
    .layers { margin-top:10px; border-top:1px dashed rgba(148,163,184,0.25); padding-top:10px; display:grid; gap:8px; }
    .layer { display:grid; grid-template-columns:28px minmax(0,1fr) 90px 160px minmax(0,1.2fr); gap:10px; font-size:12px; color:#cbd5e1; align-items:baseline; }
    .layer-header { color:var(--muted); text-transform:uppercase; font-size:11px; letter-spacing:0.06em; }
    .layer-index { color:var(--muted); text-align:right; }
    .layer code { color:#e2e8f0; }
    .layer-digest { word-break:break-all; }
    .layer-history { word-break:break-word; }
    .history { margin:10px 0 6px; display:grid; gap:6px; }
    .history-title { font-size:11px; text-transform:uppercase; letter-spacing:0.08em; color:var(--muted); }
    .history-row { display:grid; grid-template-columns:28px 60px minmax(0,1fr); gap:10px; font-size:12px; color:#cbd5e1; align-items:baseline; }
    .history-index { color:var(--muted); text-align:right; }
    .history-kind { font-weight:600; color:#e2e8f0; }
    .history-command { word-break:break-word; }
    .meta { display:grid; gap:6px; margin-bottom:10px; }
    .meta-row { display:flex; justify-content:space-between; gap:10px; font-size:12px; color:#cbd5e1; }
    .meta-key { color:var(--muted); }
    .meta-value { text-align:right; max-width:70%%; word-break:break-word; }
    @media (max-width: 900px) { .layout { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <div class="topbar">
    <div>
      <h1>ContainerVault Enterprise</h1>
      <p>Welcome, %s. Expand a namespace to browse repositories and tags.</p>
    </div>
    <form method="post" action="/logout">
      <button class="logout" type="submit">Logout</button>
    </form>
  </div>
  <div class="layout">
    <div class="panel">
      <div class="panel-title">Namespace Tree</div>
      <div id="tree" class="tree"></div>
    </div>
    <div class="panel">
      <div class="panel-title">Details</div>
      <div id="detailPanel" class="detail mono">Select a repository to view tags.</div>
    </div>
  </div>
  <script id="cv-bootstrap" type="application/json">%s</script>
  <script type="module" src="/static/ui.js"></script>
</body>
</html>
`
