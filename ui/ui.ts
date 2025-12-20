type BootstrapData = {
  namespaces: string[];
};

type TagInfo = {
  tag: string;
  digest: string;
  compressed_size: number;
};

type TagDetails = {
  repo: string;
  tag: string;
  digest: string;
  media_type: string;
  schema_version: number;
  config: {
    digest: string;
    size: number;
    media_type: string;
    created: string;
    os: string;
    architecture: string;
    entrypoint: string[];
    cmd: string[];
    env: string[];
    labels: Record<string, string>;
    history_count: number;
    history: HistoryEntry[];
  };
  platforms?: { os: string; architecture: string; variant?: string }[];
  layers: LayerInfo[];
};

type State = {
  expandedNamespace: string | null;
  expandedRepo: string | null;
  expandedFolders: Record<string, boolean>;
  reposByNamespace: Record<string, string[]>;
  repoLoading: Record<string, boolean>;
  tagsByRepo: Record<string, string[]>;
  tagDetailsByTag: Record<string, TagDetails>;
  layersLoading: Record<string, boolean>;
  layersVisible: Record<string, boolean>;
};

type LayerInfo = {
  digest: string;
  size: number;
  media_type: string;
};

type HistoryEntry = {
  created_by: string;
  empty_layer?: boolean;
};

(function initDashboard() {
  const tree = document.getElementById("tree");
  const detail = document.getElementById("detailPanel");
  if (!tree || !detail) {
    return;
  }
  const treeEl = tree;
  const detailEl = detail;

  const bootstrapEl = document.getElementById("cv-bootstrap");
  const bootstrap: BootstrapData = bootstrapEl?.textContent
    ? JSON.parse(bootstrapEl.textContent)
    : { namespaces: [] };
  const namespaces = Array.isArray(bootstrap.namespaces) ? bootstrap.namespaces : [];

  const state: State = {
    expandedNamespace: null,
    expandedRepo: null,
    expandedFolders: {},
    reposByNamespace: {},
    repoLoading: {},
    tagsByRepo: {},
    tagDetailsByTag: {},
    layersLoading: {},
    layersVisible: {},
  };

  function escapeHTML(value: string): string {
    return String(value).replace(/[&<>"']/g, (ch) => {
      const map: Record<string, string> = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      };
      return map[ch] ?? ch;
    });
  }

  function renderTree(): void {
    if (!namespaces || namespaces.length === 0) {
      treeEl.innerHTML = '<div class="mono">No namespaces assigned.</div>';
      return;
    }
    treeEl.innerHTML = namespaces
      .map((ns) => {
        const expanded = state.expandedNamespace === ns;
        const caret = expanded ? "&#9662;" : "&#9656;";
        const repos = state.reposByNamespace[ns] || [];
        const repoLoading = state.repoLoading[ns];
        const repoMarkup = expanded
          ? '<div class="branch">' + renderRepos(ns, repos, repoLoading) + "</div>"
          : "";
        return (
          '<button class="node' +
          (expanded ? " active" : "") +
          '" data-type="namespace" data-name="' +
          escapeHTML(ns) +
          '">' +
          '<span class="caret">' +
          caret +
          "</span>" +
          "<span>" +
          escapeHTML(ns) +
          "</span>" +
          "</button>" +
          repoMarkup
        );
      })
      .join("");
  }

  function renderRepos(namespace: string, repos: string[], loading?: boolean): string {
    if (loading) {
      return '<div class="leaf mono">Loading repositories...</div>';
    }
    if (!repos || repos.length === 0) {
      return '<div class="leaf mono">No repositories found.</div>';
    }
    const tree = buildRepoTree(namespace, repos);
    return renderFolderNode(namespace, tree);
  }

  function repoLabel(namespace: string, repo: string): string {
    return repo.startsWith(namespace + "/") ? repo.slice(namespace.length + 1) : repo;
  }

  function repoLeafLabel(namespace: string, repo: string): string {
    const label = repoLabel(namespace, repo);
    const parts = label.split("/");
    return parts[parts.length - 1];
  }

  type RepoTreeNode = {
    path: string;
    children: Record<string, RepoTreeNode>;
    repos: string[];
  };

  function buildRepoTree(namespace: string, repos: string[]): RepoTreeNode {
    const root: RepoTreeNode = { path: "", children: {}, repos: [] };
    repos.forEach((repo) => {
      const label = repoLabel(namespace, repo);
      const parts = label.split("/");
      if (parts.length === 1) {
        root.repos.push(repo);
        return;
      }
      let current = root;
      for (let i = 0; i < parts.length - 1; i += 1) {
        const seg = parts[i];
        if (!current.children[seg]) {
          const path = current.path ? current.path + "/" + seg : seg;
          current.children[seg] = { path, children: {}, repos: [] };
        }
        current = current.children[seg];
      }
      current.repos.push(repo);
    });
    return root;
  }

  function renderFolderNode(namespace: string, node: RepoTreeNode): string {
    const repoMarkup = node.repos
      .slice()
      .sort()
      .map((repo) => renderRepoNode(namespace, repo, repoLeafLabel(namespace, repo)))
      .join("");
    const folderMarkup = Object.keys(node.children)
      .sort()
      .map((folder) => {
        const child = node.children[folder];
        const folderKey = namespace + "/" + child.path;
        const expanded = !!state.expandedFolders[folderKey];
        const caret = expanded ? "&#9662;" : "&#9656;";
        const children = expanded
          ? '<div class="branch">' + renderFolderNode(namespace, child) + "</div>"
          : "";
        return (
          '<button class="node" data-type="folder" data-depth="' +
          escapeHTML(String(child.path.split("/").length)) +
          '" data-namespace="' +
          escapeHTML(namespace) +
          '" data-folder-path="' +
          escapeHTML(child.path) +
          '">' +
          '<span class="caret">' +
          caret +
          "</span>" +
          "<span>" +
          escapeHTML(folder) +
          "</span>" +
          "</button>" +
          children
        );
      })
      .join("");
    return repoMarkup + folderMarkup;
  }

  function renderRepoNode(namespace: string, repo: string, label: string): string {
    const expanded = state.expandedRepo === repo;
    const caret = expanded ? "&#9662;" : "&#9656;";
    return (
      '<button class="node' +
      (expanded ? " active" : "") +
      '" data-type="repo" data-depth="' +
      escapeHTML(String(repoLabel(namespace, repo).split("/").length)) +
      '" data-name="' +
      escapeHTML(repo) +
      '">' +
      '<span class="caret">' +
      caret +
      "</span>" +
      "<span>" +
      escapeHTML(label) +
      "</span>" +
      "</button>"
    );
  }

  async function loadRepos(namespace: string): Promise<void> {
    state.repoLoading[namespace] = true;
    renderTree();
    try {
      const res = await fetch("/api/repos?namespace=" + encodeURIComponent(namespace));
      const text = await res.text();
      if (!res.ok) {
        state.reposByNamespace[namespace] = [];
        state.repoLoading[namespace] = false;
        detailEl.innerHTML = '<div class="mono">' + escapeHTML(text) + "</div>";
        renderTree();
        return;
      }
      const data = JSON.parse(text) as { repositories?: string[] };
      state.reposByNamespace[namespace] = data.repositories || [];
    } catch (err) {
      detailEl.innerHTML = '<div class="mono">Unable to load repositories.</div>';
    } finally {
      state.repoLoading[namespace] = false;
      renderTree();
    }
  }

  async function loadTags(repo: string): Promise<void> {
    detailEl.innerHTML = '<div class="mono">Loading tags...</div>';
    try {
      const res = await fetch("/api/tags?repo=" + encodeURIComponent(repo));
      const text = await res.text();
      if (!res.ok) {
        state.tagsByRepo[repo] = [];
        detailEl.innerHTML = '<div class="mono">' + escapeHTML(text) + "</div>";
        return;
      }
      const data = JSON.parse(text) as { tags?: string[] };
      state.tagsByRepo[repo] = data.tags || [];
      renderDetail(repo, state.tagsByRepo[repo]);
    } catch (err) {
      detailEl.innerHTML = '<div class="mono">Unable to load tags.</div>';
    }
  }

  function renderDetail(repo: string, tags: string[]): void {
    if (!repo) {
      detailEl.innerHTML = "Select a repository to view tags.";
      return;
    }
    const base = window.location.host;
    const rows = (tags || [])
      .map((tag) => {
        return (
          '<div class="tagrow" data-tag-row="' +
          escapeHTML(tag) +
          '" data-tag="' +
          escapeHTML(tag) +
          '" data-repo="' +
          escapeHTML(repo) +
          '">' +
          '<div class="tagrow-header">' +
          '<span class="tagname">' +
          escapeHTML(tag) +
          "</span>" +
          '<span class="tagstats">' +
          '<span class="stat">loading...</span>' +
          "</span>" +
          '<button class="details-toggle" type="button" aria-expanded="false">Details</button>' +
          "</div>" +
          '<div class="ref">' +
          '<span class="ref-text">' +
          escapeHTML(base + "/" + repo + ":" + tag) +
          "</span>" +
          '<button class="copy-ref" type="button" data-copy-value="' +
          escapeHTML(base + "/" + repo + ":" + tag) +
          '">Copy</button>' +
          "</div>" +
          '<div data-layer-container="' +
          escapeHTML(repo + ":" + tag) +
          '"></div>' +
          "</div>"
        );
      })
      .join("");
    detailEl.innerHTML =
      "<div><strong>" +
      escapeHTML(repo) +
      "</strong></div>" +
      '<div class="taglist">' +
      (rows || '<div class="mono">No tags available.</div>') +
      "</div>";
    (tags || []).forEach((tag) => {
      loadTagInfo(repo, tag);
    });
  }

  function formatBytes(value: number | null | undefined): string {
    if (value == null || value < 0) {
      return "unknown size";
    }
    const units = ["B", "KB", "MB", "GB", "TB"];
    let size = value;
    let unitIndex = 0;
    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex += 1;
    }
    return size.toFixed(size >= 10 || unitIndex === 0 ? 0 : 1) + " " + units[unitIndex];
  }

  async function loadTagInfo(repo: string, tag: string): Promise<void> {
    try {
      const res = await fetch(
        "/api/taginfo?repo=" + encodeURIComponent(repo) + "&tag=" + encodeURIComponent(tag),
      );
      const text = await res.text();
      if (!res.ok) {
        updateTagRow(tag, { tag, digest: "unavailable", compressed_size: -1 });
        return;
      }
      const data = JSON.parse(text) as TagInfo;
      updateTagRow(tag, data);
    } catch (err) {
      updateTagRow(tag, { tag, digest: "unavailable", compressed_size: -1 });
    }
  }

  function updateTagRow(tag: string, data: TagInfo): void {
    const row = detailEl.querySelector('[data-tag-row="' + CSS.escape(tag) + '"]');
    if (!row) {
      return;
    }
    const repo = row.getAttribute("data-repo") || "";
    const key = repo ? repo + ":" + tag : tag;
    const isVisible = Boolean(state.layersVisible[key]);
    const digest = data.digest ? data.digest : "unknown digest";
    const compressed = formatBytes(data.compressed_size);
    const header = row.querySelector(".tagrow-header");
    if (!header) {
      return;
    }
    header.innerHTML =
      '<span class="tagname">' +
      escapeHTML(tag) +
      "</span>" +
      '<span class="tagstats">' +
      '<span class="stat">compressed ' +
      escapeHTML(compressed) +
      "</span>" +
      '<span class="stat mono">' +
      escapeHTML(digest) +
      "</span>" +
      "</span>" +
      '<button class="details-toggle" type="button" aria-expanded="' +
      (isVisible ? "true" : "false") +
      '">' +
      (isVisible ? "Hide details" : "Details") +
      "</button>";
  }

  function renderLayers(tagKey: string): string {
    if (state.layersLoading[tagKey]) {
      return '<div class="layers"><div class="mono">Loading layers...</div></div>';
    }
    const details = state.tagDetailsByTag[tagKey];
    const layers = details ? details.layers || [] : [];
    const meta = details
      ? renderMeta(details)
      : '<div class="meta"><div class="mono">Metadata unavailable.</div></div>';
    const history = details ? details.config.history || [] : [];
    const historyByLayerIndex = buildLayerHistory(history);
    if (layers.length === 0) {
      return '<div class="layers">' + meta + '<div class="mono">No layers found.</div></div>';
    }
    const header =
      '<div class="layer layer-header">' +
      "<span>#</span>" +
      "<span>Digest</span>" +
      "<span>Size</span>" +
      "<span>Media Type</span>" +
      "<span>History</span>" +
      "</div>";
    return (
      '<div class="layers">' +
      meta +
      header +
      layers
        .map((layer, index) => {
          const historyText = historyByLayerIndex[index] || "n/a";
          return (
            '<div class="layer">' +
            '<span class="layer-index">' +
            escapeHTML(String(index + 1)) +
            "</span>" +
            '<code class="layer-digest">' +
            escapeHTML(layer.digest) +
            "</code>" +
            "<span>" +
            escapeHTML(formatBytes(layer.size)) +
            "</span>" +
            "<span>" +
            escapeHTML(layer.media_type || "unknown") +
            "</span>" +
            '<span class="layer-history">' +
            escapeHTML(historyText) +
            "</span>" +
            "</div>"
          );
        })
        .join("") +
      "</div>"
    );
  }

  async function loadLayers(repo: string, tag: string): Promise<void> {
    const key = repo + ":" + tag;
    if (state.tagDetailsByTag[key]) {
      return;
    }
    state.layersLoading[key] = true;
    updateLayersUI(key);
    try {
      const res = await fetch(
        "/api/taglayers?repo=" + encodeURIComponent(repo) + "&tag=" + encodeURIComponent(tag),
      );
      const text = await res.text();
      if (!res.ok) {
        state.tagDetailsByTag[key] = emptyTagDetails(repo, tag);
        state.layersLoading[key] = false;
        updateLayersUI(key);
        return;
      }
      const data = JSON.parse(text) as TagDetails;
      state.tagDetailsByTag[key] = data;
    } catch (err) {
      state.tagDetailsByTag[key] = emptyTagDetails(repo, tag);
    } finally {
      state.layersLoading[key] = false;
      updateLayersUI(key);
    }
  }

  function emptyTagDetails(repo: string, tag: string): TagDetails {
    return {
      repo,
      tag,
      digest: "",
      media_type: "",
      schema_version: 0,
      config: {
        digest: "",
        size: 0,
        media_type: "",
        created: "",
        os: "",
        architecture: "",
        entrypoint: [],
        cmd: [],
        env: [],
        labels: {},
        history_count: 0,
        history: [],
      },
      layers: [],
    };
  }

  function renderHistory(details: TagDetails): string {
    const history = details.config.history || [];
    const entries = history
      .map((entry) => formatHistoryEntry(entry))
      .filter((entry) => entry !== null);
    if (entries.length === 0) {
      return '<div class="history"><div class="mono">No RUN/COPY/ADD history available.</div></div>';
    }
    return (
      '<div class="history">' +
      '<div class="history-title">History (RUN/COPY/ADD)</div>' +
      entries
        .map((entry, index) => {
          return (
            '<div class="history-row">' +
            '<span class="history-index">' +
            escapeHTML(String(index + 1)) +
            "</span>" +
            '<span class="history-kind">' +
            escapeHTML(entry.kind) +
            "</span>" +
            '<span class="history-command">' +
            escapeHTML(entry.command) +
            "</span>" +
            "</div>"
          );
        })
        .join("") +
      "</div>"
    );
  }

  function buildLayerHistory(history: HistoryEntry[]): Record<number, string> {
    const mapping: Record<number, string> = {};
    let layerIndex = 0;
    history.forEach((entry) => {
      if (entry.empty_layer) {
        return;
      }
      const formatted = formatHistoryEntry(entry);
      if (formatted) {
        mapping[layerIndex] = formatted.kind + ": " + formatted.command;
      } else {
        const raw = (entry.created_by || "").trim();
        if (raw) {
          mapping[layerIndex] = raw;
        }
      }
      layerIndex += 1;
    });
    return mapping;
  }

  function formatHistoryEntry(
    entry: HistoryEntry,
  ): { kind: "RUN" | "COPY" | "ADD"; command: string } | null {
    const raw = (entry.created_by || "").trim();
    if (!raw) {
      return null;
    }
    const nopPrefix = "#(nop) ";
    const cleaned = raw.startsWith(nopPrefix) ? raw.slice(nopPrefix.length).trim() : raw;
    if (cleaned.startsWith("COPY ")) {
      return { kind: "COPY", command: cleaned };
    }
    if (cleaned.startsWith("ADD ")) {
      return { kind: "ADD", command: cleaned };
    }
    const shellPrefix = "/bin/sh -c ";
    if (raw.startsWith(shellPrefix)) {
      return { kind: "RUN", command: raw.slice(shellPrefix.length).trim() || raw };
    }
    if (cleaned.startsWith("RUN ")) {
      return { kind: "RUN", command: cleaned };
    }
    return null;
  }

  function renderMeta(details: TagDetails): string {
    const platforms = (details.platforms || [])
      .map((p) => p.os + "/" + p.architecture + (p.variant ? "/" + p.variant : ""))
      .join(", ");
    const labels = details.config.labels || {};
    const labelPairs = Object.keys(labels)
      .sort()
      .map((k) => k + "=" + labels[k])
      .join(", ");
    const env = (details.config.env || []).join(", ");
    const entrypoint = (details.config.entrypoint || []).join(" ");
    const cmd = (details.config.cmd || []).join(" ");
    const osArch = [details.config.os, details.config.architecture].filter(Boolean).join("/");
    const layerTotal = (details.layers || []).reduce((sum, layer) => sum + (layer.size || 0), 0);
    return (
      '<div class="meta">' +
      metaRow("Manifest", details.media_type || "unknown") +
      metaRow("Schema", details.schema_version ? "v" + details.schema_version : "unknown") +
      metaRow("Digest", details.digest || "unknown") +
      metaRow("Config Digest", details.config.digest || "unknown") +
      metaRow("Config Media", details.config.media_type || "unknown") +
      metaRow("Config Size", formatBytes(details.config.size)) +
      metaRow("Created", details.config.created || "unknown") +
      metaRow("OS/Arch", osArch || "unknown") +
      metaRow("Entrypoint", entrypoint || "none") +
      metaRow("Cmd", cmd || "none") +
      metaRow("Env", env || "none") +
      metaRow("Labels", labelPairs || "none") +
      metaRow("History Entries", String(details.config.history_count || 0)) +
      metaRow("Layers", String(details.layers.length || 0)) +
      metaRow("Layer Total", formatBytes(layerTotal)) +
      metaRow("Platforms", platforms || "single") +
      "</div>"
    );
  }

  function metaRow(label: string, value: string): string {
    return (
      '<div class="meta-row"><span class="meta-key">' +
      escapeHTML(label) +
      '</span><span class="meta-value">' +
      escapeHTML(value || "unknown") +
      "</span></div>"
    );
  }

  function updateLayersUI(tagKey: string): void {
    const container = detailEl.querySelector('[data-layer-container="' + CSS.escape(tagKey) + '"]');
    if (!container) {
      return;
    }
    if (!state.layersVisible[tagKey]) {
      container.innerHTML = "";
      return;
    }
    container.innerHTML = renderLayers(tagKey);
  }

  treeEl.addEventListener("click", (event) => {
    const target = event.target as HTMLElement | null;
    const button = target?.closest("button.node") as HTMLButtonElement | null;
    if (!button) {
      return;
    }
    const type = button.getAttribute("data-type");
    if (type === "folder") {
      const folder = button.getAttribute("data-folder-path");
      const namespace = button.getAttribute("data-namespace");
      if (!folder || !namespace) {
        return;
      }
      const key = namespace + "/" + folder;
      state.expandedFolders[key] = !state.expandedFolders[key];
      renderTree();
      return;
    }
    const name = button.getAttribute("data-name");
    if (!name) {
      return;
    }
    if (type === "namespace") {
      if (state.expandedNamespace === name) {
        state.expandedNamespace = null;
        state.expandedRepo = null;
        renderTree();
        return;
      }
      state.expandedNamespace = name;
      state.expandedRepo = null;
      if (!state.reposByNamespace[name]) {
        loadRepos(name);
      } else {
        renderTree();
      }
      return;
    }
    if (type === "repo") {
      if (state.expandedRepo === name) {
        state.expandedRepo = null;
        renderTree();
        return;
      }
      state.expandedRepo = name;
      renderTree();
      if (!state.tagsByRepo[name]) {
        loadTags(name);
      } else {
        renderDetail(name, state.tagsByRepo[name]);
      }
    }
  });

  function toggleDetails(row: HTMLElement): void {
    const tag = row.getAttribute("data-tag");
    const repo = row.getAttribute("data-repo");
    if (!tag || !repo) {
      return;
    }
    const key = repo + ":" + tag;
    state.layersVisible[key] = !state.layersVisible[key];
    const container = row.querySelector('[data-layer-container="' + CSS.escape(key) + '"]');
    if (container) {
      if (state.layersVisible[key]) {
        container.innerHTML = renderLayers(key);
      } else {
        container.innerHTML = "";
      }
    }
    const toggleButton = row.querySelector(".details-toggle");
    if (toggleButton) {
      toggleButton.textContent = state.layersVisible[key] ? "Hide details" : "Details";
      toggleButton.setAttribute("aria-expanded", state.layersVisible[key] ? "true" : "false");
    }
    if (state.layersVisible[key]) {
      loadLayers(repo, tag);
    }
  }

  async function copyText(value: string): Promise<void> {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(value);
      return;
    }
    const input = document.createElement("textarea");
    input.value = value;
    input.setAttribute("readonly", "true");
    input.style.position = "absolute";
    input.style.left = "-9999px";
    document.body.appendChild(input);
    input.select();
    document.execCommand("copy");
    document.body.removeChild(input);
  }

  detailEl.addEventListener("click", (event) => {
    const target = event.target as HTMLElement | null;
    const copyButton = target?.closest(".copy-ref") as HTMLButtonElement | null;
    if (copyButton) {
      const value = copyButton.getAttribute("data-copy-value") || "";
      if (value) {
        copyText(value)
          .then(() => {
            copyButton.textContent = "Copied";
            window.setTimeout(() => {
              copyButton.textContent = "Copy";
            }, 1200);
          })
          .catch(() => {
            copyButton.textContent = "Failed";
            window.setTimeout(() => {
              copyButton.textContent = "Copy";
            }, 1200);
          });
      }
      event.stopPropagation();
      return;
    }
    const row = target?.closest(".tagrow") as HTMLElement | null;
    if (!row) {
      return;
    }
    toggleDetails(row);
  });

  renderTree();
})();
