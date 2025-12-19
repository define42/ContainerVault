type BootstrapData = {
  namespaces: string[];
};

type TagInfo = {
  tag: string;
  digest: string;
  compressed_size: number;
};

type State = {
  expandedNamespace: string | null;
  expandedRepo: string | null;
  reposByNamespace: Record<string, string[]>;
  repoLoading: Record<string, boolean>;
  tagsByRepo: Record<string, string[]>;
};

(function initDashboard() {
  const tree = document.getElementById("tree");
  const detail = document.getElementById("detailPanel");
  if (!tree || !detail) {
    return;
  }

  const bootstrapEl = document.getElementById("cv-bootstrap");
  const bootstrap: BootstrapData = bootstrapEl?.textContent
    ? JSON.parse(bootstrapEl.textContent)
    : { namespaces: [] };
  const namespaces = Array.isArray(bootstrap.namespaces) ? bootstrap.namespaces : [];

  const state: State = {
    expandedNamespace: null,
    expandedRepo: null,
    reposByNamespace: {},
    repoLoading: {},
    tagsByRepo: {},
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
      tree.innerHTML = '<div class="mono">No namespaces assigned.</div>';
      return;
    }
    tree.innerHTML = namespaces
      .map((ns) => {
        const expanded = state.expandedNamespace === ns;
        const caret = expanded ? "&#9662;" : "&#9656;";
        const repos = state.reposByNamespace[ns] || [];
        const repoLoading = state.repoLoading[ns];
        const repoMarkup = expanded
          ? '<div class="branch">' + renderRepos(repos, repoLoading) + "</div>"
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

  function renderRepos(repos: string[], loading?: boolean): string {
    if (loading) {
      return '<div class="leaf mono">Loading repositories...</div>';
    }
    if (!repos || repos.length === 0) {
      return '<div class="leaf mono">No repositories found.</div>';
    }
    return repos
      .map((repo) => {
        const expanded = state.expandedRepo === repo;
        const caret = expanded ? "&#9662;" : "&#9656;";
        return (
          '<button class="node' +
          (expanded ? " active" : "") +
          '" data-type="repo" data-name="' +
          escapeHTML(repo) +
          '">' +
          '<span class="caret">' +
          caret +
          "</span>" +
          "<span>" +
          escapeHTML(repo) +
          "</span>" +
          "</button>"
        );
      })
      .join("");
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
        detail.innerHTML = '<div class="mono">' + escapeHTML(text) + "</div>";
        renderTree();
        return;
      }
      const data = JSON.parse(text) as { repositories?: string[] };
      state.reposByNamespace[namespace] = data.repositories || [];
    } catch (err) {
      detail.innerHTML = '<div class="mono">Unable to load repositories.</div>';
    } finally {
      state.repoLoading[namespace] = false;
      renderTree();
    }
  }

  async function loadTags(repo: string): Promise<void> {
    detail.innerHTML = '<div class="mono">Loading tags...</div>';
    try {
      const res = await fetch("/api/tags?repo=" + encodeURIComponent(repo));
      const text = await res.text();
      if (!res.ok) {
        state.tagsByRepo[repo] = [];
        detail.innerHTML = '<div class="mono">' + escapeHTML(text) + "</div>";
        return;
      }
      const data = JSON.parse(text) as { tags?: string[] };
      state.tagsByRepo[repo] = data.tags || [];
      renderDetail(repo, state.tagsByRepo[repo]);
    } catch (err) {
      detail.innerHTML = '<div class="mono">Unable to load tags.</div>';
    }
  }

  function renderDetail(repo: string, tags: string[]): void {
    if (!repo) {
      detail.innerHTML = "Select a repository to view tags.";
      return;
    }
    const base = window.location.host;
    const rows = (tags || [])
      .map((tag) => {
        return (
          '<div class="tagrow" data-tag-row="' +
          escapeHTML(tag) +
          '">' +
          '<div class="tagrow-header">' +
          '<span class="tagname">' +
          escapeHTML(tag) +
          "</span>" +
          '<span class="stat">loading...</span>' +
          "</div>" +
          '<div class="ref">' +
          escapeHTML(base + "/" + repo + ":" + tag) +
          "</div>" +
          "</div>"
        );
      })
      .join("");
    detail.innerHTML =
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
    const row = detail.querySelector('[data-tag-row="' + CSS.escape(tag) + '"]');
    if (!row) {
      return;
    }
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
      "</span>";
  }

  tree.addEventListener("click", (event) => {
    const target = event.target as HTMLElement | null;
    const button = target?.closest("button.node") as HTMLButtonElement | null;
    if (!button) {
      return;
    }
    const type = button.getAttribute("data-type");
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

  renderTree();
})();
