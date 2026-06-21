'use strict';

(function () {
  function escapeHtml(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function getParam(name) {
    const params = new URLSearchParams(window.location.search);
    return params.get(name);
  }

  function showError(msg) {
    const box = document.getElementById('error-box');
    const msgEl = document.getElementById('error-message');
    if (msgEl) msgEl.textContent = msg;
    if (box) box.style.display = 'block';
  }

  function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value != null ? value : '';
  }

  function buildEntryEl(sub) {
    const entry = document.createElement('div');
    entry.className = 'entry';

    const nameSpan = document.createElement('span');
    nameSpan.className = 'entry-name';
    nameSpan.textContent = sub.name;
    entry.appendChild(nameSpan);

    if (sub.sources && sub.sources.length > 0) {
      const sourcesSpan = document.createElement('span');
      sourcesSpan.className = 'entry-sources';
      sub.sources.forEach(function (src) {
        const tag = document.createElement('span');
        tag.className = 'source-tag';
        tag.textContent = src;
        sourcesSpan.appendChild(tag);
      });
      entry.appendChild(sourcesSpan);
    }

    if (sub.ip != null) {
      const ipSpan = document.createElement('span');
      ipSpan.className = 'entry-ip';
      ipSpan.textContent = sub.ip;
      entry.appendChild(ipSpan);
    }

    return entry;
  }

  function renderSubdomains(subdomains) {
    const list = document.getElementById('entry-list');
    if (!list) return;
    list.innerHTML = '';

    if (!subdomains || subdomains.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'empty';
      empty.textContent = 'No subdomains found.';
      list.appendChild(empty);
      return;
    }

    subdomains.forEach(function (sub) {
      list.appendChild(buildEntryEl(sub));
    });
  }

  function populatePage(data, domain) {
    document.title = 'subfinder-recon — ' + domain;

    setText('domain-title', data.domain);

    const queriedAtEl = document.getElementById('queried-at');
    if (queriedAtEl) queriedAtEl.textContent = data.queried_at || '';

    const contributorEl = document.getElementById('contributor');
    if (contributorEl) {
      const name = data.display_name || '';
      const loc = data.display_loc || '';
      contributorEl.textContent = name && loc ? name + ' — ' + loc : name || loc;
    }

    setText('val-subdomain-count', data.subdomain_count != null ? data.subdomain_count : '');
    setText('val-source-count', data.source_count != null ? data.source_count : '');
    setText('val-unique-ips', data.unique_ips != null ? data.unique_ips : '');
    setText('val-wildcard-count', data.wildcard_count != null ? data.wildcard_count : '');

    renderSubdomains(data.subdomains);
  }

  document.addEventListener('DOMContentLoaded', function () {
    const domain = getParam('d');

    if (!domain) {
      window.location.href = 'subdomain-registry.html';
      return;
    }

    document.title = 'subfinder-recon — ' + domain;

    fetch('data/domains/' + encodeURIComponent(domain) + '.json')
      .then(function (res) {
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.json();
      })
      .then(function (data) {
        populatePage(data, domain);
      })
      .catch(function () {
        showError('No data found for ' + domain);
      });
  });
})();
