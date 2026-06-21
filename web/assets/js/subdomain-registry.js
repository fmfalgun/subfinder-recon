'use strict';

(function () {
  let allDomains = [];

  function formatDate(iso) {
    if (!iso) return '';
    return iso.slice(0, 10);
  }

  function buildCard(domain) {
    const card = document.createElement('div');
    card.className = 'domain-card';
    card.setAttribute('data-domain', domain.domain);

    card.innerHTML = `
      <div class="card-header">
        <span class="card-domain">${escapeHtml(domain.domain)}</span>
        <span class="card-date">${escapeHtml(formatDate(domain.last_refreshed))}</span>
      </div>
      <div class="card-stats">
        <span class="card-stat"><span class="stat-num">${domain.subdomain_count}</span> subdomains</span>
        <span class="card-stat"><span class="stat-num">${domain.source_count}</span> sources</span>
        <span class="card-stat"><span class="stat-num">${domain.unique_ips}</span> IPs</span>
        <span class="card-stat"><span class="stat-num">${domain.wildcard_count}</span> wildcards</span>
      </div>
      <div class="card-contributor">submitted by ${escapeHtml(domain.display_name)} · ${escapeHtml(domain.display_loc)}</div>
    `;

    card.addEventListener('click', function () {
      window.location.href = 'domain.html?d=' + encodeURIComponent(domain.domain);
    });

    return card;
  }

  function escapeHtml(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function sortDomains(domains) {
    return domains.slice().sort(function (a, b) {
      if (b.subdomain_count !== a.subdomain_count) {
        return b.subdomain_count - a.subdomain_count;
      }
      return a.domain.localeCompare(b.domain);
    });
  }

  function renderDomains(domains) {
    const list = document.getElementById('domain-list');
    const countEl = document.getElementById('search-count');
    list.innerHTML = '';

    const sorted = sortDomains(domains);

    sorted.forEach(function (domain) {
      list.appendChild(buildCard(domain));
    });

    if (countEl) {
      countEl.textContent = sorted.length + ' domain' + (sorted.length !== 1 ? 's' : '');
    }
  }

  function showError(msg) {
    const box = document.getElementById('error-box');
    const msgEl = document.getElementById('error-message');
    if (msgEl) msgEl.textContent = msg;
    if (box) box.style.display = 'block';
  }

  function updateStats(data) {
    const statsEl = document.getElementById('sr-stats');
    if (!statsEl) return;

    const domainCount = data.total_domains || (data.domains ? data.domains.length : 0);
    const subCount = (data.domains || []).reduce(function (sum, d) {
      return sum + (d.subdomain_count || 0);
    }, 0);

    statsEl.textContent =
      domainCount + ' domain' + (domainCount !== 1 ? 's' : '') +
      ' · ' +
      subCount + ' subdomains indexed';
  }

  function applySearch(query) {
    if (!query || !query.trim()) {
      renderDomains(allDomains);
      return;
    }
    const q = query.trim().toLowerCase();
    const filtered = allDomains.filter(function (d) {
      return d.domain.toLowerCase().indexOf(q) !== -1;
    });
    renderDomains(filtered);
  }

  document.addEventListener('DOMContentLoaded', function () {
    fetch('data/index.json')
      .then(function (res) {
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.json();
      })
      .then(function (data) {
        allDomains = data.domains || [];
        updateStats(data);
        renderDomains(allDomains);

        const searchInput = document.getElementById('search-input');
        if (searchInput) {
          searchInput.addEventListener('keyup', function () {
            applySearch(searchInput.value);
          });
          searchInput.addEventListener('input', function () {
            applySearch(searchInput.value);
          });
        }
      })
      .catch(function () {
        showError('Failed to load registry data.');
      });
  });
})();
