(function () {
  // The Hub clock is the reference for "last report" and the footer clock;
  // the browser clock may differ.
  var skew = Number(document.body.dataset.now || 0) - Math.floor(Date.now() / 1000);
  var tbody = document.getElementById('host-rows');
  var search = document.getElementById('search');
  var nomatch = document.getElementById('nomatch');
  var clock = document.getElementById('clock');
  var dialog = document.getElementById('enroll-dialog');
  var conn = document.getElementById('conn');
  var svcDialog = document.getElementById('service-dialog');
  var svcList = document.getElementById('svc-list');

  // A form refused with 422 comes back with its message; show it.
  if (window.htmx) htmx.config.responseHandling.unshift({ code: '422', swap: true });

  function unit(n, word) { return n + ' ' + word + (n === 1 ? '' : 's') + ' ago'; }
  function ago(s) {
    if (s < 60) return unit(s, 'second');
    if (s < 3600) return unit(Math.floor(s / 60), 'minute');
    if (s < 86400) return unit(Math.floor(s / 3600), 'hour');
    return unit(Math.floor(s / 86400), 'day');
  }
  function pad(n) { return String(n).padStart(2, '0'); }
  function hm(d) { return pad(d.getHours()) + ':' + pad(d.getMinutes()); }
  function tick() {
    var now = Math.floor(Date.now() / 1000) + skew;
    document.querySelectorAll('[data-ts]').forEach(function (el) {
      var ts = Number(el.dataset.ts);
      el.textContent = ts ? ago(Math.max(0, now - ts)) : 'never';
    });
    // How long a state has lasted: "for 8 minutes".
    document.querySelectorAll('[data-for]').forEach(function (el) {
      var ts = Number(el.dataset.for);
      el.textContent = ts ? 'for ' + ago(Math.max(0, now - ts)).replace(/ ago$/, '') : '';
    });
    if (clock) {
      var d = new Date(now * 1000);
      clock.textContent = d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + hm(d) + ':' + pad(d.getSeconds());
    }
  }

  // Times of alerts and log lines are printed in the viewer's time zone.
  function stamp() {
    document.querySelectorAll('[data-time]').forEach(function (el) {
      var d = new Date(Number(el.dataset.time) * 1000);
      el.textContent = d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) + ' ' + hm(d) + (el.dataset.secs ? ':' + pad(d.getSeconds()) : '');
      el.title = d.toLocaleString();
    });
  }
  // The menu is replaced by live updates, so the current page is marked again.
  function markNav() {
    var here = document.querySelector('.side [data-nav="' + document.body.dataset.page + '"]');
    if (here) here.setAttribute('aria-current', 'page');
  }

  // Host list: sorting. Column 0 ascending is the order the server sends.
  var sortCol = 0, sortDir = 1;
  function applySort() {
    if (!tbody) return;
    var head = document.querySelectorAll('.hosts thead th')[sortCol];
    var numeric = head.querySelector('.sort').dataset.type === 'num';
    var rows = Array.prototype.slice.call(tbody.rows);
    var sorted = rows.slice().sort(function (a, b) {
      var x = a.cells[sortCol].dataset.v || '', y = b.cells[sortCol].dataset.v || '';
      // Rows without a value go last in both directions.
      if (x === '' || y === '') return x === y ? 0 : (x === '' ? 1 : -1);
      var c = numeric ? Number(x) - Number(y) : x.localeCompare(y, undefined, { sensitivity: 'base', numeric: true });
      return c * sortDir;
    });
    var changed = sorted.some(function (r, i) { return r !== rows[i]; });
    if (changed) sorted.forEach(function (r) { tbody.appendChild(r); });
  }
  if (tbody) {
    document.querySelector('.hosts thead').addEventListener('click', function (e) {
      var btn = e.target.closest('.sort');
      if (!btn) return;
      var th = btn.closest('th');
      sortDir = th.cellIndex === sortCol ? -sortDir : 1;
      sortCol = th.cellIndex;
      document.querySelectorAll('.hosts thead th').forEach(function (h) { h.removeAttribute('aria-sort'); });
      th.setAttribute('aria-sort', sortDir === 1 ? 'ascending' : 'descending');
      applySort();
    });
  }

  // Host list: search filters by host name and by any of the host's addresses.
  function applyFilter() {
    if (!tbody || !search) return;
    var q = search.value.trim().toLowerCase();
    var rows = Array.prototype.slice.call(tbody.rows), shown = 0;
    rows.forEach(function (r) {
      var text = (r.cells[0].textContent + ' ' + r.cells[1].textContent + ' ' + r.cells[1].title).toLowerCase();
      r.hidden = q !== '' && text.indexOf(q) === -1;
      if (!r.hidden) shown++;
    });
    nomatch.hidden = !(q !== '' && rows.length > 0 && shown === 0);
  }
  // Services: search on name, address, group and description; a group
  // without a matching card hides with them.
  function applyCardFilter() {
    if (!svcList || !search) return;
    var q = search.value.trim().toLowerCase(), cards = svcList.querySelectorAll('.svc-card'), shown = 0;
    cards.forEach(function (c) {
      c.hidden = q !== '' && c.dataset.search.indexOf(q) === -1;
      if (!c.hidden) shown++;
    });
    svcList.querySelectorAll('.svc-group').forEach(function (g) {
      g.hidden = !g.querySelector('.svc-card:not([hidden])');
    });
    nomatch.hidden = !(q !== '' && cards.length > 0 && shown === 0);
  }
  if (search) {
    search.addEventListener('input', applyFilter);
    search.addEventListener('input', applyCardFilter);
    document.addEventListener('keydown', function (e) {
      if (e.key === '/' && document.activeElement !== search && !(dialog && dialog.open) && !(svcDialog && svcDialog.open)) {
        e.preventDefault();
        search.focus();
      } else if (e.key === 'Escape' && document.activeElement === search) {
        search.value = '';
        applyFilter();
        applyCardFilter();
        var found = document.getElementById('search-results');
        if (found) found.innerHTML = '';
        search.blur();
      }
    });
  }

  // Charts: the time axis is printed in the viewer's time zone.
  function axisLabel(ts, fmt) {
    var d = new Date(ts * 1000);
    if (fmt === 'md') return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    if (fmt === 'dhm') return d.toLocaleDateString(undefined, { weekday: 'short' }) + ' ' + hm(d);
    return hm(d);
  }
  function labelCharts() {
    document.querySelectorAll('svg.chart').forEach(function (svg) {
      svg.querySelectorAll('.xlab text').forEach(function (t) { t.textContent = axisLabel(Number(t.dataset.t), svg.dataset.fmt); });
    });
  }
  // Charts: crosshair and value under the pointer. Geometry matches chart.go.
  var VW = 420, L = 36, R = 412, T = 12, B = 128;
  function hover(e) {
    var svg = e.target.closest ? e.target.closest('svg.chart') : null;
    document.querySelectorAll('svg.chart.on').forEach(function (s) { if (s !== svg) leave(s); });
    if (!svg) return;
    var pts = svg._pts || (svg._pts = JSON.parse(svg.dataset.points));
    if (!pts.length) return;
    var box = svg.getBoundingClientRect();
    var from = Number(svg.dataset.from), to = Number(svg.dataset.to);
    var vx = (e.clientX - box.left) / box.width * VW;
    var ts = from + (vx - L) / (R - L) * (to - from);
    var best = pts[0];
    for (var i = 1; i < pts.length; i++) if (Math.abs(pts[i][0] - ts) < Math.abs(best[0] - ts)) best = pts[i];
    var px = L + (best[0] - from) / (to - from) * (R - L), py = B - Math.min(Math.max(best[1], 0), 100) / 100 * (B - T);
    var cross = svg.querySelector('.cross'), dot = svg.querySelector('.dot'), tip = svg.parentNode.querySelector('.tip');
    cross.setAttribute('x1', px); cross.setAttribute('x2', px);
    dot.setAttribute('cx', px); dot.setAttribute('cy', py);
    svg.classList.add('on');
    var d = new Date(best[0] * 1000);
    tip.textContent = best[1] + '%  ·  ' + (svg.dataset.fmt === 'hm' ? hm(d) : axisLabel(best[0], 'md') + ' ' + hm(d));
    tip.classList.add('on');
    // SVG elements have no offsetLeft; measure against the figure instead.
    var fig = svg.parentNode.getBoundingClientRect();
    var left = box.left - fig.left + px / VW * box.width;
    tip.style.left = Math.min(Math.max(left, 60), fig.width - 60) + 'px';
  }
  function leave(svg) {
    svg.classList.remove('on');
    var tip = svg.parentNode.querySelector('.tip');
    if (tip) tip.classList.remove('on');
  }
  document.addEventListener('pointermove', hover);
  document.addEventListener('pointerdown', hover);

  // Logs: the console follows new lines like tail -f until the reader scrolls up.
  var consoleBox = document.getElementById('console');
  var following = true;
  function logsTick() {
    if (!consoleBox) return;
    var keep = Number(consoleBox.dataset.keep || 1000);
    while (consoleBox.children.length > keep) consoleBox.removeChild(consoleBox.firstChild);
    var q = document.getElementById('logfilter').value.trim().toLowerCase();
    var only = document.getElementById('problems').checked, reports = document.getElementById('showreports').checked, shown = 0;
    Array.prototype.forEach.call(consoleBox.children, function (l) {
      l.hidden = (only && !l.classList.contains('problem')) || (!reports && l.classList.contains('report')) ||
        (q !== '' && l.lastChild.textContent.toLowerCase().indexOf(q) === -1);
      if (!l.hidden) shown++;
    });
    document.getElementById('lognone').hidden = !(consoleBox.children.length > 0 && shown === 0);
    document.getElementById('logcount').textContent = consoleBox.children.length;
    if (following) consoleBox.scrollTop = consoleBox.scrollHeight;
  }
  if (consoleBox) {
    var follow = document.getElementById('follow'), missed = 0;
    function setFollow(on) {
      following = on;
      missed = 0;
      follow.setAttribute('aria-pressed', on);
      follow.textContent = on ? 'Following' : 'Paused';
      if (on) consoleBox.scrollTop = consoleBox.scrollHeight;
    }
    document.getElementById('logfilter').addEventListener('input', logsTick);
    document.getElementById('problems').addEventListener('change', logsTick);
    // Agent reports are off by default; the choice is kept in this browser.
    var showReports = document.getElementById('showreports');
    try { showReports.checked = localStorage.getItem('fw-logs-reports') === '1'; } catch (e) {}
    showReports.addEventListener('change', function () {
      try { localStorage.setItem('fw-logs-reports', showReports.checked ? '1' : '0'); } catch (e) {}
      logsTick();
    });
    follow.addEventListener('click', function () { setFollow(!following); });
    consoleBox.addEventListener('scroll', function () {
      var atBottom = consoleBox.scrollHeight - consoleBox.scrollTop - consoleBox.clientHeight < 4;
      if (following && !atBottom) setFollow(false);
      else if (!following && atBottom) setFollow(true);
    });
    consoleBox.addEventListener('htmx:sseMessage', function () {
      if (!following) follow.textContent = 'Paused · ' + (++missed) + ' new';
    });
    // Lines written while the stream was down are fetched when it is back.
    document.body.addEventListener('htmx:sseOpen', function () {
      var last = consoleBox.lastElementChild;
      fetch('/logs?after=' + (last ? last.dataset.seq : 0), { headers: { 'HX-Request': 'true' } })
        .then(function (r) { return r.ok ? r.text() : ''; })
        .then(function (html) { if (html) { consoleBox.insertAdjacentHTML('beforeend', html); refresh(); } });
    });
  }

  // Availability blocks: the time range in the viewer's time zone.
  function barTitles() {
    document.querySelectorAll('.avail .blk').forEach(function (b) {
      var from = new Date(Number(b.dataset.from) * 1000), to = new Date(Number(b.dataset.to) * 1000);
      b.title = hm(from) + '–' + hm(to) + ' · ' + (b.dataset.up || 'no checks');
    });
  }
  // On a service's page an edit reloads the page; the list is not there.
  if (document.body.dataset.service) {
    document.body.addEventListener('services-saved', function () { location.reload(); });
  }

  function refresh() { tick(); stamp(); markNav(); applySort(); applyFilter(); applyCardFilter(); labelCharts(); logsTick(); barTitles(); }
  setInterval(tick, 1000);
  refresh();
  document.body.addEventListener('htmx:sseMessage', refresh);
  // The extension only raises events it swaps, so the removal of a server
  // is read from the stream itself: its row goes, and its own page leaves.
  document.body.addEventListener('htmx:sseOpen', function (e) {
    var source = e.detail && e.detail.source;
    if (!source || source._removalHooked) return;
    source._removalHooked = true;
    source.addEventListener('host-removed', function (ev) {
      var row = document.getElementById('host-' + ev.data);
      if (row) row.remove();
      if (document.body.dataset.host === ev.data) location.href = '/hosts';
      refresh();
    });
  });
  document.body.addEventListener('htmx:afterSwap', function (e) {
    if (dialog && e.target.id === 'enroll-body') dialog.showModal();
    // Service dialog: an empty answer means the service was saved.
    if (svcDialog && e.target.id === 'service-body') {
      if (e.target.innerHTML.trim() === '') svcDialog.close();
      else if (!svcDialog.open) svcDialog.showModal();
    }
    refresh();
  });

  if (conn) {
    document.body.addEventListener('htmx:sseError', function () { conn.hidden = false; });
    document.body.addEventListener('htmx:sseOpen', function () { conn.hidden = true; });
  }

  // Usage tooltips: one fixed element, so it can neither be clipped by nor
  // widen a scrolling table. A tap shows it on touch screens; the next tap hides it.
  var tipBox = null, tipFor = null;
  function showTip(cell) {
    if (!tipBox) {
      tipBox = document.createElement('div');
      tipBox.className = 'floattip';
      tipBox.setAttribute('role', 'tooltip');
      document.body.appendChild(tipBox);
    }
    tipFor = cell;
    tipBox.textContent = cell.dataset.tip;
    tipBox.classList.add('on');
    var r = (cell.querySelector('.meter') || cell).getBoundingClientRect(), w = tipBox.offsetWidth, h = tipBox.offsetHeight;
    var top = r.top - h - 6;
    if (top < 4) top = r.bottom + 6;
    tipBox.style.left = Math.min(Math.max(r.left + r.width / 2 - w / 2, 4), window.innerWidth - w - 4) + 'px';
    tipBox.style.top = top + 'px';
  }
  function hideTip() {
    tipFor = null;
    if (tipBox) tipBox.classList.remove('on');
  }
  document.addEventListener('pointerover', function (e) {
    if (e.pointerType !== 'mouse') return;
    var cell = e.target.closest('[data-tip]');
    if (cell) showTip(cell); else if (tipFor) hideTip();
  });
  document.addEventListener('pointerdown', function (e) {
    var cell = e.target.closest('[data-tip]');
    if (e.pointerType === 'mouse') { if (!cell) hideTip(); return; }
    if (cell && cell !== tipFor) showTip(cell); else hideTip();
  });
  window.addEventListener('scroll', hideTip, true);
  // A live update can replace the cell the tooltip points at.
  document.body.addEventListener('htmx:afterSwap', function () { if (tipFor && !tipFor.isConnected) hideTip(); });

  // A row with data-href opens that page, unless a link or button in it was hit.
  document.body.addEventListener('click', function (e) {
    var row = e.target.closest('tr[data-href]');
    if (row && !e.target.closest('a, button, form')) location.href = row.dataset.href;
  });

  document.body.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-copy]');
    if (!btn) return;
    var out = document.getElementById('copy-result');
    function fail() {
      out.textContent = 'Copy failed. Select the command and copy it by hand.';
      out.className = 'bad';
    }
    // navigator.clipboard exists only on https:// and localhost.
    if (!navigator.clipboard) { fail(); return; }
    navigator.clipboard.writeText(document.querySelector(btn.dataset.copy).textContent).then(function () {
      out.textContent = 'Copied.';
      out.className = 'ok';
    }, fail);
  });
  document.addEventListener('click', function (e) {
    if (svcDialog && e.target.closest('[data-close]')) svcDialog.close();
    // A click outside an open card menu closes it.
    document.querySelectorAll('details.svc-menu[open]').forEach(function (d) {
      if (!d.contains(e.target) || e.target.closest('.svc-actions button')) d.open = false;
    });
  });
  document.addEventListener('submit', function (e) {
    var msg = e.target.dataset && e.target.dataset.confirm;
    if (msg && !confirm(msg)) e.preventDefault();
  });
})();
