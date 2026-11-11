/* Hubbo v7 segmentation test-page controller.
 * Identify/track APIs cited from EMBED@1c31aa2 src/utils/identify.ts and event-rules.ts.
 */
(function () {
  'use strict';

  const PRESETS = {
    pro: { id: 'u1', email: '', traits: { plan: 'pro' } },
    free: { id: 'u1', email: '', traits: { plan: 'free' } },
    spoof: { id: 'attacker', email: '', traits: { company: 'AcmeSecretCorp' } },
    enterprise: { id: 'u1', email: '', traits: { plan: 'enterprise' } },
    admin: { id: 'u1', email: '', traits: { role: 'admin' } },
  };

  const $ = (id) => document.getElementById(id);
  const params = new URLSearchParams(location.search);

  function variantFromPath(pathname) {
    const p = '/' + ((pathname.replace(/\/+$/, '').split('/').pop()) || '');
    if (p === '/anonymous' || p === '/anonymous.html' || p === '/anon') return 'anonymous';
    if (p === '/identified' || p === '/identified.html') return 'identified';
    if (p === '/spoofed' || p === '/spoofed.html') return 'spoofed';
    return 'base';
  }

  const variant = variantFromPath(location.pathname);

  function nowStamp() {
    try {
      return new Date().toLocaleString('pl-PL', {
        timeZone: 'Europe/Warsaw',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      }) + ' Europe/Warsaw';
    } catch {
      return new Date().toISOString();
    }
  }

  function truthy(v) {
    if (v == null) return false;
    return ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase());
  }

  function decodeTraits(raw) {
    if (raw == null || raw === '') return null;
    const s = String(raw).trim();
    try {
      if (s.startsWith('{') || s.startsWith('[')) return JSON.parse(s);
    } catch (_) { /* try base64 */ }
    try {
      let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
      const pad = (4 - (b64.length % 4)) % 4;
      if (pad) b64 += '='.repeat(pad);
      const json = new TextDecoder().decode(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
      return JSON.parse(json);
    } catch (err) {
      console.warn('[testsite] could not decode traits', err);
      return null;
    }
  }

  function encodeTraitsParam(obj) {
    const json = JSON.stringify(obj);
    const bytes = new TextEncoder().encode(json);
    let bin = '';
    bytes.forEach((b) => { bin += String.fromCharCode(b); });
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function readHubboStore() {
    try {
      return JSON.parse(localStorage.getItem('hubbo') || '{}') || {};
    } catch {
      return {};
    }
  }

  function storedVisitor() {
    return readHubboStore()['hubbo:visitor'] || null;
  }

  function storedEvents() {
    return readHubboStore().events || {};
  }

  function pretty(v) {
    if (v == null || v === '') return '—';
    if (typeof v === 'string') return v;
    try { return JSON.stringify(v); } catch { return String(v); }
  }

  let config = { key: '' };
  let keySource = 'none';
  let projectKey = '';
  let lastAction = 'page load';
  let lastSent = null; // payload we last handed to identify / boot
  let lastSentAt = null;
  let embedInjected = false;
  let hashWarning = '';

  function projectKeyFromSources() {
    const q = (params.get('key') || '').trim();
    if (q) return { key: q, source: 'query ?key=' };
    const c = (config.key || '').trim();
    if (c) return { key: c, source: 'config.json' };
    return { key: '', source: 'none (embed not injected)' };
  }

  function defaultIdentity() {
    const forced = truthy(params.get('force'));
    if (variant === 'anonymous' && !forced) {
      return null;
    }
    const vid = (params.get('vid') || params.get('id') || '').trim();
    const email = (params.get('email') || '').trim();
    const hash = (params.get('hash') || params.get('userHash') || '').trim();
    const traitsParam = params.get('traits') || params.get('traits_json');
    let traits = decodeTraits(traitsParam);

    if (variant === 'identified') {
      const base = PRESETS.pro;
      return {
        id: vid || base.id,
        email: email || undefined,
        traits: traits && typeof traits === 'object' ? traits : { ...base.traits },
        userHash: hash || undefined,
        autoHash: params.has('auto_hash') ? truthy(params.get('auto_hash')) : true,
      };
    }
    if (variant === 'spoofed') {
      const base = PRESETS.spoof;
      return {
        id: vid || base.id,
        email: email || undefined,
        traits: traits && typeof traits === 'object' ? traits : { ...base.traits },
        userHash: hash || undefined,
        autoHash: params.has('auto_hash') ? truthy(params.get('auto_hash')) : true,
      };
    }
    // base path: identify only when a vid (or traits+vid) is supplied
    if (!vid) return null;
    return {
      id: vid,
      email: email || undefined,
      traits: traits && typeof traits === 'object' ? traits : undefined,
      userHash: hash || undefined,
      autoHash: truthy(params.get('auto_hash')),
    };
  }

  function identityPayload(src) {
    if (!src || !src.id) return null;
    const out = { id: String(src.id).trim() };
    if (!out.id) return null;
    if (src.email) out.email = String(src.email).trim();
    if (src.traits && typeof src.traits === 'object' && !Array.isArray(src.traits)) {
      out.traits = { ...src.traits };
    }
    if (src.userHash) out.userHash = String(src.userHash).trim();
    return out;
  }

  async function fetchHash(userId) {
    const url = 'hash?id=' + encodeURIComponent(userId);
    const res = await fetch(url, { cache: 'no-store' });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(data.error || ('HTTP ' + res.status));
      err.detail = data;
      throw err;
    }
    return data.userHash;
  }

  function fillForm(src) {
    $('f-id').value = src && src.id ? src.id : '';
    $('f-email').value = src && src.email ? src.email : '';
    $('f-traits').value = src && src.traits ? JSON.stringify(src.traits, null, 2) : '';
    $('f-hash').value = src && src.userHash ? src.userHash : '';
  }

  function formIdentity() {
    let traits;
    const raw = $('f-traits').value.trim();
    if (raw) {
      try { traits = JSON.parse(raw); }
      catch (err) { throw new Error('traits JSON is invalid: ' + err.message); }
    }
    return identityPayload({
      id: $('f-id').value,
      email: $('f-email').value,
      traits,
      userHash: $('f-hash').value,
    });
  }

  function setAction(msg) {
    lastAction = msg;
    render();
  }

  function render() {
    $('clock').textContent = nowStamp();
    $('origin-label').textContent = location.origin;
    $('p-origin').textContent = location.origin;
    $('p-path').textContent = location.pathname + location.search;
    $('variant-label').textContent = variant;
    $('variant-chip').textContent = variant;

    $('p-key-source').textContent = keySource;
    $('p-key').textContent = projectKey ? projectKey : '—';
    $('p-sent-at').textContent = lastSentAt || '—';
    $('p-vid').textContent = lastSent && lastSent.id ? lastSent.id : '—';
    $('p-email').textContent = lastSent && lastSent.email ? lastSent.email : '—';
    $('p-hash').textContent = lastSent && lastSent.userHash ? lastSent.userHash : '—';
    $('p-traits').textContent = lastSent && lastSent.traits ? pretty(lastSent.traits) : '—';

    const stored = storedVisitor();
    const ev = storedEvents();
    $('p-stored').textContent = pretty(stored);
    $('p-events').textContent = pretty(ev);

    const api = window.hubbo || window.Hubbo;
    const embedChip = $('embed-chip');
    if (!projectKey) {
      embedChip.textContent = 'embed: no key';
      embedChip.className = 'chip warn';
    } else if (!embedInjected) {
      embedChip.textContent = 'embed: not injected';
      embedChip.className = 'chip warn';
    } else if (!api) {
      embedChip.textContent = 'embed: script injected, API not ready';
      embedChip.className = 'chip warn';
    } else {
      embedChip.textContent = 'embed: window.hubbo ready';
      embedChip.className = 'chip ok';
    }

    const idChip = $('id-chip');
    if (variant === 'anonymous' && !lastSent) {
      idChip.textContent = 'anonymous';
      idChip.className = 'chip';
    } else if (stored && stored.id) {
      const ver = stored.verified === true ? 'verified' : (stored.verified === false ? 'unverified' : 'identified');
      idChip.textContent = ver + ' · ' + stored.id;
      idChip.className = 'chip ok';
    } else if (lastSent && lastSent.id) {
      idChip.textContent = 'boot identify · ' + lastSent.id;
      idChip.className = 'chip warn';
    } else {
      idChip.textContent = 'anonymous';
      idChip.className = 'chip';
    }

    const titles = {
      base: 'Hubbo segmentation test page',
      anonymous: 'Anonymous visitor',
      identified: 'Identified visitor',
      spoofed: 'Spoofed traits',
    };
    const blurbs = {
      base: 'Query-driven host. Identity is applied only when vid / traits are in the URL.',
      anonymous: 'No identify() call. Widget should treat this visitor as logged out.',
      identified: 'Identifies as u1 with traits {plan:"pro"} unless overridden by the query string.',
      spoofed: 'Identifies as attacker with traits {company:"AcmeSecretCorp"} (unsigned traits; HMAC covers userId only).',
    };
    $('page-title').textContent = titles[variant] || titles.base;
    $('page-blurb').textContent = blurbs[variant] || blurbs.base;
    document.title = 'Hubbo v7 · ' + (titles[variant] || titles.base);

    const actionBits = [lastAction];
    if (hashWarning) actionBits.push(hashWarning);
    $('p-action').textContent = actionBits.join(' · ');

    $('raw').textContent = JSON.stringify(
      {
        time: nowStamp(),
        origin: location.origin,
        variant,
        keySource,
        projectKey: projectKey || null,
        sent: lastSent,
        sentAt: lastSentAt,
        storedVisitor: stored,
        events: ev,
        hubboApi: !!api,
      },
      null,
      2,
    );
  }

  function injectEmbed(key) {
    if (embedInjected || !key) return;
    if (document.getElementById('hubbo-embed-script')) {
      embedInjected = true;
      return;
    }
    const s = document.createElement('script');
    s.id = 'hubbo-embed-script';
    s.async = true;
    s.type = 'module';
    s.crossOrigin = 'use-credentials';
    s.src = 'https://api.hubbo.io/embed?key=' + encodeURIComponent(key);
    s.addEventListener('load', () => setAction('embed script loaded'));
    s.addEventListener('error', () => setAction('embed script failed to load'));
    document.body.appendChild(s);
    embedInjected = true;
  }

  async function applyIdentify(payload, label) {
    if (!payload) {
      lastSent = null;
      lastSentAt = nowStamp();
      setAction(label || 'no identity (anonymous)');
      return;
    }
    lastSent = { ...payload };
    lastSentAt = nowStamp();
    const api = window.hubbo || window.Hubbo;
    if (api && typeof api.identify === 'function') {
      try {
        const result = await api.identify(payload);
        setAction((label || 'identify()') + (result && result.id ? ' → ' + result.id : ' → (null / rejected)'));
      } catch (err) {
        setAction('identify() threw: ' + (err && err.message ? err.message : err));
      }
      return;
    }
    // Embed not ready: seed boot identify so installHubboIdentifyApi picks it up
    // (identify.ts:238–241) as soon as the script installs the public API.
    window.__hubboBootIdentify = payload;
    setAction((label || 'identify') + ' queued on window.__hubboBootIdentify');
  }

  function applyReset() {
    lastSent = null;
    lastSentAt = nowStamp();
    hashWarning = '';
    try { delete window.__hubboBootIdentify; } catch (_) { window.__hubboBootIdentify = undefined; }
    const api = window.hubbo || window.Hubbo;
    if (api && typeof api.reset === 'function') {
      api.reset();
      setAction('reset()');
    } else {
      const store = readHubboStore();
      delete store['hubbo:visitor'];
      try { localStorage.setItem('hubbo', JSON.stringify(store)); } catch (_) {}
      setAction('reset (storage only; embed API not ready)');
    }
    fillForm({ id: '', email: '', traits: null, userHash: '' });
  }

  function track(name, times) {
    const n = (name || '').trim();
    const count = times || 1;
    const api = window.hubbo || window.Hubbo;
    if (api && typeof api.track === 'function') {
      for (let i = 0; i < count; i++) api.track(n);
      setAction("track('" + n + "')" + (count > 1 ? ' ×' + count : ''));
      return;
    }
    // Mirror event-rules.ts when the embed is not yet up, so the panel still works.
    const EVENT_KEY = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
    if (!EVENT_KEY.test(n)) {
      setAction("track ignored (invalid name): " + n);
      return;
    }
    const store = readHubboStore();
    const events = store.events && typeof store.events === 'object' ? store.events : {};
    events[n] = Math.min(100000, (Number(events[n]) || 0) + count);
    store.events = events;
    try { localStorage.setItem('hubbo', JSON.stringify(store)); } catch (_) {}
    setAction("track('" + n + "')" + (count > 1 ? ' ×' + count : '') + ' (local, embed API not ready)');
  }

  function withKeyQuery(href) {
    const u = new URL(href, location.origin);
    if (projectKey && !u.searchParams.get('key')) u.searchParams.set('key', projectKey);
    return u.pathname + u.search;
  }

  async function boot() {
    try {
      const res = await fetch('config.json', { cache: 'no-store' });
      if (res.ok) config = await res.json();
    } catch (_) { /* config is optional */ }

    const ks = projectKeyFromSources();
    projectKey = ks.key;
    keySource = ks.source;

    $('link-root').href = withKeyQuery('/');
    $('link-anon').href = withKeyQuery('/anonymous');
    $('link-id').href = withKeyQuery('/identified');
    $('link-spoof').href = withKeyQuery('/spoofed');

    let ident = defaultIdentity();
    if (ident && ident.autoHash && ident.id && !ident.userHash) {
      try {
        ident.userHash = await fetchHash(ident.id);
        hashWarning = '';
      } catch (err) {
        hashWarning = '/hash unavailable (' + (err.message || err) + '); identifying without userHash';
      }
    }

    fillForm(ident || { id: '', email: '', traits: null, userHash: '' });

    if (ident && ident.id) {
      const payload = identityPayload(ident);
      lastSent = payload;
      lastSentAt = nowStamp();
      window.__hubboBootIdentify = payload;
      lastAction = 'boot: window.__hubboBootIdentify set' + (hashWarning ? ' · ' + hashWarning : '');
    } else {
      lastSent = null;
      lastSentAt = nowStamp();
      lastAction = variant === 'anonymous' ? 'boot: anonymous (no identify)' : 'boot: no vid in query';
    }

    if (projectKey) injectEmbed(projectKey);
    render();
  }

  window.addEventListener('hubbo:identify', (ev) => {
    lastSentAt = nowStamp();
    lastSent = ev && ev.detail ? ev.detail : lastSent;
    setAction('event hubbo:identify');
  });
  window.addEventListener('hubbo:reset', () => {
    lastSentAt = nowStamp();
    setAction('event hubbo:reset');
  });
  window.addEventListener('hubbo:identify-rejected', (ev) => {
    const reason = ev && ev.detail && ev.detail.reason ? ev.detail.reason : 'unknown';
    lastSentAt = nowStamp();
    setAction('event hubbo:identify-rejected · ' + reason);
  });

  $('btn-identify').addEventListener('click', async () => {
    try { await applyIdentify(formIdentity(), 'identify()'); }
    catch (err) { setAction(err.message); }
  });
  $('btn-hash-identify').addEventListener('click', async () => {
    try {
      const base = formIdentity();
      if (!base || !base.id) { setAction('id required for /hash'); return; }
      const userHash = await fetchHash(base.id);
      $('f-hash').value = userHash;
      base.userHash = userHash;
      hashWarning = '';
      await applyIdentify(base, 'identify() after /hash');
    } catch (err) {
      hashWarning = String(err.message || err);
      setAction('GET /hash failed: ' + hashWarning);
    }
  });
  $('btn-reset').addEventListener('click', () => applyReset());
  $('btn-preset-pro').addEventListener('click', () => fillForm(PRESETS.pro));
  $('btn-preset-free').addEventListener('click', () => fillForm(PRESETS.free));
  $('btn-preset-spoof').addEventListener('click', () => fillForm(PRESETS.spoof));
  $('btn-track-pv').addEventListener('click', () => track('pricing_view', 1));
  $('btn-track-pv3').addEventListener('click', () => track('pricing_view', 3));
  $('btn-track-custom').addEventListener('click', () => track($('f-event').value, 1));
  $('btn-clear-events').addEventListener('click', () => {
    const store = readHubboStore();
    delete store.events;
    try { localStorage.setItem('hubbo', JSON.stringify(store)); } catch (_) {}
    setAction('cleared events');
  });
  $('btn-refresh').addEventListener('click', () => { setAction('panel refreshed'); });
  $('btn-reload').addEventListener('click', () => location.reload());
  $('btn-clear-hubbo').addEventListener('click', () => {
    try { localStorage.removeItem('hubbo'); } catch (_) {}
    lastSent = null;
    setAction('cleared localStorage.hubbo');
  });

  setInterval(render, 1000);
  boot();
})();
