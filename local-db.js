// מצב מקומי: כשאין עדיין מסד נתונים מחובר (config.js ריק), האפליקציה שומרת הכול במכשיר (IndexedDB) –
// ביקורות, ליקויים, תמונות וחתימות. ממשק זהה לחלק של Supabase שהאפליקציה משתמשת בו,
// כך שבהמשך מספיק למלא את config.js בפרטי מסד הנתונים החדש והכול עובר לשרת.
(function () {
  const DBN = 'ogmar96-local', ST = 'kv';
  let dbp = null;
  const open = () => dbp || (dbp = new Promise((res, rej) => {
    const r = indexedDB.open(DBN, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(ST);
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
  }));
  const tx = async (mode, fn) => { const db = await open(); return new Promise((res, rej) => { const t = db.transaction(ST, mode); const s = t.objectStore(ST); const out = fn(s); t.oncomplete = () => res(out instanceof IDBRequest ? out.result : undefined); t.onerror = () => rej(t.error); }); };
  const get = k => tx('readonly', s => s.get(k));
  const put = (k, v) => tx('readwrite', s => { s.put(v, k); });
  const del = k => tx('readwrite', s => { s.delete(k); });

  const UID = 'local-user';
  const ME = { id: UID, email: 'local@device', full_name: 'מבקר (מצב מקומי)', role: 'מנהל המערכת', is_admin: true, active: true };
  const rows = async t => { let r = await get('t:' + t); if (!r && t === 'profiles') { r = [ME]; await put('t:profiles', r); } return r || []; };
  const saveRows = (t, r) => put('t:' + t, r);
  const ok = data => ({ data, error: null });

  class Q {
    constructor(t) { this.t = t; this.op = 'select'; this.f = []; this.lim = null; this.ord = null; this.single = false; this.ret = false; }
    select() { if (this.op === 'select') this.op = 'select'; else this.ret = true; return this; }
    eq(k, v) { this.f.push([k, v]); return this; }
    order(k, o) { this.ord = [k, !(o && o.ascending === false)]; return this; }
    limit(n) { this.lim = n; return this; }
    maybeSingle() { this.single = true; return this; }
    single_() { this.single = true; return this; }
    upsert(v, o) { this.op = 'upsert'; this.val = Array.isArray(v) ? v : [v]; this.opt = o || {}; return this; }
    insert(v) { return this.upsert(v, { ignoreDuplicates: true }); }
    update(v) { this.op = 'update'; this.val = v; return this; }
    delete() { this.op = 'delete'; return this; }
    match(r) { return this.f.every(([k, v]) => r[k] === v); }
    async run() {
      let all = await rows(this.t); const n = new Date().toISOString();
      if (this.op === 'select') {
        let r = all.filter(x => this.match(x));
        if (this.ord) { const [k, asc] = this.ord; r.sort((a, b) => String(a[k]).localeCompare(String(b[k])) * (asc ? 1 : -1)); }
        if (this.lim) r = r.slice(0, this.lim);
        return ok(this.single ? (r[0] || null) : r.map(x => JSON.parse(JSON.stringify(x))));
      }
      if (this.op === 'upsert') {
        const out = [];
        for (const v of this.val) {
          const i = all.findIndex(x => x.id === v.id);
          if (i >= 0) { if (this.opt.ignoreDuplicates) continue; all[i] = Object.assign({}, all[i], v, { updated_at: n }); out.push(all[i]); }
          else { const r = Object.assign({ created_at: n, updated_at: n }, v); all.push(r); out.push(r); }
        }
        await saveRows(this.t, all); return ok(out);
      }
      if (this.op === 'update') {
        const out = []; all = all.map(x => { if (!this.match(x)) return x; const r = Object.assign({}, x, this.val, { updated_at: n }); out.push(r); return r; });
        await saveRows(this.t, all); return ok(out);
      }
      if (this.op === 'delete') {
        const out = all.filter(x => this.match(x)); await saveRows(this.t, all.filter(x => !this.match(x))); return ok(out);
      }
    }
    then(a, b) { return this.run().then(a, b); }
  }
  const urls = {};
  const bucket = {
    async upload(path, blob) { await put('f:' + path, blob); return ok({ path }); },
    async download(path) { const b = await get('f:' + path); return b ? ok(b) : { data: null, error: { message: 'התמונה לא נמצאה במכשיר' } }; },
    async remove(paths) { for (const p of paths) { await del('f:' + p); if (urls[p]) { URL.revokeObjectURL(urls[p]); delete urls[p]; } } return ok(paths); },
    async createSignedUrl(path) { const r = await this.createSignedUrls([path]); return ok({ signedUrl: r.data[0] && r.data[0].signedUrl }); },
    async createSignedUrls(paths) {
      const out = [];
      for (const p of paths) { if (!urls[p]) { const b = await get('f:' + p); if (b) urls[p] = URL.createObjectURL(b); } if (urls[p]) out.push({ path: p, signedUrl: urls[p] }); }
      return ok(out);
    }
  };
  const session = { user: { id: UID, email: ME.email } };
  window.LocalDB = {
    isLocal: true,
    from: t => new Q(t),
    rpc: async () => ok([]),
    channel: () => ({ on() { return this; }, subscribe() { return this; } }),
    storage: { from: () => bucket },
    auth: {
      onAuthStateChange() { return { data: { subscription: { unsubscribe() { } } } }; },
      getSession: async () => ok({ session }),
      signOut: async () => ok(null),
      signInWithPassword: async () => ok({ session }),
      signUp: async () => ok({ session }),
      resetPasswordForEmail: async () => ok({}),
      updateUser: async () => ok({ user: session.user })
    }
  };
})();
