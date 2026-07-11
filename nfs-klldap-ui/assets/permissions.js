// ===== Detached "Share Permissions" panel behaviour =====
// Everything is module-private except window.PermUI, the surface the index page
// script and Rust-built fragments (Apply Log cancel button) are allowed to call.
(function () {
    'use strict';

    // Single source of truth for panel state — never read back out of DOM text.
    const state = {
        shareName: '',    // set via PermUI.setShare() when a share card is picked
        currentPath: '',  // directory currently shown in the panel
        applying: false,  // a POSIX apply is in flight (locks navigation)
        dirty: false,     // unsaved edits while in edit mode (gates Cancel)
    };

    const panel = () => document.getElementById('perm-panel');
    const pbody = () => panel() && panel().querySelector('.perm-body');
    const isEditing = () => !!(panel() && panel().classList.contains('editing'));

    // Selection lock: edit mode OR an in-flight apply blocks navigating to another dir/share.
    const isLocked = () => isEditing() || state.applying;
    function flashLock() {
        const b = document.getElementById('edit-lock-banner');
        if (!b) return;
        b.classList.add('flash');
        setTimeout(() => b.classList.remove('flash'), 500);
    }
    function setTreeLock(on) {
        const tree = document.getElementById('tree-root');
        if (tree) tree.classList.toggle('perm-locked', on);
        document.querySelectorAll('.shares-host').forEach(s => s.classList.toggle('perm-locked', on));
        let banner = document.getElementById('edit-lock-banner');
        if (on && !banner) {
            banner = document.createElement('div');
            banner.id = 'edit-lock-banner';
            banner.className = 'edit-lock-banner';
            banner.textContent = 'Editing — directory selection is locked. Cancel or Apply to change directory.';
            const title = document.getElementById('current-share-title');
            if (title && title.parentNode) title.parentNode.insertBefore(banner, title);
        } else if (!on && banner) { banner.remove(); }
    }

    // Apply Log grows with the panel: cap its height at 90% of the Permissions panel's height.
    function syncApplyLogHeight() {
        const pl = panel();
        const log = document.querySelector('#apply-status .apply-log-content');
        if (pl && log) log.style.maxHeight = Math.round(pl.offsetHeight * 0.9) + 'px';
    }
    function initApplyLogAutosize() {
        syncApplyLogHeight();
        if (window.ResizeObserver && panel()) new ResizeObserver(syncApplyLogHeight).observe(panel());
    }
    window.addEventListener('resize', syncApplyLogHeight);

    // Clear the hidden numeric uid/gid when the visible owner/group name is edited by hand, so
    // Apply re-resolves the typed name via LDAP (matches the old inline editor's translation).
    function attachEditorInputListeners(root) {
        if (!root) return;
        root.querySelectorAll('input[name="owner_user"], input[name="owner_group"]').forEach(inp => {
            if (inp.dataset.clrWired) return;
            inp.dataset.clrWired = '1';
            inp.addEventListener('input', () => {
                const hidden = inp.name === 'owner_user'
                    ? root.querySelector('input[name="owner_user_uid"]')
                    : root.querySelector('input[name="owner_group_gid"]');
                if (hidden) hidden.value = '';
            });
        });
    }

    // Foreground busy state for the panel: dim the body, spin, announce via the state chip.
    function setPanelLoading(on) {
        const pl = panel(); if (!pl) return;
        pl.classList.toggle('loading', on);
        const busy = pl.querySelector('.perm-busy'); if (busy) busy.hidden = !on;
        pl.querySelector('.perm-state').textContent =
            on ? 'loading' : (pl.classList.contains('editing') ? 'editing' : 'viewing');
    }

    // Load the panel body (view mode) for a selected directory.
    function loadDirPerms(path) {
        if (!panel()) return;
        panel().classList.remove('editing');
        setPanelLoading(true);
        htmx.ajax('GET', '/dir-perms?path=' + encodeURIComponent(path),
            { target: '#perm-panel .perm-body', swap: 'innerHTML' }).then(() => {
                state.currentPath = path;
                const pl = panel();
                pl.querySelector('.perm-share').textContent = state.shareName;
                pl.querySelector('.perm-path').textContent = path;
                setPanelLoading(false);
                setPanelMode(false);
                recomputeMode();
                attachEditorInputListeners(pbody());
                syncApplyLogHeight();
            });
    }

    // Button/field visibility for edit mode is CSS-driven off the .editing class.
    // On a Non-ACL directory (.acl-sec.disabled) the ACL entries stay inert even in
    // edit mode: pointer-events only blocks the mouse, not keyboard focus.
    function setPanelMode(editing) {
        const pl = panel(); if (!pl) return;
        pl.classList.toggle('editing', editing);
        pl.querySelector('.perm-state').textContent = editing ? 'editing' : 'viewing';
        const aclInert = !!pl.querySelector('.acl-sec.disabled');
        pl.querySelectorAll('.p-owner,.p-group,.pbit,.sbit').forEach(el => el.disabled = !editing);
        pl.querySelectorAll('.abit').forEach(el => el.disabled = !editing || aclInert);
        setTreeLock(editing);
    }

    // rwx matrix + setgid/sticky -> live octal + symbolic; keeps the hidden name="mode" field in sync.
    function recomputeMode() {
        const pl = panel(); if (!pl) return;
        const oct = pl.querySelector('.octal'); if (!oct) return;
        const sum = { u: 0, g: 0, o: 0 };
        pl.querySelectorAll('.pbit').forEach(cb => { if (cb.checked) sum[cb.dataset.role] += +cb.dataset.bit; });
        let s = 0;
        pl.querySelectorAll('.sbit').forEach(cb => { if (cb.checked) s += +cb.dataset.special; });
        const octal = '' + s + sum.u + sum.g + sum.o;
        oct.textContent = octal;
        const field = pl.querySelector('.mode-field'); if (field) field.value = octal;
        const sym = pl.querySelector('.symbolic'); if (sym) sym.textContent = symbolicMode(s, sum.u, sum.g, sum.o);
    }
    function symbolicMode(s, u, g, o) {
        const trip = (b, kind) => {
            const r = (b & 4) ? 'r' : '-', w = (b & 2) ? 'w' : '-';
            let x;
            if (kind === 'g') x = (s & 2) ? ((b & 1) ? 's' : 'S') : ((b & 1) ? 'x' : '-');
            else if (kind === 'o') x = (s & 1) ? ((b & 1) ? 't' : 'T') : ((b & 1) ? 'x' : '-');
            else x = (b & 1) ? 'x' : '-';
            return r + w + x;
        };
        return trip(u, 'u') + trip(g, 'g') + trip(o, 'o');
    }

    // Native cancel for the Apply Log button (works during a long apply).
    function cancelCurrentApply() {
        fetch('/cancel-apply', { method: 'POST', credentials: 'include' }).catch(() => {});
    }

    // Hidden htmx poller that drives live #apply-status oob updates while an apply runs.
    // htmx 1.9 only ends an `every ...` poll loop when the element leaves the DOM or the
    // server answers 286 — removing hx-trigger does nothing, and a cancelled element stays
    // dead even if re-processed. So stop removes the element; start always builds a fresh one.
    let applyPollerEl = null;
    function startApplyProgressPoller() {
        stopApplyProgressPoller();
        applyPollerEl = document.createElement('div');
        applyPollerEl.id = 'apply-poller';
        applyPollerEl.style.display = 'none';
        applyPollerEl.setAttribute('hx-get', '/apply-progress');
        applyPollerEl.setAttribute('hx-trigger', 'every 350ms');
        applyPollerEl.setAttribute('hx-swap', 'none');
        document.body.appendChild(applyPollerEl);
        if (window.htmx) htmx.process(applyPollerEl);
    }
    function stopApplyProgressPoller() {
        if (applyPollerEl) { applyPollerEl.remove(); applyPollerEl = null; }
        const stray = document.getElementById('apply-poller');
        if (stray) stray.remove();
    }

    // Inline red note at the top of the panel body (or the Apply Log if the body is gone).
    function showPermPanelError(msg) {
        const host = pbody() || document.getElementById('apply-status-content');
        if (!host) return;
        let box = host.querySelector('.perm-inline-error');
        if (!box) {
            box = document.createElement('div');
            box.className = 'alert alert-danger alert-compact perm-inline-error';
            host.prepend(box);
        }
        box.textContent = msg;
    }

    // POST an ACL add/delete to /acl-apply, then refresh the panel; the poller delivers the
    // async setfacl result to the Apply Log and self-terminates on the finished (286) response.
    function aclApply(fields) {
        const pl = panel(); if (!pl || !state.currentPath) return;
        const fd = new URLSearchParams(Object.assign({ path: state.currentPath }, fields));
        fetch('/acl-apply', { method: 'POST', credentials: 'include',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: fd.toString() })
            .then(res => {
                if (!res.ok) throw new Error(String(res.status));
                startApplyProgressPoller();
                loadDirPerms(state.currentPath);
            })
            .catch(err => {
                pl.querySelectorAll('.acl-del:disabled,.acl-add-btn:disabled')
                    .forEach(b => b.disabled = false);
                showPermPanelError(err && err.message === '422'
                    ? 'ACL apply rejected — could not resolve that user/group in LLDAP.'
                    : 'ACL apply failed — the server rejected the request. See server logs.');
            });
    }

    // Live LDAP suggestions for the ACL "add user/group" field (parallels the owner/group search).
    function wireAclAddSearch(box) {
        const type = box.dataset.type;
        const inp = box.querySelector('.acl-add-name');
        const sugg = box.querySelector('.acl-sugg');
        if (!inp || !sugg || inp.dataset.wired) return;
        inp.dataset.wired = '1';
        let tmr = null;
        inp.addEventListener('input', () => {
            delete inp.dataset.pickId;
            clearTimeout(tmr);
            const q = inp.value.trim();
            if (!q) { sugg.innerHTML = ''; return; }
            tmr = setTimeout(() => {
                const url = type === 'user'
                    ? '/users/search?owner_user=' + encodeURIComponent(q)
                    : '/groups/search?owner_group=' + encodeURIComponent(q);
                fetch(url, { credentials: 'include' }).then(r => r.text()).then(html => {
                    sugg.innerHTML = html;
                    sugg.querySelectorAll('.suggestion').forEach(s => {
                        if (!s.dataset.uid && !s.dataset.gid) return; // note rows aren't pickable
                        s.onclick = (ev) => {
                            ev.stopPropagation();
                            inp.dataset.pickId = s.dataset.uid || s.dataset.gid || '';
                            inp.value = (s.textContent || '').trim();
                            sugg.innerHTML = '';
                        };
                    });
                }).catch(() => {});
            }, 180);
        });
    }

    // ===== Delegated clicks: tree expand/select, panel edit/cancel/apply, ACL collapse/add/del =====
    document.addEventListener('click', function (e) {
        // Caret button: expand/collapse ONLY (lazy 1-level fetch on first expand).
        const caret = e.target.closest('#tree-root .dir-caret');
        if (caret) {
            if (isLocked()) { flashLock(); e.stopPropagation(); return; }
            const dir = caret.closest('.dir');
            let sib = dir && dir.nextElementSibling;
            while (sib && !sib.classList.contains('children')) sib = sib.nextElementSibling;
            if (!sib) return;
            if (caret.getAttribute('aria-expanded') === 'true') {
                sib.style.display = 'none';
                caret.textContent = '▶';
                caret.setAttribute('aria-expanded', 'false');
            } else {
                sib.style.display = '';
                caret.setAttribute('aria-expanded', 'true');
                if (sib.dataset.loaded !== 'true') {
                    sib.dataset.loaded = 'true';
                    caret.classList.add('busy');
                    caret.textContent = '⋯';
                    htmx.ajax('GET', '/tree?path=' + encodeURIComponent(dir.dataset.path),
                        { target: sib, swap: 'innerHTML' }).then(() => {
                            caret.classList.remove('busy');
                            caret.textContent = '▼';
                        });
                } else {
                    caret.textContent = '▼';
                }
            }
            return;
        }
        // Label (or row): select the directory and load its permissions — never toggles expansion.
        const dir = e.target.closest('#tree-root .dir');
        if (dir && dir.dataset.path) {
            if (isLocked()) { flashLock(); e.stopPropagation(); return; }
            if (!dir.classList.contains('selected')) {
                document.querySelectorAll('#tree-root .dir.selected').forEach(d => d.classList.remove('selected'));
                dir.classList.add('selected');
                loadDirPerms(dir.dataset.path);
            }
            return;
        }

        const pl = panel(); if (!pl) return;
        if (e.target.closest('.btn-edit')) {
            state.dirty = false;
            setPanelMode(true);
            pl.querySelectorAll('.acl-add').forEach(wireAclAddSearch);
            attachEditorInputListeners(pbody());
            return;
        }
        if (e.target.closest('.btn-cancel')) {
            if (state.dirty && !confirm('Discard unsaved permission changes?')) return;
            state.dirty = false;
            if (state.currentPath) loadDirPerms(state.currentPath);
            return;
        }
        if (e.target.closest('.btn-apply')) {
            const form = pl.querySelector('form.posix-sec');
            if (!form) return;
            const rec = pl.querySelector('.rec-box');
            const recField = form.querySelector('.rec-field');
            if (recField) recField.value = (rec && rec.checked) ? 'true' : 'false';
            if (rec && rec.checked
                && !confirm('Recursively apply owner and mode to EVERYTHING under\n' + state.currentPath + ' ?')) return;
            state.dirty = false;
            state.applying = true;
            htmx.trigger(form, 'submit');
            // Leave edit mode visually (CSS hides the edit controls) but keep the
            // tree locked until the apply finishes.
            pl.classList.remove('editing');
            pl.querySelector('.perm-state').textContent = 'viewing';
            setTreeLock(true);
            return;
        }
        const head = e.target.closest('.acl-grp-head');
        if (head) {
            const grp = head.closest('.acl-grp');
            grp.classList.toggle('collapsed');
            head.setAttribute('aria-expanded', grp.classList.contains('collapsed') ? 'false' : 'true');
            return;
        }

        const del = e.target.closest('.acl-del');
        if (del) {
            const row = del.closest('.acl-row');
            del.disabled = true; // re-enabled by aclApply's error path; success replaces the DOM
            aclApply({ op: 'delete', typ: row.dataset.type,
                       selected: (row.dataset.type === 'group' ? 'g:' : 'u:') + row.dataset.id });
            return;
        }

        const add = e.target.closest('.acl-add-btn');
        if (add) {
            const box = add.closest('.acl-add');
            const nameInp = box.querySelector('.acl-add-name');
            const name = nameInp.value.trim();
            const perms = box.querySelector('.acl-add-perms').value.trim() || 'r--';
            if (!name) return;
            const idm = name.match(/(\d+)/);
            add.disabled = true; // re-enabled by aclApply's error path; success replaces the DOM
            aclApply({ op: 'add', typ: box.dataset.type,
                       id: nameInp.dataset.pickId || (idm ? idm[1] : ''), name: name, perms: perms });
            return;
        }
    });

    // Live octal readout while toggling the matrix / special bits.
    // The panel always targets a DIRECTORY, where read implies execute
    // (Ganesha lists r-without-x directories as EMPTY — readdir attributes
    // need R+X on the dir). Checking r therefore auto-checks x for the same
    // audience; the server normalizes directory modes the same way.
    document.addEventListener('change', function (e) {
        if (!e.target.classList) return;
        if (e.target.classList.contains('pbit')) {
            const cb = e.target;
            if (cb.checked && +cb.dataset.bit === 4) {
                const pl = cb.closest('.perm-body, form') || document;
                pl.querySelectorAll('.pbit').forEach(other => {
                    if (other.dataset.role === cb.dataset.role && +other.dataset.bit === 1)
                        other.checked = true;
                });
            }
            recomputeMode();
        } else if (e.target.classList.contains('sbit')) {
            recomputeMode();
        }
    });

    // Mark unsaved edits. ACL quick-add fields are excluded: those apply immediately
    // via /acl-apply, so text typed there is never "unsaved" POSIX state.
    function markDirtyIfEditing(e) {
        const t = e.target;
        if (!isEditing() || !t || !t.closest) return;
        if (!t.closest('#perm-panel') || t.closest('.acl-add')) return;
        state.dirty = true;
    }
    document.addEventListener('input', markDirtyIfEditing);
    document.addEventListener('change', markDirtyIfEditing);

    // ===== Suggestion dropdown selection (owner/group search) + outside-click dismiss =====
    document.addEventListener('click', function (evt) {
        const suggestion = evt.target.closest('.suggestion');
        if (!suggestion) return;
        const suggBox = suggestion.closest('.suggestions');
        if (suggBox && suggBox.classList.contains('acl-sugg')) return; // handled in wireAclAddSearch
        const container = suggestion.closest('form, .perm-body') || document;
        const userId = suggestion.dataset.userId;
        if (userId) {
            const uid = parseInt(suggestion.dataset.uid || '0', 10);
            const label = (suggestion.textContent || '').trim();
            const nameInput = container.querySelector('input[name="owner_user"]');
            const uidInput  = container.querySelector('input[name="owner_user_uid"]');
            if (nameInput) nameInput.value = label || userId;
            // uid 0 (nobody) is a real id — `uid || ''` would drop it.
            if (uidInput)  uidInput.value = Number.isFinite(uid) ? String(uid) : '';
            if (suggBox) suggBox.innerHTML = '';
            return;
        }
        const groupId = suggestion.dataset.groupId;
        if (groupId) {
            const gid = parseInt(suggestion.dataset.gid || '0', 10);
            const label = (suggestion.textContent || '').trim();
            const nameInput = container.querySelector('input[name="owner_group"]');
            const gidInput  = container.querySelector('input[name="owner_group_gid"]');
            if (nameInput) nameInput.value = label || groupId;
            // gid 0 (nobody) is a real id — `gid || ''` would drop it.
            if (gidInput)  gidInput.value = Number.isFinite(gid) ? String(gid) : '';
            if (suggBox) suggBox.innerHTML = '';
        }
    });
    document.addEventListener('click', function (evt) {
        const t = evt.target;
        if (t.closest('.suggestions') ||
            t.closest('input[name="owner_user"], input[name="owner_group"], .acl-add-name')) return;
        document.querySelectorAll('.suggestions').forEach(el => { if (el.innerHTML.trim()) el.innerHTML = ''; });
    }, true);
    document.addEventListener('focusout', function (evt) {
        const input = evt.target;
        if (!input || !input.matches || !input.matches('input[name="owner_user"], input[name="owner_group"], .acl-add-name')) return;
        setTimeout(() => {
            const active = document.activeElement;
            const wrap = input.closest('label, .acl-add');
            const box = wrap ? wrap.querySelector('.suggestions') : null;
            if (box && (!active || (active !== input && !box.contains(active)))) box.innerHTML = '';
        }, 120);
    });

    // ===== Apply lifecycle: /apply placeholder -> poller -> finish refetch of /dir-perms =====
    document.addEventListener('htmx:afterSwap', function (evt) {
        const t = evt.detail && evt.detail.target;
        if (!t || !t.closest || !t.closest('#perm-panel .perm-body')) return;
        recomputeMode();
        if (t.querySelector('[data-applying]')) {
            state.applying = true;
            setTreeLock(true);
            startApplyProgressPoller();
        } else if (state.applying) {
            // Apply returned without a placeholder (e.g. LDAP resolve error): unlock.
            state.applying = false;
            setTreeLock(false);
        }
    });
    document.addEventListener('htmx:afterOnLoad', function (evt) {
        const elt = evt.detail && evt.detail.elt;
        if (!elt || elt.id !== 'apply-poller') return;
        const xhr = evt.detail.xhr;
        const txt = (xhr && xhr.responseText) || '';
        if (txt.indexOf('data-apply-finished="true"') === -1) return;
        stopApplyProgressPoller();
        // A stale finished marker (an in-flight poll racing the stop, or an ACL op's
        // log-only poll) must not touch the panel or the tree lock.
        const ph = document.querySelector('#perm-panel [data-applying]');
        if (!state.applying && !ph) return;
        state.applying = false;
        const path = ph ? ph.dataset.path : state.currentPath;
        setTreeLock(false);
        if (path) loadDirPerms(path);
    });
    // A failed request (non-2xx or network error) must never strand the UI locked: if an
    // apply was in flight, stop polling, unlock, and say so; otherwise just surface a note
    // for requests that live inside the permissions panel (search, dir-perms, ...).
    function handleApplyRequestError(evt) {
        const elt = evt.detail && evt.detail.elt;
        const isPoller = !!(elt && elt.id === 'apply-poller');
        setPanelLoading(false);
        if (state.applying || isPoller) {
            stopApplyProgressPoller();
            state.applying = false;
            setPanelMode(false);
            showPermPanelError('Apply failed — the server returned an error. Check the service logs; the permissions may not have been changed.');
            return;
        }
        if (elt && elt.closest && elt.closest('#perm-panel')) {
            showPermPanelError('Request failed — the server returned an error.');
        }
    }
    document.addEventListener('htmx:responseError', handleApplyRequestError);
    document.addEventListener('htmx:sendError', handleApplyRequestError);
    // Each apply-status oob swap replaces .apply-log-content, dropping its inline cap — re-apply it.
    document.addEventListener('htmx:oobAfterSwap', syncApplyLogHeight);

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initApplyLogAutosize);
    } else {
        initApplyLogAutosize();
    }

    // Public surface: index.html's page script and the Apply Log cancel button.
    window.PermUI = {
        isLocked,
        flashLock,
        loadDirPerms,
        cancelCurrentApply,
        setShare(name) { state.shareName = name || ''; },
    };
})();
