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
            banner.textContent = 'Editing — directory/file selection is locked. Cancel or Apply to change selection.';
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

    // Shares list caps at the first 5 rendered cards. Measured, not assumed: chips wrap on
    // narrow viewports so card height varies; the CSS --share-card-h calc is only the
    // pre-JS fallback. Cards are server-rendered once, so load + resize cover all changes.
    function sizeSharesHost() {
        const host = document.querySelector('.shares-host');
        if (!host) return; // pages without a shares list (settings, login)
        const cards = Array.from(host.querySelectorAll('.share-card')).slice(0, 5);
        if (!cards.length) return;
        const h = cards.reduce((sum, c) => sum + c.getBoundingClientRect().height, 0);
        host.style.maxHeight = Math.round(h + 6 * (cards.length - 1) + 2) + 'px';
    }
    window.addEventListener('resize', sizeSharesHost);

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
                syncScopeUI();
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
        pl.querySelectorAll('.p-owner,.p-group,.pbit,.sbit,.fbit,.rec-radio').forEach(el => el.disabled = !editing);
        pl.querySelectorAll('.acl-ename,.ebit,.abit,.mbit,.acl-rec-radio').forEach(el => el.disabled = !editing || aclInert);
        if (!editing) {
            pl.querySelectorAll('.acl-row.selected').forEach(r => r.classList.remove('selected'));
            exitAclAdd();
        }
        pl.querySelectorAll('.acl-pane').forEach(syncAclActions);
        setTreeLock(editing);
    }

    // Matrix + setgid/sticky -> live octal + symbolic; keeps the hidden name="mode" field in sync.
    // The SUBMITTED mode is always the raw checkbox sum — x-less on the condensed
    // directory matrix, so recursive applies can never hand files execute. The
    // octal/symbolic READOUT previews the r→x fusion the server performs on the
    // directory itself (fs::dir_mode_r_implies_x, per entry, dirs only).
    function recomputeMode() {
        const pl = panel(); if (!pl) return;
        const oct = pl.querySelector('.octal'); if (!oct) return;
        const form = pl.querySelector('form.posix-sec');
        const isDir = !form || form.dataset.kind !== 'file';
        const sum = { u: 0, g: 0, o: 0 };
        pl.querySelectorAll('.pbit').forEach(cb => { if (cb.checked) sum[cb.dataset.role] += +cb.dataset.bit; });
        let s = 0;
        pl.querySelectorAll('.sbit').forEach(cb => { if (cb.checked) s += +cb.dataset.special; });
        const field = pl.querySelector('.mode-field');
        if (field) field.value = '' + s + sum.u + sum.g + sum.o;
        const fuse = b => b | ((b & 4) >> 2);
        const d = isDir ? { u: fuse(sum.u), g: fuse(sum.g), o: fuse(sum.o) } : sum;
        oct.textContent = '' + s + d.u + d.g + d.o;
        const sym = pl.querySelector('.symbolic'); if (sym) sym.textContent = symbolicMode(s, d.u, d.g, d.o);
        // File-options bits (dir panels, recursive scopes): the explicit file
        // mode composes independently of the directory matrix — no fusing.
        const fsum = { u: 0, g: 0, o: 0 };
        pl.querySelectorAll('.fbit').forEach(cb => { if (cb.checked) fsum[cb.dataset.role] += +cb.dataset.bit; });
        const ffield = pl.querySelector('.file-mode-field');
        if (ffield) ffield.value = '0' + fsum.u + fsum.g + fsum.o;
        const foct = pl.querySelector('.file-octal');
        if (foct) foct.textContent = '0' + fsum.u + fsum.g + fsum.o;
    }

    // Reveal the file-bits editor and its readout only when the chosen apply
    // scope actually touches files ("single" or "all").
    function syncScopeUI() {
        const pl = panel(); if (!pl) return;
        const form = pl.querySelector('form.posix-sec'); if (!form) return;
        const checked = form.querySelector('.rec-radio:checked');
        const scopeNone = !checked || checked.value === 'none';
        const opts = form.querySelector('.file-opts');
        if (opts) opts.hidden = scopeNone;
        const fr = pl.querySelector('.file-mode-readout');
        if (fr) fr.hidden = scopeNone;
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
                pl.querySelectorAll('.acl-pane').forEach(syncAclActions);
                showPermPanelError(err && err.message === '422'
                    ? 'ACL apply rejected — could not resolve that user/group in LLDAP.'
                    : 'ACL apply failed — the server rejected the request. See server logs.');
            });
    }

    // Selection-aware enable state: the Add buttons are always available in
    // edit mode; Remove needs a named selection (the mask can't be removed).
    function syncAclActions(pane) {
        const sel = pane.querySelector('.acl-row.selected');
        pane.querySelectorAll('.acl-act').forEach(b => {
            if (b.dataset.act === 'remove') b.disabled = !sel || sel.dataset.type === 'mask';
            else b.disabled = false;
        });
    }
    function rowPerms(row) {
        return Array.from(row.querySelectorAll('.abit,.mbit'))
            .map(cb => cb.checked ? cb.dataset.ch : '-').join('');
    }
    function addFormPerms(form) {
        return Array.from(form.querySelectorAll('.ebit'))
            .map(cb => cb.checked ? cb.dataset.ch : '-').join('');
    }

    // ===== ACL add mode: Add User / Add Group flow finished by the panel's
    // Apply/Cancel. Everything else in the panel is inert while adding. =====
    function activeAclAddForm() {
        const pl = panel();
        return pl && pl.querySelector('.acl-addform:not([hidden])');
    }
    function syncAclAddApply() {
        const pl = panel(); if (!pl) return;
        const form = activeAclAddForm(); if (!form) return;
        const name = form.querySelector('.acl-ename').value.trim();
        const armed = !!name && addFormPerms(form) !== '---';
        pl.querySelectorAll('.btn-apply').forEach(b => b.disabled = !armed);
    }
    function enterAclAdd(pane, typ) {
        const pl = panel(); if (!pl) return;
        exitAclAdd();
        const form = pane.querySelector('.acl-addform'); if (!form) return;
        form.dataset.typ = typ;
        form.hidden = false;
        const inp = form.querySelector('.acl-ename');
        inp.placeholder = typ === 'group' ? 'group or id' : 'user or id';
        inp.value = ''; delete inp.dataset.pickId;
        pl.classList.add('acl-adding');
        pl.querySelector('.perm-state').textContent =
            typ === 'group' ? 'EDITING - ADDING ACL GROUP' : 'EDITING - ADDING ACL USER';
        wireAclAddSearch(form);
        syncAclAddApply();
        inp.focus();
    }
    function exitAclAdd() {
        const pl = panel(); if (!pl) return;
        pl.classList.remove('acl-adding');
        pl.querySelectorAll('.acl-addform').forEach(f => { f.hidden = true; });
        pl.querySelectorAll('.btn-apply').forEach(b => b.disabled = false);
        const st = pl.querySelector('.perm-state');
        if (st && pl.classList.contains('editing')) st.textContent = 'editing';
    }

    // Live LDAP suggestions for the ACL editor's name field (parallels the
    // owner/group search; the type comes from the pane's User/Group select).
    function wireAclAddSearch(box) {
        const inp = box.querySelector('.acl-ename');
        const sugg = box.querySelector('.acl-sugg');
        if (!inp || !sugg || inp.dataset.wired) return;
        inp.dataset.wired = '1';
        let tmr = null;
        inp.addEventListener('input', () => {
            delete inp.dataset.pickId;
            clearTimeout(tmr);
            syncAclAddApply();
            const q = inp.value.trim();
            if (!q) { sugg.innerHTML = ''; return; }
            tmr = setTimeout(() => {
                const type = box.dataset.typ || 'user';
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
        // Label (or row): select the directory or file and load its permissions —
        // never toggles expansion (file rows have no caret at all).
        const row = e.target.closest('#tree-root .dir, #tree-root .file');
        if (row && row.dataset.path) {
            if (isLocked()) { flashLock(); e.stopPropagation(); return; }
            if (!row.classList.contains('selected')) {
                document.querySelectorAll('#tree-root .dir.selected, #tree-root .file.selected')
                    .forEach(d => d.classList.remove('selected'));
                row.classList.add('selected');
                loadDirPerms(row.dataset.path);
            }
            return;
        }

        const pl = panel(); if (!pl) return;
        if (e.target.closest('.btn-edit')) {
            state.dirty = false;
            setPanelMode(true);
            pl.querySelectorAll('.acl-addform').forEach(wireAclAddSearch);
            attachEditorInputListeners(pbody());
            return;
        }
        if (e.target.closest('.btn-cancel')) {
            if (pl.classList.contains('acl-adding')) { exitAclAdd(); return; }
            if (state.dirty && !confirm('Discard unsaved permission changes?')) return;
            state.dirty = false;
            if (state.currentPath) loadDirPerms(state.currentPath);
            return;
        }
        if (e.target.closest('.btn-apply')) {
            if (pl.classList.contains('acl-adding')) {
                const form = activeAclAddForm(); if (!form) return;
                const pane = form.closest('.acl-pane');
                const inp = form.querySelector('.acl-ename');
                const name = inp.value.trim();
                if (!name || addFormPerms(form) === '---') return;
                const scopeSel = form.querySelector('.acl-rec-radio:checked');
                const scope = scopeSel ? scopeSel.value : 'none';
                if (scope === 'all'
                    && !confirm('Add this ACL entry to EVERYTHING under\n' + state.currentPath + ' (all subdirectories and files)?')) return;
                if (scope === 'single'
                    && !confirm('Add this ACL entry to ' + state.currentPath + ' and every file directly inside it?')) return;
                const idm = name.match(/(\d+)/);
                aclApply({ op: 'add', typ: form.dataset.typ || 'user',
                           layer: pane.dataset.layer, scope: scope,
                           id: inp.dataset.pickId || (idm ? idm[1] : ''), name: name,
                           perms: addFormPerms(form) });
                exitAclAdd();
                return;
            }
            const form = pl.querySelector('form.posix-sec');
            if (!form) return;
            // Scope radios live inside the form (dir panels only) and submit
            // natively; file panels have none, so their scope is always none —
            // the server braces file targets independently.
            const checkedScope = form.querySelector('.rec-radio:checked');
            const scope = checkedScope ? checkedScope.value : 'none';
            if (scope === 'all'
                && !confirm('Recursively apply to EVERYTHING under\n' + state.currentPath + ' (all subdirectories and files)?')) return;
            if (scope === 'single'
                && !confirm('Apply to ' + state.currentPath + ' and every file directly inside it?')) return;
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
        // ACL tab: swap the visible layer pane (Current vs Inherit).
        const tab = e.target.closest('.acl-tab');
        if (tab) {
            const sec = tab.closest('.acl-sec');
            sec.querySelectorAll('.acl-tab').forEach(t => t.classList.toggle('active', t === tab));
            sec.querySelectorAll('.acl-pane').forEach(p => p.hidden = p.dataset.layer !== tab.dataset.layer);
            return;
        }

        // Category header: collapse/expand its row block (list keeps scrolling).
        const cat = e.target.closest('.acl-cat');
        if (cat) {
            cat.classList.toggle('collapsed');
            const rows = cat.nextElementSibling;
            if (rows && rows.classList.contains('acl-cat-rows')) rows.hidden = cat.classList.contains('collapsed');
            return;
        }

        // Action buttons: the Add pair enters add mode (finished by the
        // panel's Apply/Cancel); Remove deletes the selected entry.
        const act = e.target.closest('.acl-act');
        if (act && !act.disabled && !panel().classList.contains('acl-adding')) {
            const pane = act.closest('.acl-pane');
            const layer = pane.dataset.layer;
            if (act.dataset.act === 'add-user') { enterAclAdd(pane, 'user'); return; }
            if (act.dataset.act === 'add-group') { enterAclAdd(pane, 'group'); return; }
            const sel = pane.querySelector('.acl-row.selected');
            if (act.dataset.act === 'remove' && sel) {
                act.disabled = true;
                aclApply({ op: 'delete', typ: sel.dataset.type, layer: layer,
                           selected: (sel.dataset.type === 'group' ? 'g:' : 'u:') + sel.dataset.id });
            }
            return;
        }

        // Row click (edit mode) selects for Remove; checkbox clicks toggle
        // permissions instead (handled by the change listener below).
        const arow = e.target.closest('.acl-row');
        if (arow && isEditing() && !arow.closest('.acl-sec.disabled')
            && !e.target.closest('input') && !panel().classList.contains('acl-adding')) {
            const pane = arow.closest('.acl-pane');
            const was = arow.classList.contains('selected');
            pane.querySelectorAll('.acl-row.selected').forEach(r => r.classList.remove('selected'));
            if (!was) arow.classList.add('selected');
            syncAclActions(pane);
            return;
        }
    });

    // POSIX-style direct toggles: a row checkbox change applies immediately
    // to that node (op=set; the mask row posts op=mask) and the panel reloads
    // from getfacl truth. Add-form checkboxes only re-arm the Apply button.
    document.addEventListener('change', (e) => {
        const bit = e.target.closest('.abit,.mbit,.ebit,.acl-rec-radio');
        if (!bit || bit.disabled) return;
        if (bit.classList.contains('ebit') || bit.classList.contains('acl-rec-radio')) {
            syncAclAddApply();
            return;
        }
        const row = bit.closest('.acl-row');
        if (!row || panel().classList.contains('acl-adding')) return;
        const layer = row.dataset.layer || 'access';
        if (bit.classList.contains('mbit')) {
            aclApply({ op: 'mask', layer: layer, perms: rowPerms(row) });
        } else {
            aclApply({ op: 'set', typ: row.dataset.type, layer: layer,
                       id: row.dataset.id, perms: rowPerms(row) });
        }
    });

    // Live octal readout while toggling the matrix / special bits.
    // Directory panels use the condensed Read/Write matrix where each audience
    // is none / read-only / read-write: checking Write auto-checks Read, and
    // un-checking Read drops Write (a w-without-r directory can't even be
    // entered over NFS). File panels keep the full independent triad —
    // r without x is normal for a file, so no auto-check at all.
    document.addEventListener('change', function (e) {
        if (!e.target.classList) return;
        if (e.target.classList.contains('pbit')) {
            const cb = e.target;
            const form = cb.closest('form.posix-sec');
            const isDir = !form || form.dataset.kind !== 'file';
            if (isDir) {
                const scope = cb.closest('.perm-body, form') || document;
                const peers = scope.querySelectorAll('.pbit');
                if (cb.checked && +cb.dataset.bit === 2) {
                    peers.forEach(other => {
                        if (other.dataset.role === cb.dataset.role && +other.dataset.bit === 4)
                            other.checked = true;
                    });
                }
                if (!cb.checked && +cb.dataset.bit === 4) {
                    peers.forEach(other => {
                        if (other.dataset.role === cb.dataset.role && +other.dataset.bit === 2)
                            other.checked = false;
                    });
                }
            }
            recomputeMode();
        } else if (e.target.classList.contains('sbit') || e.target.classList.contains('fbit')) {
            // File bits are fully independent — no auto-check between them.
            recomputeMode();
        } else if (e.target.classList.contains('rec-radio')) {
            syncScopeUI();
            recomputeMode();
        }
    });

    // Mark unsaved edits. ACL quick-add fields are excluded: those apply immediately
    // via /acl-apply, so text typed there is never "unsaved" POSIX state.
    function markDirtyIfEditing(e) {
        const t = e.target;
        if (!isEditing() || !t || !t.closest) return;
        if (!t.closest('#perm-panel') || t.closest('.acl-addform')) return;
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
            t.closest('input[name="owner_user"], input[name="owner_group"], .acl-ename')) return;
        document.querySelectorAll('.suggestions').forEach(el => { if (el.innerHTML.trim()) el.innerHTML = ''; });
    }, true);
    document.addEventListener('focusout', function (evt) {
        const input = evt.target;
        if (!input || !input.matches || !input.matches('input[name="owner_user"], input[name="owner_group"], .acl-ename')) return;
        setTimeout(() => {
            const active = document.activeElement;
            const wrap = input.closest('label, .acl-addform');
            const box = wrap ? wrap.querySelector('.suggestions') : null;
            if (box && (!active || (active !== input && !box.contains(active)))) box.innerHTML = '';
        }, 120);
    });

    // ===== Apply lifecycle: /apply placeholder -> poller -> finish refetch of /dir-perms =====
    document.addEventListener('htmx:afterSwap', function (evt) {
        const t = evt.detail && evt.detail.target;
        if (!t || !t.closest || !t.closest('#perm-panel .perm-body')) return;
        syncScopeUI();
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

    function initPageLayout() { initApplyLogAutosize(); sizeSharesHost(); }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initPageLayout);
    } else {
        initPageLayout();
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
