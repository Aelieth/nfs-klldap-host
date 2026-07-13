//! Apply logic for structured settings and shares to config/TOML.
//! Extracted mechanically to keep settings/mod.rs <=1000 LOC.
//! ACL (enable_acl) and container_path kept explicit in maps and emission.

use super::{build_settings_template, SettingsTemplate, StructuredSettingsForm};

pub(crate) fn apply_structured_form_to_config(
    form: &StructuredSettingsForm,
    cfg: &mut nfs_klldap_config::NfsKlldapConfig,
) {
    if let Some(v) = form.ldap_uri.clone() {
        cfg.ldap_uri = v;
    }
    if let Some(v) = form.storage_container_root.clone() {
        cfg.storage.container_root = v;
    }
    if form.override_server_hostname.unwrap_or(false) {
        if let Some(v) = form.server_hostname.clone() {
            cfg.server.hostname = if v.trim().is_empty() { None } else { Some(v) };
        }
    }
    if let Some(v) = form.sssd_bind_dn.clone() {
        cfg.sssd.ldap_default_bind_dn = v;
    }
    if let Some(v) = form.sssd_bind_pw.clone() {
        if !v.trim().is_empty() {
            cfg.sssd.ldap_default_authtok = v;
        }
    }
    if let Some(v) = form.sssd_port {
        cfg.sssd.port = Some(v);
    }
    if form.override_sssd_search_base.unwrap_or(false) {
        if let Some(v) = form.sssd_search_base.clone() {
            cfg.sssd.ldap_search_base = if v.trim().is_empty() { None } else { Some(v) };
        }
    }
    if form.override_sssd_user_base.unwrap_or(false) {
        if let Some(v) = form.sssd_user_base.clone() {
            cfg.sssd.ldap_user_search_base = if v.trim().is_empty() { None } else { Some(v) };
        }
    }
    if form.override_sssd_group_base.unwrap_or(false) {
        if let Some(v) = form.sssd_group_base.clone() {
            cfg.sssd.ldap_group_search_base = if v.trim().is_empty() { None } else { Some(v) };
        }
    }
    if form.override_sssd_ldap_tls_reqcert.unwrap_or(false) {
        if let Some(v) = form.sssd_ldap_tls_reqcert.clone() {
            cfg.sssd.ldap_tls_reqcert = if v.trim().is_empty() { None } else { Some(v) };
        }
    }
    if form.override_sssd_ldap_tls_cacert.unwrap_or(false) {
        if let Some(v) = form.sssd_ldap_tls_cacert.clone() {
            cfg.sssd.ldap_tls_cacert = if v.trim().is_empty() { None } else { Some(v) };
        }
    }
    if form.override_sssd_ldap_id_use_start_tls.unwrap_or(false) {
        cfg.sssd.ldap_id_use_start_tls = form.sssd_ldap_id_use_start_tls;
    }
    if form.override_sssd_enumerate.unwrap_or(false) {
        cfg.sssd.enumerate = form.sssd_enumerate;
    }
    cfg.sssd.kllldap_ignored_attributes = Some(form.kllldap_ignored_attributes.unwrap_or(false));
    if form.override_kerberos_realm.unwrap_or(false) {
        if let Some(v) = form.kerberos_realm.clone() {
            cfg.kerberos.realm = if v.trim().is_empty() { None } else { Some(v) };
        }
    }
    if form.override_ganesha_default_security.unwrap_or(false) {
        if let Some(v) = form.ganesha_default_security.clone() {
            if !v.trim().is_empty() {
                cfg.ganesha.default_security = v;
            } else {
                cfg.ganesha.default_security = "krb5p".to_string();
            }
        }
    } else {
        cfg.ganesha.default_security = "krb5p".to_string();
    }
    if form.auto_probe_ldap.unwrap_or(false) {
        cfg.probe.user_principal = None;
        cfg.probe.client_host = None;
    } else {
        if let Some(v) = form.probe_user_principal.clone() {
            cfg.probe.user_principal = if v.trim().is_empty() { None } else { Some(v) };
        }
        if let Some(v) = form.probe_client_host.clone() {
            cfg.probe.client_host = if v.trim().is_empty() { None } else { Some(v) };
        }
    }
}

pub(crate) fn make_settings_error_template(
    state: &crate::web::AppState,
    current_user: Option<String>,
    message: String,
) -> SettingsTemplate {
    build_settings_template(state, current_user, Some(message))
}

pub(crate) fn atomic_write_config(path: &std::path::Path, content: &str) -> Result<(), String> {
    let tmp = path.with_extension("conf.saving");
    std::fs::write(&tmp, content.as_bytes()).map_err(|e| format!("Write failed: {}", e))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("Rename failed: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub(crate) fn make_settings_success_template(
    state: &crate::web::AppState,
    current_user: Option<String>,
    message: String,
) -> SettingsTemplate {
    build_settings_template(state, current_user, Some(message))
}

pub(crate) fn apply_structured_form_to_toml_doc(
    form: &StructuredSettingsForm,
    doc: &mut toml_edit::DocumentMut,
) {
    if let Some(v) = &form.ldap_uri {
        doc["ldap_uri"] = toml_edit::value(v.clone());
    }
    if let Some(v) = &form.storage_container_root {
        let item = doc.entry("storage").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["container_root"] = toml_edit::value(v.clone());
        }
    }
    if form.override_server_hostname.unwrap_or(false) {
        if let Some(v) = &form.server_hostname {
            let item = doc.entry("server").or_insert(toml_edit::table());
            if let Some(tbl) = item.as_table_mut() {
                tbl["hostname"] = toml_edit::value(v.clone());
            }
        }
    } else if let Some(item) = doc.get_mut("server") {
        if let Some(tbl) = item.as_table_mut() {
            let _ = tbl.remove("hostname");
        }
    }
    if let Some(v) = &form.sssd_bind_dn {
        let item = doc.entry("sssd").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["ldap_default_bind_dn"] = toml_edit::value(v.clone());
        }
    }
    if let Some(v) = &form.sssd_bind_pw {
        if !v.trim().is_empty() {
            let item = doc.entry("sssd").or_insert(toml_edit::table());
            if let Some(tbl) = item.as_table_mut() {
                tbl["ldap_default_authtok"] = toml_edit::value(v.clone());
            }
        }
    }
    if let Some(v) = form.sssd_port {
        let item = doc.entry("sssd").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["port"] = toml_edit::value(v as i64);
        }
    }
    if form.override_sssd_search_base.unwrap_or(false) {
        if let Some(v) = &form.sssd_search_base {
            let item = doc.entry("sssd").or_insert(toml_edit::table());
            if let Some(tbl) = item.as_table_mut() {
                if v.trim().is_empty() {
                    let _ = tbl.remove("ldap_search_base");
                } else {
                    tbl["ldap_search_base"] = toml_edit::value(v.clone());
                }
            }
        }
    } else if let Some(item) = doc.get_mut("sssd") {
        if let Some(tbl) = item.as_table_mut() {
            let _ = tbl.remove("ldap_search_base");
        }
    }
    if form.override_sssd_user_base.unwrap_or(false) {
        if let Some(v) = &form.sssd_user_base {
            let item = doc.entry("sssd").or_insert(toml_edit::table());
            if let Some(tbl) = item.as_table_mut() {
                tbl["ldap_user_search_base"] = toml_edit::value(v.clone());
            }
        }
    } else if let Some(item) = doc.get_mut("sssd") {
        if let Some(tbl) = item.as_table_mut() {
            let _ = tbl.remove("ldap_user_search_base");
        }
    }
    if form.override_sssd_group_base.unwrap_or(false) {
        if let Some(v) = &form.sssd_group_base {
            let item = doc.entry("sssd").or_insert(toml_edit::table());
            if let Some(tbl) = item.as_table_mut() {
                tbl["ldap_group_search_base"] = toml_edit::value(v.clone());
            }
        }
    } else if let Some(item) = doc.get_mut("sssd") {
        if let Some(tbl) = item.as_table_mut() {
            let _ = tbl.remove("ldap_group_search_base");
        }
    }
    if form.override_sssd_ldap_tls_reqcert.unwrap_or(false) {
        if let Some(v) = &form.sssd_ldap_tls_reqcert {
            let item = doc.entry("sssd").or_insert(toml_edit::table());
            if let Some(tbl) = item.as_table_mut() {
                if v.trim().is_empty() {
                    let _ = tbl.remove("ldap_tls_reqcert");
                } else {
                    tbl["ldap_tls_reqcert"] = toml_edit::value(v.clone());
                }
            }
        }
    } else if let Some(item) = doc.get_mut("sssd") {
        if let Some(tbl) = item.as_table_mut() {
            let _ = tbl.remove("ldap_tls_reqcert");
        }
    }
    if form.override_sssd_ldap_tls_cacert.unwrap_or(false) {
        if let Some(v) = &form.sssd_ldap_tls_cacert {
            let item = doc.entry("sssd").or_insert(toml_edit::table());
            if let Some(tbl) = item.as_table_mut() {
                if v.trim().is_empty() {
                    let _ = tbl.remove("ldap_tls_cacert");
                } else {
                    tbl["ldap_tls_cacert"] = toml_edit::value(v.clone());
                }
            }
        }
    } else if let Some(item) = doc.get_mut("sssd") {
        if let Some(tbl) = item.as_table_mut() {
            let _ = tbl.remove("ldap_tls_cacert");
        }
    }
    if form.override_sssd_ldap_id_use_start_tls.unwrap_or(false) {
        let v = form.sssd_ldap_id_use_start_tls.unwrap_or(false);
        let item = doc.entry("sssd").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["ldap_id_use_start_tls"] = toml_edit::value(v);
        }
    } else if let Some(item) = doc.get_mut("sssd") {
        if let Some(tbl) = item.as_table_mut() {
            let _ = tbl.remove("ldap_id_use_start_tls");
        }
    }
    if form.override_sssd_enumerate.unwrap_or(false) {
        let v = form.sssd_enumerate.unwrap_or(false);
        let item = doc.entry("sssd").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["enumerate"] = toml_edit::value(v);
        }
    } else if let Some(item) = doc.get_mut("sssd") {
        if let Some(tbl) = item.as_table_mut() {
            let _ = tbl.remove("enumerate");
        }
    }
    {
        let kll = form.kllldap_ignored_attributes.unwrap_or(false);
        let item = doc.entry("sssd").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["kllldap_ignored_attributes"] = toml_edit::value(kll);
        }
    }
    if form.override_kerberos_realm.unwrap_or(false) {
        if let Some(v) = &form.kerberos_realm {
            let item = doc.entry("kerberos").or_insert(toml_edit::table());
            if let Some(tbl) = item.as_table_mut() {
                tbl["realm"] = toml_edit::value(v.clone());
            }
        }
    } else if let Some(item) = doc.get_mut("kerberos") {
        if let Some(tbl) = item.as_table_mut() {
            let _ = tbl.remove("realm");
        }
    }
    if form.override_ganesha_default_security.unwrap_or(false) {
        if let Some(v) = &form.ganesha_default_security {
            let val = if v.trim().is_empty() { "krb5p".to_string() } else { v.clone() };
            let item = doc.entry("ganesha").or_insert(toml_edit::table());
            if let Some(tbl) = item.as_table_mut() {
                tbl["default_security"] = toml_edit::value(val);
            }
        } else {
            let item = doc.entry("ganesha").or_insert(toml_edit::table());
            if let Some(tbl) = item.as_table_mut() {
                tbl["default_security"] = toml_edit::value("krb5p");
            }
        }
    } else {
        let item = doc.entry("ganesha").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            tbl["default_security"] = toml_edit::value("krb5p");
        }
    }
    apply_probe_form_to_toml_doc(form, doc);
}

/// Auto probe checked removes [probe]; unchecked persists non-empty fields.
fn apply_probe_form_to_toml_doc(form: &StructuredSettingsForm, doc: &mut toml_edit::DocumentMut) {
    if form.auto_probe_ldap.unwrap_or(false) {
        let _ = doc.as_table_mut().remove("probe");
        return;
    }
    for (key, val) in [
        ("user_principal", &form.probe_user_principal),
        ("client_host", &form.probe_client_host),
    ] {
        let Some(v) = val else { continue };
        let item = doc.entry("probe").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            if v.trim().is_empty() {
                let _ = tbl.remove(key);
            } else {
                tbl[key] = toml_edit::value(v.clone());
            }
        }
    }
    let empty = doc
        .get("probe")
        .and_then(|i| i.as_table())
        .is_some_and(|t| t.is_empty());
    if empty {
        let _ = doc.as_table_mut().remove("probe");
    }
}

/// Replace only the `[[shares]]` array in the raw TOML doc (shares-save path).
/// ACL vs NOACL kept explicit via enable_acl field write; container_path required per share.
pub(crate) fn apply_shares_to_toml_doc(doc: &mut toml_edit::DocumentMut, new_shares: &[nfs_klldap_config::Share]) {
    let had_shares = doc.get("shares").is_some();
    let _ = doc.as_table_mut().remove("shares");
    let mut shares = toml_edit::ArrayOfTables::new();
    for s in new_shares {
        let mut t = toml_edit::Table::new();
        t["name"] = toml_edit::value(s.name.clone());
        t["host_path"] = toml_edit::value(s.host_path.display().to_string());
        t["container_path"] = toml_edit::value(s.container_path.clone());
        if let Some(ep) = &s.pseudo_path {
            t["pseudo_path"] = toml_edit::value(ep.clone());
        }
        if let Some(sec) = &s.security {
            t["security"] = toml_edit::value(sec.clone());
        }
        let rw = s.rw.unwrap_or(true);
        if !rw {
            t["rw"] = toml_edit::value(false);
        }
        if let Some(sq) = &s.squash {
            if sq != "no_root_squash" {
                t["squash"] = toml_edit::value(sq.clone());
            }
        }
        if let Some(cp) = &s.cache_profile {
            if !cp.trim().is_empty() {
                t["cache_profile"] = toml_edit::value(cp.clone());
            }
        } else {
            if let Some(pr) = s.pref_read {
                t["pref_read"] = toml_edit::value(pr as i64);
            }
            if let Some(pw) = s.pref_write {
                t["pref_write"] = toml_edit::value(pw as i64);
            }
        }
        if let Some(v) = s.enable_acl {
            t["enable_acl"] = toml_edit::value(v);
        }
        if let Some(v) = s.manage_gids {
            t["manage_gids"] = toml_edit::value(v);
        }
        if let Some(ref rap) = s.read_access_policy {
            if !rap.trim().is_empty() {
                t["read_access_policy"] = toml_edit::value(rap.clone());
            }
        }
        if let Some(exp) = s.manage_gids_expiration {
            t["manage_gids_expiration"] = toml_edit::value(exp as i64);
        }
        if let Some(sp) = &s.source_path {
            if !sp.trim().is_empty() {
                t["source_path"] = toml_edit::value(sp.clone());
            }
        }
        if let Some(um) = &s.umask {
            if !um.trim().is_empty() {
                t["umask"] = toml_edit::value(um.clone());
            }
        }
        shares.push(t);
    }
    let shares_item = toml_edit::Item::ArrayOfTables(shares);
    if !had_shares {
        let anchor = if doc.get("webui").is_some() {
            Some("webui")
        } else if doc.get("ganesha").is_some() {
            Some("ganesha")
        } else if doc.get("kerberos").is_some() {
            Some("kerberos")
        } else if doc.get("sssd").is_some() {
            Some("sssd")
        } else {
            None
        };
        if let Some(anchor_key) = anchor {
            let trailing = doc.trailing().clone();
            let items: Vec<(String, toml_edit::Item)> = doc
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect();
            for (k, _) in &items {
                let _ = doc.as_table_mut().remove(k.as_str());
            }
            let mut inserted = false;
            for (k, v) in items {
                doc[k.as_str()] = v;
                if k == anchor_key {
                    doc["shares"] = shares_item.clone();
                    inserted = true;
                }
            }
            if !inserted {
                doc["shares"] = shares_item;
            }
            doc.set_trailing(trailing);
        } else {
            doc["shares"] = shares_item;
        }
    } else {
        doc["shares"] = shares_item;
    }
    if !had_shares {
        let mut full = doc.to_string();
        let shares_tail = if let Some(start) = full.find("[[shares]]") {
            let t = full[start..].trim_end().to_string();
            full = full[..start].to_string();
            Some(t)
        } else {
            None
        };
        if let Some(tail) = shares_tail {
            let lines: Vec<&str> = tail.lines().collect();
            let mut peel_count = 0usize;
            for line in lines.iter().rev() {
                let t = line.trim_start();
                if t.is_empty() || t.starts_with('#') {
                    peel_count += 1;
                } else {
                    break;
                }
            }
            let (shares_part_owned, peeled_comments) = if peel_count > 0 {
                let keep = lines.len() - peel_count;
                let s = if keep == 0 { String::new() } else { lines[..keep].join("\n") };
                let c = lines[keep..].join("\n");
                (s, c)
            } else {
                (tail.clone(), String::new())
            };
            let shares_text = shares_part_owned.trim().to_string();
            if let Some(wstart) = full.find("[webui]") {
                let mut insert_at = wstart;
                if let Some(nl) = full[insert_at..].find('\n') {
                    insert_at += nl + 1;
                } else {
                    insert_at = full.len();
                }
                let tail_after = &full[insert_at..];
                let mut consumed = 0usize;
                for line in tail_after.lines() {
                    let t = line.trim_start();
                    if t.is_empty() || t.starts_with('#') {
                        consumed += line.len() + 1;
                    } else {
                        break;
                    }
                }
                insert_at += consumed;
                let before = &full[..insert_at];
                let after = &full[insert_at..];
                let mut middle = String::new();
                if !peeled_comments.is_empty() {
                    middle.push('\n');
                    middle.push_str(&peeled_comments);
                }
                if !shares_text.is_empty() {
                    middle.push_str("\n\n");
                    middle.push_str(&shares_text);
                }
                let reassembled = if after.trim().is_empty() {
                    format!("{}{}\n", before.trim_end(), middle)
                } else {
                    format!("{}{}{}", before.trim_end(), middle, after)
                };
                if let Ok(reparsed) = reassembled.parse::<toml_edit::DocumentMut>() {
                    *doc = reparsed;
                }
            }
        }
    }
}

#[cfg(test)]
mod probe_apply_tests {
    use super::{apply_probe_form_to_toml_doc, StructuredSettingsForm};

    fn doc(text: &str) -> toml_edit::DocumentMut {
        text.parse().unwrap()
    }

    const BASE: &str = "# keep this comment\n\
        ldap_uri = \"ldaps://klldap.example.test:6360\"\n\n\
        [probe]\n\
        user_principal = \"alice\"\n\
        client_host = \"lt-a\"\n";

    #[test]
    fn auto_checked_removes_probe_table_and_keeps_rest() {
        let mut d = doc(BASE);
        let form = StructuredSettingsForm {
            auto_probe_ldap: Some(true),
            probe_user_principal: Some("alice".into()),
            probe_client_host: Some("lt-a".into()),
            ..Default::default()
        };
        apply_probe_form_to_toml_doc(&form, &mut d);
        let out = d.to_string();
        assert!(!out.contains("[probe]"), "probe table must be removed: {out}");
        assert!(out.contains("# keep this comment"));
        assert!(out.contains("ldap_uri"));
    }

    #[test]
    fn unchecked_persists_values_and_empty_clears_per_key() {
        let mut d = doc("ldap_uri = \"ldaps://klldap.example.test:6360\"\n");
        let form = StructuredSettingsForm {
            auto_probe_ldap: None,
            probe_user_principal: Some("bob".into()),
            probe_client_host: Some("lt-b".into()),
            ..Default::default()
        };
        apply_probe_form_to_toml_doc(&form, &mut d);
        let out = d.to_string();
        assert!(out.contains("user_principal = \"bob\""), "{out}");
        assert!(out.contains("client_host = \"lt-b\""), "{out}");
        // Clearing one field removes only that key.
        let form2 = StructuredSettingsForm {
            probe_user_principal: Some(String::new()),
            probe_client_host: Some("lt-b".into()),
            ..Default::default()
        };
        apply_probe_form_to_toml_doc(&form2, &mut d);
        let out2 = d.to_string();
        assert!(!out2.contains("user_principal"), "{out2}");
        assert!(out2.contains("client_host = \"lt-b\""), "{out2}");
        // Clearing both collapses the table back to auto.
        let form3 = StructuredSettingsForm {
            probe_user_principal: Some(String::new()),
            probe_client_host: Some(String::new()),
            ..Default::default()
        };
        apply_probe_form_to_toml_doc(&form3, &mut d);
        assert!(!d.to_string().contains("[probe]"));
    }

    #[test]
    fn absent_fields_leave_existing_probe_untouched() {
        let mut d = doc(BASE);
        let form = StructuredSettingsForm::default();
        apply_probe_form_to_toml_doc(&form, &mut d);
        let out = d.to_string();
        assert!(out.contains("user_principal = \"alice\""), "{out}");
        assert!(out.contains("client_host = \"lt-a\""), "{out}");
    }
}
