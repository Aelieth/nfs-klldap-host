//! Share-array persistence and template helpers for the settings handlers.
//! The scalar field surface lives in spec.rs (one FieldSpec row per field).

use super::{build_settings_template, SettingsTemplate};

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

