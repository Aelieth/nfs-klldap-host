//! Share-array persistence helpers for the settings handlers.
//! The scalar field surface lives in spec.rs (one FieldSpec row per field).

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

/// Replace only the `[[shares]]` array in the raw TOML doc (shares-save path).
/// Rebuilt tables carry no position metadata, so toml_edit renders them after
/// every positioned section: `[[shares]]` always lands at the bottom of the
/// file (a mid-file block migrates there on its next save). The comment block
/// above the shares region rides along — the first-ever insert hoists the
/// document trailing (the template's commented example), later saves re-attach
/// the first table's prefix — so a rewrite never eats operator comments.
/// ACL vs NOACL kept explicit via enable_acl field write; container_path required per share.
pub(crate) fn apply_shares_to_toml_doc(
    doc: &mut toml_edit::DocumentMut,
    new_shares: &[nfs_klldap_config::Share],
) {
    let mut banner: Option<String> = doc
        .get("shares")
        .and_then(|i| i.as_array_of_tables())
        .and_then(|a| a.iter().next())
        .and_then(|t| t.decor().prefix())
        .and_then(|p| p.as_str())
        .filter(|p| !p.trim().is_empty())
        .map(str::to_string);
    if banner.is_none() {
        let trailing = doc.trailing().as_str().unwrap_or("").to_string();
        if !trailing.trim().is_empty() {
            doc.set_trailing("");
            banner = Some(trailing);
        }
    }
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
        // Written verbatim: an absent key falls back to the root_squash
        // default, so swallowing no_root_squash would silently re-enable
        // squashing the form explicitly turned off.
        if let Some(sq) = &s.squash {
            t["squash"] = toml_edit::value(sq.clone());
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
        // Some(0) is meaningful (attribute caching off), so every set value writes.
        if let Some(v) = s.attr_expiration_secs {
            t["attr_expiration_secs"] = toml_edit::value(i64::from(v));
        }
        // Default-false economy (the rw idiom): only an explicit true writes.
        if s.navahi_insecure == Some(true) {
            t["navahi_insecure"] = toml_edit::value(true);
        }
        if let Some(sp) = &s.source_path {
            if !sp.trim().is_empty() {
                t["source_path"] = toml_edit::value(sp.clone());
            }
        }
        shares.push(t);
    }
    if shares.is_empty() {
        // Deleting the last share leaves no table to carry the banner: it
        // returns to the document trailing instead of vanishing.
        if let Some(b) = banner {
            let rest = doc.trailing().as_str().unwrap_or("").to_string();
            doc.set_trailing(format!("{b}{rest}"));
        }
        return;
    }
    if let Some(mut prefix) = banner {
        if !prefix.ends_with('\n') {
            prefix.push('\n');
        }
        if let Some(first) = shares.iter_mut().next() {
            first.decor_mut().set_prefix(prefix);
        }
    }
    doc["shares"] = toml_edit::Item::ArrayOfTables(shares);
}

#[cfg(test)]
mod apply_tests {
    use super::apply_shares_to_toml_doc;

    fn share(name: &str) -> nfs_klldap_config::Share {
        nfs_klldap_config::Share {
            name: name.to_string(),
            host_path: std::path::PathBuf::from(format!("/data/{name}")),
            container_path: format!("/export/{name}"),
            ..Default::default()
        }
    }

    fn apply_to(text: &str, shares: &[nfs_klldap_config::Share]) -> String {
        let mut doc: toml_edit::DocumentMut = text.parse().expect("fixture parses");
        apply_shares_to_toml_doc(&mut doc, shares);
        doc.to_string()
    }

    /// Start of the real `[[shares]]` header (example lines carry a leading `# `).
    fn shares_pos(out: &str) -> usize {
        out.find("\n[[shares]]").expect("real [[shares]] block present")
    }

    #[test]
    fn first_share_on_fresh_template_lands_at_bottom_with_example_above() {
        let out = apply_to(&nfs_klldap_config::generate_default_template(), &[share("users")]);
        let sh = shares_pos(&out);
        let banner = out.find("# [[shares]]").expect("template example survives");
        let webui = out.find("[webui]").expect("webui section survives");
        assert!(webui < banner && banner < sh, "layout must read [webui] .. example .. [[shares]]: {out}");
        assert!(
            !out[sh + "\n[[shares]]".len()..].contains("\n["),
            "[[shares]] must be the last section: {out}"
        );
        let cfg = nfs_klldap_config::NfsKlldapConfig::parse_str("t", &out).expect("round-trips");
        assert_eq!(cfg.shares.len(), 1);
        assert_eq!(cfg.shares[0].name, "users");
    }

    #[test]
    fn first_share_never_splits_a_populated_webui_section() {
        let src = "ldap_uri = \"ldaps://x:6360\"\n\n[webui]\ntls = false\nsession_timeout_minutes = 30\n";
        let out = apply_to(src, &[share("users")]);
        let reparsed: toml_edit::DocumentMut = out.parse().expect("output parses");
        let webui = reparsed.get("webui").and_then(|i| i.as_table()).expect("[webui] intact");
        assert_eq!(webui.get("tls").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(
            webui.get("session_timeout_minutes").and_then(|v| v.as_integer()),
            Some(30),
            "webui keys must not reparent into a share: {out}"
        );
        assert!(
            out.find("session_timeout_minutes").expect("key present") < shares_pos(&out),
            "webui keys stay above the shares block: {out}"
        );
        let t0 = reparsed["shares"].as_array_of_tables().unwrap().iter().next().unwrap();
        assert!(t0.get("tls").is_none(), "share must not absorb webui keys: {out}");
    }

    #[test]
    fn midfile_shares_normalize_to_bottom_on_save() {
        let src = "[storage]\ncontainer_root = \"/export\"\n\n[[shares]]\nname = \"a\"\nhost_path = \"/h/a\"\ncontainer_path = \"/export/a\"\n\n[webui]\ntls = false\n";
        let out = apply_to(src, &[share("a"), share("b")]);
        let sh = shares_pos(&out);
        assert!(
            out.find("[webui]").expect("webui survives") < sh,
            "shares must migrate below [webui]: {out}"
        );
        let reparsed: toml_edit::DocumentMut = out.parse().unwrap();
        assert_eq!(reparsed["shares"].as_array_of_tables().unwrap().len(), 2);
        assert_eq!(reparsed["webui"]["tls"].as_bool(), Some(false));
    }

    #[test]
    fn banner_above_existing_shares_survives_rewrites() {
        let src = "ldap_uri = \"x\"\n\n# keep me\n# above the shares\n[[shares]]\nname = \"a\"\nhost_path = \"/h/a\"\ncontainer_path = \"/export/a\"\n";
        let once = apply_to(src, &[share("a")]);
        let twice = apply_to(&once, &[share("a")]);
        for out in [&once, &twice] {
            let keep = out.find("# keep me").expect("banner survives");
            assert!(keep < shares_pos(out), "banner stays above the shares block: {out}");
        }
    }

    #[test]
    fn deleting_all_shares_keeps_the_example_banner() {
        let with_share = apply_to(&nfs_klldap_config::generate_default_template(), &[share("users")]);
        let out = apply_to(&with_share, &[]);
        assert!(!out.contains("\n[[shares]]"), "real shares gone: {out}");
        assert!(out.contains("# [[shares]]"), "example banner preserved: {out}");
        assert!(out.parse::<toml_edit::DocumentMut>().is_ok());
    }

    #[test]
    fn no_root_squash_and_attr_expiration_round_trip() {
        let mut s = share("a");
        s.squash = Some("no_root_squash".to_string());
        s.attr_expiration_secs = Some(0);
        let out = apply_to("ldap_uri = \"x\"\n", &[s]);
        assert!(out.contains("squash = \"no_root_squash\""), "no_root_squash must persist: {out}");
        assert!(out.contains("attr_expiration_secs = 0"), "attr_expiration_secs = 0 must persist: {out}");
        let cfg = nfs_klldap_config::NfsKlldapConfig::parse_str("t", &out).unwrap();
        assert_eq!(cfg.shares[0].squash.as_deref(), Some("no_root_squash"));
        assert_eq!(cfg.shares[0].attr_expiration_secs, Some(0));
    }
}
