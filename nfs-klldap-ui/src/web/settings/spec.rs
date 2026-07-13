//! Single source of truth for the scalar settings fields: one FieldSpec row
//! drives both the validated-config apply and the comment-preserving
//! toml_edit persistence (and, next, template population). Adding a setting
//! means adding one row here plus its config-struct field.

use nfs_klldap_config::NfsKlldapConfig;

use super::StructuredSettingsForm;

/// Typed value moved between form and config.
pub(crate) enum FieldValue {
    Str(Option<String>),
    Bool(Option<bool>),
    U16(Option<u16>),
}

/// Persistence/behavior class of a field. Each variant mirrors one of the
/// historical hand-written per-field block shapes exactly.
pub(crate) enum FieldKind {
    /// Plain text: a submitted value is written verbatim (config + doc).
    Text,
    /// Password: a blank submission keeps the stored value.
    Password,
    /// u16 port: absent or unparsable form value leaves config + doc alone.
    Port,
    /// Checkbox persisted both ways on every save.
    BoolAlways,
    /// Auto/Custom text pair gated by the override_<name> checkbox; Auto
    /// removes the key. With remove_when_blank a blank Custom value also
    /// removes the key; otherwise the blank string is written.
    OverrideText { remove_when_blank: bool },
    /// Auto/Custom bool pair: config gets the submitted Option, the doc
    /// writes unwrap_or(false); Auto removes the key.
    OverrideBool,
    /// Auto/Custom select with a fixed default written when Auto or blank.
    OverrideSelect { default: &'static str },
}

pub(crate) struct FieldSpec {
    /// Form input name; the override checkbox is "override_<name>".
    pub name: &'static str,
    /// TOML section ("" = top level).
    pub section: &'static str,
    /// TOML key inside the section.
    pub key: &'static str,
    pub kind: FieldKind,
    pub set: fn(&mut NfsKlldapConfig, FieldValue),
}

pub(crate) const FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "ldap_uri",
        section: "",
        key: "ldap_uri",
        kind: FieldKind::Text,
        set: |c, v| {
            if let FieldValue::Str(Some(s)) = v {
                c.ldap_uri = s;
            }
        },
    },
    FieldSpec {
        name: "storage_container_root",
        section: "storage",
        key: "container_root",
        kind: FieldKind::Text,
        set: |c, v| {
            if let FieldValue::Str(Some(s)) = v {
                c.storage.container_root = s;
            }
        },
    },
    FieldSpec {
        name: "server_hostname",
        section: "server",
        key: "hostname",
        kind: FieldKind::OverrideText {
            remove_when_blank: false,
        },
        set: |c, v| {
            if let FieldValue::Str(s) = v {
                c.server.hostname = s;
            }
        },
    },
    FieldSpec {
        name: "sssd_bind_dn",
        section: "sssd",
        key: "ldap_default_bind_dn",
        kind: FieldKind::Text,
        set: |c, v| {
            if let FieldValue::Str(Some(s)) = v {
                c.sssd.ldap_default_bind_dn = s;
            }
        },
    },
    FieldSpec {
        name: "sssd_bind_pw",
        section: "sssd",
        key: "ldap_default_authtok",
        kind: FieldKind::Password,
        set: |c, v| {
            if let FieldValue::Str(Some(s)) = v {
                c.sssd.ldap_default_authtok = s;
            }
        },
    },
    FieldSpec {
        name: "sssd_port",
        section: "sssd",
        key: "port",
        kind: FieldKind::Port,
        set: |c, v| {
            if let FieldValue::U16(p @ Some(_)) = v {
                c.sssd.port = p;
            }
        },
    },
    FieldSpec {
        name: "sssd_search_base",
        section: "sssd",
        key: "ldap_search_base",
        kind: FieldKind::OverrideText {
            remove_when_blank: true,
        },
        set: |c, v| {
            if let FieldValue::Str(s) = v {
                c.sssd.ldap_search_base = s;
            }
        },
    },
    FieldSpec {
        name: "sssd_user_base",
        section: "sssd",
        key: "ldap_user_search_base",
        kind: FieldKind::OverrideText {
            remove_when_blank: false,
        },
        set: |c, v| {
            if let FieldValue::Str(s) = v {
                c.sssd.ldap_user_search_base = s;
            }
        },
    },
    FieldSpec {
        name: "sssd_group_base",
        section: "sssd",
        key: "ldap_group_search_base",
        kind: FieldKind::OverrideText {
            remove_when_blank: false,
        },
        set: |c, v| {
            if let FieldValue::Str(s) = v {
                c.sssd.ldap_group_search_base = s;
            }
        },
    },
    FieldSpec {
        name: "sssd_ldap_tls_reqcert",
        section: "sssd",
        key: "ldap_tls_reqcert",
        kind: FieldKind::OverrideText {
            remove_when_blank: true,
        },
        set: |c, v| {
            if let FieldValue::Str(s) = v {
                c.sssd.ldap_tls_reqcert = s;
            }
        },
    },
    FieldSpec {
        name: "sssd_ldap_tls_cacert",
        section: "sssd",
        key: "ldap_tls_cacert",
        kind: FieldKind::OverrideText {
            remove_when_blank: true,
        },
        set: |c, v| {
            if let FieldValue::Str(s) = v {
                c.sssd.ldap_tls_cacert = s;
            }
        },
    },
    FieldSpec {
        name: "sssd_ldap_id_use_start_tls",
        section: "sssd",
        key: "ldap_id_use_start_tls",
        kind: FieldKind::OverrideBool,
        set: |c, v| {
            if let FieldValue::Bool(b) = v {
                c.sssd.ldap_id_use_start_tls = b;
            }
        },
    },
    FieldSpec {
        name: "sssd_enumerate",
        section: "sssd",
        key: "enumerate",
        kind: FieldKind::OverrideBool,
        set: |c, v| {
            if let FieldValue::Bool(b) = v {
                c.sssd.enumerate = b;
            }
        },
    },
    FieldSpec {
        name: "kllldap_ignored_attributes",
        section: "sssd",
        key: "kllldap_ignored_attributes",
        kind: FieldKind::BoolAlways,
        set: |c, v| {
            if let FieldValue::Bool(b) = v {
                c.sssd.kllldap_ignored_attributes = Some(b.unwrap_or(false));
            }
        },
    },
    FieldSpec {
        name: "kerberos_realm",
        section: "kerberos",
        key: "realm",
        kind: FieldKind::OverrideText {
            remove_when_blank: false,
        },
        set: |c, v| {
            if let FieldValue::Str(s) = v {
                c.kerberos.realm = s;
            }
        },
    },
    FieldSpec {
        name: "ganesha_default_security",
        section: "ganesha",
        key: "default_security",
        kind: FieldKind::OverrideSelect { default: "krb5p" },
        set: |c, v| {
            if let FieldValue::Str(Some(s)) = v {
                c.ganesha.default_security = s;
            }
        },
    },
];

pub(crate) fn form_str<'a>(form: &'a StructuredSettingsForm, name: &str) -> Option<&'a str> {
    form.fields.get(name).map(String::as_str)
}

/// Checkbox truthiness: browsers submit "on"; the JS-driven saves use "true".
pub(crate) fn form_flag(form: &StructuredSettingsForm, name: &str) -> bool {
    matches!(form_str(form, name), Some("true") | Some("on"))
}

fn form_bool(form: &StructuredSettingsForm, name: &str) -> Option<bool> {
    form_str(form, name).map(|v| v == "true" || v == "on")
}

fn set_key<V: Into<toml_edit::Value>>(
    doc: &mut toml_edit::DocumentMut,
    section: &str,
    key: &str,
    v: V,
) {
    if section.is_empty() {
        doc[key] = toml_edit::value(v);
        return;
    }
    let item = doc.entry(section).or_insert(toml_edit::table());
    if let Some(tbl) = item.as_table_mut() {
        tbl[key] = toml_edit::value(v);
    }
}

fn remove_key(doc: &mut toml_edit::DocumentMut, section: &str, key: &str) {
    if section.is_empty() {
        let _ = doc.as_table_mut().remove(key);
    } else if let Some(tbl) = doc.get_mut(section).and_then(|i| i.as_table_mut()) {
        let _ = tbl.remove(key);
    }
}

/// Apply the submitted form to the validated config side.
pub(crate) fn apply_structured_form_to_config(
    form: &StructuredSettingsForm,
    cfg: &mut NfsKlldapConfig,
) {
    for spec in FIELDS {
        match &spec.kind {
            FieldKind::Text => {
                if let Some(v) = form_str(form, spec.name) {
                    (spec.set)(cfg, FieldValue::Str(Some(v.to_string())));
                }
            }
            FieldKind::Password => {
                if let Some(v) = form_str(form, spec.name) {
                    if !v.trim().is_empty() {
                        (spec.set)(cfg, FieldValue::Str(Some(v.to_string())));
                    }
                }
            }
            FieldKind::Port => {
                if let Some(p) =
                    form_str(form, spec.name).and_then(|v| v.trim().parse::<u16>().ok())
                {
                    (spec.set)(cfg, FieldValue::U16(Some(p)));
                }
            }
            FieldKind::OverrideText { .. } => {
                if form_flag(form, &format!("override_{}", spec.name)) {
                    if let Some(v) = form_str(form, spec.name) {
                        let val = if v.trim().is_empty() {
                            None
                        } else {
                            Some(v.to_string())
                        };
                        (spec.set)(cfg, FieldValue::Str(val));
                    }
                }
            }
            FieldKind::OverrideBool => {
                if form_flag(form, &format!("override_{}", spec.name)) {
                    (spec.set)(cfg, FieldValue::Bool(form_bool(form, spec.name)));
                }
            }
            FieldKind::BoolAlways => {
                (spec.set)(cfg, FieldValue::Bool(Some(form_flag(form, spec.name))));
            }
            FieldKind::OverrideSelect { default } => {
                if form_flag(form, &format!("override_{}", spec.name)) {
                    if let Some(v) = form_str(form, spec.name) {
                        let val = if v.trim().is_empty() {
                            (*default).to_string()
                        } else {
                            v.to_string()
                        };
                        (spec.set)(cfg, FieldValue::Str(Some(val)));
                    }
                } else {
                    (spec.set)(cfg, FieldValue::Str(Some((*default).to_string())));
                }
            }
        }
    }
    apply_probe_form_to_config(form, cfg);
}

/// Apply the submitted form to the comment-preserving on-disk TOML.
pub(crate) fn apply_structured_form_to_toml_doc(
    form: &StructuredSettingsForm,
    doc: &mut toml_edit::DocumentMut,
) {
    for spec in FIELDS {
        let over = format!("override_{}", spec.name);
        match &spec.kind {
            FieldKind::Text => {
                if let Some(v) = form_str(form, spec.name) {
                    set_key(doc, spec.section, spec.key, v);
                }
            }
            FieldKind::Password => {
                if let Some(v) = form_str(form, spec.name) {
                    if !v.trim().is_empty() {
                        set_key(doc, spec.section, spec.key, v);
                    }
                }
            }
            FieldKind::Port => {
                if let Some(p) =
                    form_str(form, spec.name).and_then(|v| v.trim().parse::<u16>().ok())
                {
                    set_key(doc, spec.section, spec.key, p as i64);
                }
            }
            FieldKind::OverrideText { remove_when_blank } => {
                if form_flag(form, &over) {
                    if let Some(v) = form_str(form, spec.name) {
                        if v.trim().is_empty() && *remove_when_blank {
                            remove_key(doc, spec.section, spec.key);
                        } else {
                            set_key(doc, spec.section, spec.key, v);
                        }
                    }
                } else {
                    remove_key(doc, spec.section, spec.key);
                }
            }
            FieldKind::OverrideBool => {
                if form_flag(form, &over) {
                    set_key(
                        doc,
                        spec.section,
                        spec.key,
                        form_bool(form, spec.name).unwrap_or(false),
                    );
                } else {
                    remove_key(doc, spec.section, spec.key);
                }
            }
            FieldKind::BoolAlways => {
                set_key(doc, spec.section, spec.key, form_flag(form, spec.name));
            }
            FieldKind::OverrideSelect { default } => {
                if form_flag(form, &over) {
                    let val = match form_str(form, spec.name) {
                        Some(v) if !v.trim().is_empty() => v.to_string(),
                        _ => (*default).to_string(),
                    };
                    set_key(doc, spec.section, spec.key, val);
                } else {
                    set_key(doc, spec.section, spec.key, *default);
                }
            }
        }
    }
    apply_probe_form_to_toml_doc(form, doc);
}

fn apply_probe_form_to_config(form: &StructuredSettingsForm, cfg: &mut NfsKlldapConfig) {
    if form_flag(form, "auto_probe_ldap") {
        cfg.probe.user_principal = None;
        cfg.probe.client_host = None;
    } else {
        if let Some(v) = form_str(form, "probe_user_principal") {
            cfg.probe.user_principal = if v.trim().is_empty() {
                None
            } else {
                Some(v.to_string())
            };
        }
        if let Some(v) = form_str(form, "probe_client_host") {
            cfg.probe.client_host = if v.trim().is_empty() {
                None
            } else {
                Some(v.to_string())
            };
        }
    }
}

/// Auto probe checked removes [probe]; unchecked persists non-empty fields.
fn apply_probe_form_to_toml_doc(form: &StructuredSettingsForm, doc: &mut toml_edit::DocumentMut) {
    if form_flag(form, "auto_probe_ldap") {
        let _ = doc.as_table_mut().remove("probe");
        return;
    }
    for (key, name) in [
        ("user_principal", "probe_user_principal"),
        ("client_host", "probe_client_host"),
    ] {
        let Some(v) = form_str(form, name) else { continue };
        let item = doc.entry("probe").or_insert(toml_edit::table());
        if let Some(tbl) = item.as_table_mut() {
            if v.trim().is_empty() {
                let _ = tbl.remove(key);
            } else {
                tbl[key] = toml_edit::value(v);
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

#[cfg(test)]
pub(crate) fn form_of(pairs: &[(&str, &str)]) -> StructuredSettingsForm {
    StructuredSettingsForm {
        fields: pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    }
}

#[cfg(test)]
mod spec_tests {
    use super::*;

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
        let form = form_of(&[
            ("auto_probe_ldap", "true"),
            ("probe_user_principal", "alice"),
            ("probe_client_host", "lt-a"),
        ]);
        apply_probe_form_to_toml_doc(&form, &mut d);
        let out = d.to_string();
        assert!(!out.contains("[probe]"), "probe table must be removed: {out}");
        assert!(out.contains("# keep this comment"));
        assert!(out.contains("ldap_uri"));
    }

    #[test]
    fn unchecked_persists_values_and_empty_clears_per_key() {
        let mut d = doc("ldap_uri = \"ldaps://klldap.example.test:6360\"\n");
        let form = form_of(&[
            ("probe_user_principal", "bob"),
            ("probe_client_host", "lt-b"),
        ]);
        apply_probe_form_to_toml_doc(&form, &mut d);
        let out = d.to_string();
        assert!(out.contains("user_principal = \"bob\""), "{out}");
        assert!(out.contains("client_host = \"lt-b\""), "{out}");
        // Clearing one field removes only that key.
        let form2 = form_of(&[
            ("probe_user_principal", ""),
            ("probe_client_host", "lt-b"),
        ]);
        apply_probe_form_to_toml_doc(&form2, &mut d);
        let out2 = d.to_string();
        assert!(!out2.contains("user_principal"), "{out2}");
        assert!(out2.contains("client_host = \"lt-b\""), "{out2}");
        // Clearing both collapses the table back to auto.
        let form3 = form_of(&[
            ("probe_user_principal", ""),
            ("probe_client_host", ""),
        ]);
        apply_probe_form_to_toml_doc(&form3, &mut d);
        assert!(!d.to_string().contains("[probe]"));
    }

    #[test]
    fn absent_fields_leave_existing_probe_untouched() {
        let mut d = doc(BASE);
        let form = form_of(&[]);
        apply_probe_form_to_toml_doc(&form, &mut d);
        let out = d.to_string();
        assert!(out.contains("user_principal = \"alice\""), "{out}");
        assert!(out.contains("client_host = \"lt-a\""), "{out}");
    }

    #[test]
    fn roundtrip_covers_every_field_kind() {
        let mut d = doc("# top comment\nldap_uri = \"x\"\n");
        let form = form_of(&[
            ("ldap_uri", "ldaps://k.test:6360"),
            ("storage_container_root", "/exports"),
            ("sssd_bind_dn", "uid=a"),
            ("sssd_bind_pw", "pw"),
            ("sssd_port", "6360"),
            ("override_server_hostname", "on"),
            ("server_hostname", "nas"),
            ("override_sssd_search_base", "true"),
            ("sssd_search_base", ""),
            ("override_sssd_user_base", "true"),
            ("sssd_user_base", ""),
            ("override_sssd_ldap_id_use_start_tls", "true"),
            ("sssd_ldap_id_use_start_tls", "true"),
            ("kllldap_ignored_attributes", "true"),
            ("override_ganesha_default_security", "on"),
            ("ganesha_default_security", "nfs"),
        ]);
        apply_structured_form_to_toml_doc(&form, &mut d);
        let out = d.to_string();
        assert!(out.contains("# top comment"));
        assert!(out.contains("ldap_uri = \"ldaps://k.test:6360\""));
        assert!(out.contains("container_root = \"/exports\""));
        assert!(out.contains("port = 6360"));
        assert!(out.contains("hostname = \"nas\""));
        // Blank + remove_when_blank drops the key; blank without it writes "".
        assert!(!out.contains("ldap_search_base"), "{out}");
        assert!(out.contains("ldap_user_search_base = \"\""), "{out}");
        assert!(out.contains("ldap_id_use_start_tls = true"));
        assert!(out.contains("kllldap_ignored_attributes = true"));
        assert!(out.contains("default_security = \"nfs\""));

        let mut cfg = NfsKlldapConfig::default();
        apply_structured_form_to_config(&form, &mut cfg);
        assert_eq!(cfg.ldap_uri, "ldaps://k.test:6360");
        assert_eq!(cfg.sssd.port, Some(6360));
        assert_eq!(cfg.server.hostname.as_deref(), Some("nas"));
        assert_eq!(cfg.sssd.ldap_search_base, None);
        assert_eq!(cfg.sssd.ldap_id_use_start_tls, Some(true));
        assert_eq!(cfg.sssd.kllldap_ignored_attributes, Some(true));
        assert_eq!(cfg.ganesha.default_security, "nfs");

        // Override off snaps default_security back to krb5p on both sides
        // and removes the override-gated keys.
        let off = form_of(&[("ganesha_default_security", "nfs")]);
        apply_structured_form_to_config(&off, &mut cfg);
        assert_eq!(cfg.ganesha.default_security, "krb5p");
        apply_structured_form_to_toml_doc(&off, &mut d);
        let out2 = d.to_string();
        assert!(out2.contains("default_security = \"krb5p\""));
        assert!(!out2.contains("hostname = \"nas\""), "{out2}");
    }

    #[test]
    fn comments_and_unrelated_keys_survive_a_full_save() {
        let base = "# keep\nldap_uri = \"x\"\n\n[sssd]\ncustom_key = \"stay\" # Auto-enabled\n";
        let mut d = doc(base);
        let form = form_of(&[("ldap_uri", "y"), ("sssd_bind_dn", "uid=b")]);
        apply_structured_form_to_toml_doc(&form, &mut d);
        let out = d.to_string();
        assert!(out.contains("# keep"), "{out}");
        assert!(out.contains("custom_key = \"stay\" # Auto-enabled"), "{out}");
        assert!(out.contains("ldap_uri = \"y\""));
        assert!(out.contains("ldap_default_bind_dn = \"uid=b\""));
    }
}
