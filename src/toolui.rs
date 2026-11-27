//! What a chat app shows while one of lore's tools runs: the status texts
//! ChatGPT reads from a tool's `_meta` (`openai/toolInvocation/invoking`
//! while the call runs, `openai/toolInvocation/invoked` once it is done).
//! Each text is at most 64 characters (ChatGPT's limit) and fixed per tool:
//! the tool list carries no per-call or per-locale variant. Other MCP clients
//! ignore `_meta` keys they do not know, as the MCP specification asks.
//!
//! The language is chosen once at start-up from `LORE_TOOL_STATUS_LANG`
//! (`tr`, the default, `en`, or `off` for no status texts).

use std::sync::OnceLock;

use rmcp::model::MetaObject;

/// ChatGPT's limit on each status text, in characters.
#[cfg(test)]
pub const MAX_STATUS_CHARS: usize = 64;
pub const INVOKING_KEY: &str = "openai/toolInvocation/invoking";
pub const INVOKED_KEY: &str = "openai/toolInvocation/invoked";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    Tr,
    En,
    Off,
}

impl Lang {
    /// `LORE_TOOL_STATUS_LANG`'s value; empty means the default, Turkish.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "" | "tr" => Some(Self::Tr),
            "en" => Some(Self::En),
            "off" => Some(Self::Off),
            _ => None,
        }
    }
}

static LANG: OnceLock<Lang> = OnceLock::new();

/// Sets the language once, at start-up. Without a call (tests) it is Turkish.
pub fn set_lang(lang: Lang) {
    let _ = LANG.set(lang);
}

fn lang() -> Lang {
    *LANG.get().unwrap_or(&Lang::Tr)
}

/// One tool's status texts: Turkish and English, each (invoking, invoked).
pub struct Status {
    pub tool: &'static str,
    pub tr: (&'static str, &'static str),
    pub en: (&'static str, &'static str),
}

/// Every tool lore offers. A test fails when a tool has no row here.
pub const STATUS: &[Status] = &[
    Status {
        tool: "hello",
        tr: ("Lore oturumu açılıyor…", "Lore oturumu açıldı"),
        en: ("Opening a lore session…", "Lore session open"),
    },
    Status {
        tool: "recall",
        tr: ("Hafıza aranıyor…", "Hafıza arandı"),
        en: ("Searching memory…", "Memory searched"),
    },
    Status {
        tool: "recent",
        tr: ("Son çalışmalara bakılıyor…", "Son çalışmalar getirildi"),
        en: ("Checking recent work…", "Recent work loaded"),
    },
    Status {
        tool: "projects",
        tr: ("Projeler listeleniyor…", "Projeler listelendi"),
        en: ("Listing projects…", "Projects listed"),
    },
    Status {
        tool: "get",
        tr: ("Kayıt açılıyor…", "Kayıt açıldı"),
        en: ("Opening entry…", "Entry opened"),
    },
    Status {
        tool: "log",
        tr: ("Hafızaya yazılıyor…", "Hafızaya yazıldı"),
        en: ("Writing to memory…", "Written to memory"),
    },
    Status {
        tool: "amend",
        tr: ("Kayıt düzeltiliyor…", "Kayıt düzeltildi"),
        en: ("Amending entry…", "Entry amended"),
    },
    Status {
        tool: "forget",
        tr: ("Kayıt siliniyor…", "Kayıt silindi"),
        en: ("Forgetting entry…", "Entry forgotten"),
    },
    Status {
        tool: "checkin",
        tr: ("Durum kaydediliyor…", "Durum kaydedildi"),
        en: ("Checking in…", "Checked in"),
    },
    Status {
        tool: "bye",
        tr: ("Oturum kapatılıyor…", "Oturum kapatıldı"),
        en: ("Closing session…", "Session closed"),
    },
    Status {
        tool: "notes",
        tr: ("Notlar okunuyor…", "Notlar okundu"),
        en: ("Reading notes…", "Notes read"),
    },
    Status {
        tool: "note_add",
        tr: ("Not ekleniyor…", "Not eklendi"),
        en: ("Adding note…", "Note added"),
    },
    Status {
        tool: "note_edit",
        tr: ("Not güncelleniyor…", "Not güncellendi"),
        en: ("Editing note…", "Note edited"),
    },
    Status {
        tool: "note_delete",
        tr: ("Not siliniyor…", "Not silindi"),
        en: ("Deleting note…", "Note deleted"),
    },
    Status {
        tool: "todos",
        tr: ("Yapılacaklar okunuyor…", "Yapılacaklar okundu"),
        en: ("Reading to-dos…", "To-dos read"),
    },
    Status {
        tool: "todo_add",
        tr: ("Yapılacak ekleniyor…", "Yapılacak eklendi"),
        en: ("Adding to-do…", "To-do added"),
    },
    Status {
        tool: "todo_done",
        tr: (
            "Tamamlandı olarak işaretleniyor…",
            "Tamamlandı olarak işaretlendi",
        ),
        en: ("Marking done…", "Marked done"),
    },
    Status {
        tool: "tasks",
        tr: ("Görev panosu açılıyor…", "Görev panosu getirildi"),
        en: ("Opening the board…", "Board loaded"),
    },
    Status {
        tool: "task_add",
        tr: ("Görev ekleniyor…", "Görev eklendi"),
        en: ("Adding task…", "Task added"),
    },
    Status {
        tool: "task_update",
        tr: ("Görev güncelleniyor…", "Görev güncellendi"),
        en: ("Updating task…", "Task updated"),
    },
    Status {
        tool: "send",
        tr: ("Mesaj gönderiliyor…", "Mesaj gönderildi"),
        en: ("Sending message…", "Message sent"),
    },
    Status {
        tool: "inbox",
        tr: ("Gelen kutusu okunuyor…", "Gelen kutusu okundu"),
        en: ("Reading inbox…", "Inbox read"),
    },
    Status {
        tool: "handoff",
        tr: ("Devir notu yazılıyor…", "Devir notu yazıldı"),
        en: ("Writing handoff…", "Handoff written"),
    },
    Status {
        tool: "file_save",
        tr: ("Dosya kaydediliyor…", "Dosya kaydedildi"),
        en: ("Saving file…", "File saved"),
    },
    Status {
        tool: "file_get",
        tr: ("Dosya açılıyor…", "Dosya açıldı"),
        en: ("Opening file…", "File opened"),
    },
    Status {
        tool: "files",
        tr: ("Dosyalar listeleniyor…", "Dosyalar listelendi"),
        en: ("Listing files…", "Files listed"),
    },
    Status {
        tool: "file_delete",
        tr: ("Dosya siliniyor…", "Dosya silindi"),
        en: ("Deleting file…", "File deleted"),
    },
    Status {
        tool: "project_rename",
        tr: (
            "Proje yeniden adlandırılıyor…",
            "Proje yeniden adlandırıldı",
        ),
        en: ("Renaming project…", "Project renamed"),
    },
    Status {
        tool: "project_aliases",
        tr: ("Proje takma adları okunuyor…", "Proje takma adları okundu"),
        en: ("Reading project aliases…", "Project aliases read"),
    },
    Status {
        tool: "integrations",
        tr: ("Bağlantılar kontrol ediliyor…", "Bağlantılar listelendi"),
        en: ("Checking integrations…", "Integrations listed"),
    },
    Status {
        tool: "cloudflare",
        tr: ("Cloudflare'e istek gidiyor…", "Cloudflare yanıtladı"),
        en: ("Calling Cloudflare…", "Cloudflare answered"),
    },
    Status {
        tool: "github",
        tr: ("GitHub'a istek gidiyor…", "GitHub yanıtladı"),
        en: ("Calling GitHub…", "GitHub answered"),
    },
    Status {
        tool: "github_org",
        tr: ("GitHub'a (kuruluş) istek gidiyor…", "GitHub yanıtladı"),
        en: ("Calling GitHub (organization)…", "GitHub answered"),
    },
    Status {
        tool: "git_server",
        tr: ("GitLab'a istek gidiyor…", "GitLab yanıtladı"),
        en: ("Calling GitLab…", "GitLab answered"),
    },
    Status {
        tool: "dokploy",
        tr: ("Dokploy'a istek gidiyor…", "Dokploy yanıtladı"),
        en: ("Calling Dokploy…", "Dokploy answered"),
    },
    Status {
        tool: "repo_tree",
        tr: ("Depo ağacı okunuyor…", "Depo ağacı okundu"),
        en: ("Reading the repository tree…", "Repository tree read"),
    },
    Status {
        tool: "repo_read",
        tr: ("Depodan dosya okunuyor…", "Depodaki dosya okundu"),
        en: ("Reading repository files…", "Repository files read"),
    },
    Status {
        tool: "repo_search",
        tr: ("Depoda aranıyor…", "Depoda arandı"),
        en: ("Searching the repository…", "Repository searched"),
    },
    Status {
        tool: "repo_commit",
        tr: ("Depoya commit atılıyor…", "Commit atıldı"),
        en: ("Committing to the repository…", "Committed"),
    },
    Status {
        tool: "assistants",
        tr: (
            "Yerleşik ajanlara bakılıyor…",
            "Yerleşik ajanlar listelendi",
        ),
        en: ("Checking built-in agents…", "Built-in agents listed"),
    },
    Status {
        tool: "delegate",
        tr: ("İş yerleşik ajana veriliyor…", "İş yerleşik ajana verildi"),
        en: ("Handing work to a built-in agent…", "Work handed over"),
    },
    Status {
        tool: "ask",
        tr: ("Yerleşik ajana soruluyor…", "Yerleşik ajana soruldu"),
        en: ("Asking a built-in agent…", "Built-in agent asked"),
    },
    Status {
        tool: "mail",
        tr: ("Posta kutusu okunuyor…", "Posta kutusu okundu"),
        en: ("Reading the mailbox…", "Mailbox read"),
    },
];

/// The status texts of `tool` in `lang`, or `None` (no row, or `off`).
pub fn texts(tool: &str, lang: Lang) -> Option<(&'static str, &'static str)> {
    let row = STATUS.iter().find(|row| row.tool == tool)?;
    match lang {
        Lang::Tr => Some(row.tr),
        Lang::En => Some(row.en),
        Lang::Off => None,
    }
}

/// The tool `_meta` for `tool` in `lang`: both status keys, or nothing.
pub fn meta_in(tool: &str, lang: Lang) -> MetaObject {
    let mut meta = MetaObject::default();
    if let Some((invoking, invoked)) = texts(tool, lang) {
        meta.0.insert(INVOKING_KEY.into(), invoking.into());
        meta.0.insert(INVOKED_KEY.into(), invoked.into());
    }
    meta
}

/// The tool `_meta` for `tool` in the language chosen at start-up. Used
/// by every `#[tool(meta = ...)]` attribute in `server.rs`.
pub fn meta(tool: &str) -> MetaObject {
    meta_in(tool, lang())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_text_fits_and_rows_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for row in STATUS {
            assert!(seen.insert(row.tool), "{} listed twice", row.tool);
            for text in [row.tr.0, row.tr.1, row.en.0, row.en.1] {
                assert!(!text.trim().is_empty(), "{}: empty status text", row.tool);
                assert!(
                    text.chars().count() <= MAX_STATUS_CHARS,
                    "{}: \"{text}\" is longer than {MAX_STATUS_CHARS} characters",
                    row.tool
                );
            }
        }
    }

    #[test]
    fn language_values() {
        assert_eq!(Lang::parse(""), Some(Lang::Tr));
        assert_eq!(Lang::parse("TR"), Some(Lang::Tr));
        assert_eq!(Lang::parse(" en "), Some(Lang::En));
        assert_eq!(Lang::parse("off"), Some(Lang::Off));
        assert_eq!(Lang::parse("de"), None);
        let tr = meta_in("recall", Lang::Tr);
        assert_eq!(tr.0[INVOKING_KEY], "Hafıza aranıyor…");
        assert_eq!(tr.0[INVOKED_KEY], "Hafıza arandı");
        let en = meta_in("recall", Lang::En);
        assert_eq!(en.0[INVOKING_KEY], "Searching memory…");
        assert!(meta_in("recall", Lang::Off).0.is_empty());
        assert!(meta_in("no_such_tool", Lang::Tr).0.is_empty());
    }
}
