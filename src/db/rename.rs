//! Renaming a project: every row stored under one project name moves to
//! another in one transaction, ids unchanged, and the old name is kept as
//! an alias so agents that still use it land on the new one.
//!
//! Where a project name lives (all of it moves):
//! - `entries.project` (memories, notes, to-dos). The full-text index
//!   holds only title, body, tags and files, so it needs no change, and
//!   the embeddings do not include the project either.
//! - `tasks.project`; `task_notes` follow their task by id.
//! - `files.project`, every version (unique on project, path, version).
//! - `sessions.project`, `messages.project` (handoffs and messages),
//!   `activity.project` (the feed), `agent_runs.project` (built-in runs;
//!   `delegations`, `agent_run_refs`, `run_writes` go by task or run id).
//! - `rules.target` of rules with scope `project`.
//! - `meta` keys `project_alias.<old>` (the aliases themselves).
//!
//! No table is added: aliases are `meta` rows.

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};

use super::{Db, Entry, get_entry, set_meta};

/// The `meta` key prefix of an alias: `project_alias.<old>` holds the
/// project the old name now stands for.
pub const ALIAS_PREFIX: &str = "project_alias.";

/// How many rows of each kind a project holds (or a rename moved).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct ProjectCounts {
    pub entries: i64,
    pub tasks: i64,
    /// Owner notes on those tasks; they follow their task by id.
    pub task_notes: i64,
    /// File versions.
    pub files: i64,
    /// Distinct file paths.
    pub file_paths: i64,
    pub sessions: i64,
    pub messages: i64,
    pub activity: i64,
    pub rules: i64,
    pub agent_runs: i64,
}

impl ProjectCounts {
    /// Rows stored under the name itself (task notes and file paths are
    /// counted through their task and versions).
    pub fn total(&self) -> i64 {
        self.entries
            + self.tasks
            + self.files
            + self.sessions
            + self.messages
            + self.activity
            + self.rules
            + self.agent_runs
    }

    /// "3 entries, 1 task, …", every kind with its count.
    pub fn describe(&self) -> String {
        let part = |count: i64, one: &str, many: &str| {
            format!("{count} {}", if count == 1 { one } else { many })
        };
        [
            part(self.entries, "entry", "entries"),
            part(self.tasks, "task", "tasks"),
            part(self.task_notes, "task note", "task notes"),
            format!(
                "{} ({})",
                part(self.files, "file version", "file versions"),
                part(self.file_paths, "path", "paths")
            ),
            part(self.sessions, "session", "sessions"),
            part(self.messages, "message or handoff", "messages and handoffs"),
            part(self.activity, "activity line", "activity lines"),
            part(self.rules, "project rule", "project rules"),
            part(self.agent_runs, "built-in run", "built-in runs"),
        ]
        .join(", ")
    }
}

/// What a rename would do, without doing it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RenamePreview {
    pub from: String,
    pub to: String,
    /// The rows under `from`.
    pub moving: ProjectCounts,
    /// The rows already under `to`.
    pub target: ProjectCounts,
    pub target_exists: bool,
    /// Paths stored under both names; a merge renumbers their versions.
    pub conflicting_paths: Vec<String>,
    /// Why the rename cannot happen at all, if it cannot (merge aside).
    pub refusal: Option<String>,
}

/// What a rename did.
#[derive(Debug, Clone)]
pub struct RenameOutcome {
    pub from: String,
    pub to: String,
    pub moved: ProjectCounts,
    pub merged: bool,
    /// Paths whose versions were renumbered by a merge.
    pub renumbered_paths: Vec<String>,
    /// Whether `from` is now an alias of `to`.
    pub alias_kept: bool,
    /// The alias `to` that was removed because `to` is a project now.
    pub removed_alias: Option<String>,
    /// Whether this undid an earlier rename (`to` was an alias of `from`).
    pub undo: bool,
    /// Other aliases that pointed at `from` and now point at `to`.
    pub repointed: Vec<String>,
    /// The note recording the rename, in `to`.
    pub note: Entry,
}

/// Who asks for a rename, and how.
#[derive(Debug, Clone, Default)]
pub struct RenameRequest {
    pub from: String,
    pub to: String,
    pub merge: bool,
    pub keep_alias: bool,
    /// The agent or user, for the note.
    pub by: String,
    pub session_id: Option<String>,
}

/// A project name as every tool takes it: trimmed, lowercase, not empty.
/// `log`, the board, files and the rename all check names with this.
pub fn normalize_project(project: &str) -> Result<String> {
    let project = project.trim().to_lowercase();
    if project.is_empty() {
        anyhow::bail!("project must not be empty");
    }
    Ok(project)
}

/// The project an alias stands for, if `name` is one.
pub(super) fn alias_of(conn: &Connection, name: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params![format!("{ALIAS_PREFIX}{name}")],
            |row| row.get(0),
        )
        .optional()?)
}

/// `name`, or the project it is an alias of. Aliases never chain, so one
/// lookup is enough. An empty name stays empty.
pub(super) fn resolve_alias(conn: &Connection, name: &str) -> Result<String> {
    if name.is_empty() {
        return Ok(String::new());
    }
    Ok(alias_of(conn, name)?.unwrap_or_else(|| name.to_string()))
}

/// Every alias as (old name, project), by old name.
pub(super) fn all_aliases(conn: &Connection) -> Result<Vec<(String, String)>> {
    let mut stmt = conn.prepare(
        "SELECT substr(key, ?2), value FROM meta
         WHERE substr(key, 1, ?1) = ?3 ORDER BY key",
    )?;
    let rows = stmt.query_map(
        params![
            ALIAS_PREFIX.len() as i64,
            ALIAS_PREFIX.len() as i64 + 1,
            ALIAS_PREFIX
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

fn count(conn: &Connection, sql: &str, name: &str) -> Result<i64> {
    Ok(conn.query_row(sql, params![name], |row| row.get(0))?)
}

/// The rows stored under one project name.
pub(super) fn project_counts(conn: &Connection, name: &str) -> Result<ProjectCounts> {
    Ok(ProjectCounts {
        entries: count(
            conn,
            "SELECT COUNT(*) FROM entries WHERE project = ?1",
            name,
        )?,
        tasks: count(conn, "SELECT COUNT(*) FROM tasks WHERE project = ?1", name)?,
        task_notes: count(
            conn,
            "SELECT COUNT(*) FROM task_notes n JOIN tasks t ON t.id = n.task_id
             WHERE t.project = ?1",
            name,
        )?,
        files: count(conn, "SELECT COUNT(*) FROM files WHERE project = ?1", name)?,
        file_paths: count(
            conn,
            "SELECT COUNT(DISTINCT path) FROM files WHERE project = ?1",
            name,
        )?,
        sessions: count(
            conn,
            "SELECT COUNT(*) FROM sessions WHERE project = ?1",
            name,
        )?,
        messages: count(
            conn,
            "SELECT COUNT(*) FROM messages WHERE project = ?1",
            name,
        )?,
        activity: count(
            conn,
            "SELECT COUNT(*) FROM activity WHERE project = ?1",
            name,
        )?,
        rules: count(
            conn,
            "SELECT COUNT(*) FROM rules WHERE scope = 'project' AND target = ?1",
            name,
        )?,
        agent_runs: count(
            conn,
            "SELECT COUNT(*) FROM agent_runs WHERE project = ?1",
            name,
        )?,
    })
}

fn conflicting_paths(conn: &Connection, from: &str, to: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT path FROM files WHERE project = ?1
           AND path IN (SELECT path FROM files WHERE project = ?2)
         ORDER BY path",
    )?;
    let rows = stmt.query_map(params![from, to], |row| row.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Moves every row from `from` to `to`, ids unchanged; the caller holds
/// the transaction. Files stored at the same path under both names keep
/// every version: the versions of that path are renumbered 1..n in the
/// order they were saved (`created_at`, then id), so the newest saved is
/// the current one. Returns the renumbered paths.
pub(super) fn move_rows(conn: &Connection, from: &str, to: &str) -> Result<Vec<String>> {
    let conflicts = conflicting_paths(conn, from, to)?;
    for path in &conflicts {
        let ids: Vec<i64> = {
            let mut stmt = conn.prepare(
                "SELECT id FROM files WHERE project IN (?1, ?2) AND path = ?3
                 ORDER BY created_at, id",
            )?;
            let rows = stmt.query_map(params![from, to, path], |row| row.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        // Negative first, so no step meets the unique (project, path,
        // version) of a row not renumbered yet.
        for (rank, id) in ids.iter().enumerate() {
            conn.execute(
                "UPDATE files SET project = ?2, version = ?3 WHERE id = ?1",
                params![id, to, -(rank as i64 + 1)],
            )?;
        }
        conn.execute(
            "UPDATE files SET version = -version WHERE project = ?1 AND path = ?2 AND version < 0",
            params![to, path],
        )?;
    }
    for sql in [
        "UPDATE entries SET project = ?2 WHERE project = ?1",
        "UPDATE tasks SET project = ?2 WHERE project = ?1",
        "UPDATE files SET project = ?2 WHERE project = ?1",
        "UPDATE sessions SET project = ?2 WHERE project = ?1",
        "UPDATE messages SET project = ?2 WHERE project = ?1",
        "UPDATE activity SET project = ?2 WHERE project = ?1",
        "UPDATE agent_runs SET project = ?2 WHERE project = ?1",
        "UPDATE rules SET target = ?2 WHERE scope = 'project' AND target = ?1",
    ] {
        conn.execute(sql, params![from, to])?;
    }
    Ok(conflicts)
}

/// Checks a rename. `Err` carries the refusal shown to the caller.
fn check(conn: &Connection, from: &str, to: &str) -> Result<std::result::Result<(), String>> {
    if from == to {
        return Ok(Err(format!(
            "`{from}` and `{to}` are the same name: nothing to rename"
        )));
    }
    if let Some(project) = alias_of(conn, from)? {
        return Ok(Err(format!(
            "`{from}` is not a project but an alias of `{project}` (it was renamed): rename \
             `{project}` instead, or remove the alias"
        )));
    }
    if project_counts(conn, from)?.total() == 0 {
        return Ok(Err(format!(
            "lore has nothing under the project `{from}`: no entries, tasks, files, sessions, \
             messages, activity, rules or runs"
        )));
    }
    Ok(Ok(()))
}

impl Db {
    /// Every alias as (old name, project), by old name.
    pub fn project_aliases(&self) -> Result<Vec<(String, String)>> {
        all_aliases(&self.lock())
    }

    /// `name` (normalised), or the project it is an alias of, with the
    /// alias when there is one.
    pub fn resolve_project(&self, name: &str) -> Result<(String, Option<String>)> {
        let name = name.trim().to_lowercase();
        if name.is_empty() {
            return Ok((name, None));
        }
        match alias_of(&self.lock(), &name)? {
            Some(project) => Ok((project, Some(name))),
            None => Ok((name, None)),
        }
    }

    /// Removes one alias; the project it pointed at, or `None` when there
    /// was no such alias.
    pub fn remove_project_alias(&self, name: &str) -> Result<Option<String>> {
        let name = normalize_project(name)?;
        let conn = self.lock();
        let project = alias_of(&conn, &name)?;
        if project.is_some() {
            conn.execute(
                "DELETE FROM meta WHERE key = ?1",
                params![format!("{ALIAS_PREFIX}{name}")],
            )?;
        }
        Ok(project)
    }

    /// What renaming `from` to `to` would move, and whether it may.
    pub fn rename_preview(&self, from: &str, to: &str) -> Result<RenamePreview> {
        let (from, to) = (normalize_project(from)?, normalize_project(to)?);
        let conn = self.lock();
        let refusal = check(&conn, &from, &to)?.err();
        let target = if alias_of(&conn, &to)?.is_some() {
            ProjectCounts::default()
        } else {
            project_counts(&conn, &to)?
        };
        Ok(RenamePreview {
            moving: project_counts(&conn, &from)?,
            target_exists: target.total() > 0,
            target,
            conflicting_paths: conflicting_paths(&conn, &from, &to)?,
            refusal,
            from,
            to,
        })
    }

    /// Renames a project in one transaction: every row moves from `from`
    /// to `to` with its id, `from` becomes an alias of `to` (unless
    /// `keep_alias` is off, or this undoes an earlier rename), aliases of
    /// `from` now point at `to`, and a note in `to` tagged `rename`
    /// records it. `Ok(Err(..))` is a refusal: nothing changed.
    pub fn rename_project(
        &self,
        request: &RenameRequest,
    ) -> Result<std::result::Result<RenameOutcome, String>> {
        let from = match normalize_project(&request.from) {
            Ok(name) => name,
            Err(error) => return Ok(Err(format!("from: {error}"))),
        };
        let to = match normalize_project(&request.to) {
            Ok(name) => name,
            Err(error) => return Ok(Err(format!("to: {error}"))),
        };
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        if let Err(refusal) = check(&tx, &from, &to)? {
            return Ok(Err(refusal));
        }
        // A name that is an alias is not a project: renaming to it makes
        // it one, so the alias goes. When it pointed back at `from` this
        // is a rename back, which leaves no alias behind.
        let to_alias = alias_of(&tx, &to)?;
        let undo = to_alias.as_deref() == Some(from.as_str());
        let target = project_counts(&tx, &to)?;
        if target.total() > 0 && !request.merge {
            return Ok(Err(format!(
                "the project `{to}` already exists ({}); pass merge: true to merge `{from}` into \
                 it",
                target.describe()
            )));
        }
        let moved = project_counts(&tx, &from)?;
        if to_alias.is_some() {
            tx.execute(
                "DELETE FROM meta WHERE key = ?1",
                params![format!("{ALIAS_PREFIX}{to}")],
            )?;
        }
        let renumbered_paths = move_rows(&tx, &from, &to)?;
        // Chains collapse: every alias of `from` now names `to`.
        let repointed: Vec<String> = all_aliases(&tx)?
            .into_iter()
            .filter(|(_, project)| *project == from)
            .map(|(old, _)| old)
            .collect();
        tx.execute(
            "UPDATE meta SET value = ?2 WHERE substr(key, 1, ?3) = ?4 AND value = ?1",
            params![from, to, ALIAS_PREFIX.len() as i64, ALIAS_PREFIX],
        )?;
        let alias_kept = request.keep_alias && !undo;
        if alias_kept {
            set_meta(&tx, &format!("{ALIAS_PREFIX}{from}"), &to)?;
        }
        let by = if request.by.trim().is_empty() {
            "unknown".to_string()
        } else {
            request.by.trim().to_string()
        };
        let mut body = format!(
            "The project `{from}` was renamed to `{to}` by {by}. Moved: {}.",
            moved.describe()
        );
        if target.total() > 0 {
            body.push_str(&format!(
                " Merged into the existing `{to}` ({}).",
                target.describe()
            ));
        }
        if !renumbered_paths.is_empty() {
            body.push_str(&format!(
                " Files at the same path under both names keep every version, renumbered in \
                 the order they were saved: {}.",
                renumbered_paths.join(", ")
            ));
        }
        if alias_kept {
            body.push_str(&format!(
                " `{from}` stays an alias: agents that still use it are sent to `{to}`."
            ));
        } else if undo {
            body.push_str(&format!(
                " This undid the earlier rename of `{to}` to `{from}`; the alias `{to}` was \
                 removed."
            ));
        } else {
            body.push_str(&format!(" No alias was kept for `{from}`."));
        }
        if !repointed.is_empty() {
            body.push_str(&format!(
                " Aliases now pointing at `{to}`: {}.",
                repointed.join(", ")
            ));
        }
        tx.execute(
            "INSERT INTO entries (project, kind, title, body, tags, agent, session_id)
             VALUES (?1, 'note', ?2, ?3, 'rename', ?4, ?5)",
            params![
                to,
                format!("project {from} renamed to {to} by {by}"),
                body,
                by,
                request.session_id
            ],
        )?;
        let note_id = tx.last_insert_rowid();
        let note = get_entry(&tx, note_id)?
            .ok_or_else(|| anyhow::anyhow!("the rename note vanished after insert"))?;
        tx.commit()?;
        Ok(Ok(RenameOutcome {
            merged: target.total() > 0,
            removed_alias: to_alias.map(|_| to.clone()),
            from,
            to,
            moved,
            renumbered_paths,
            alias_kept,
            undo,
            repointed,
            note,
        }))
    }
}

/// A copy of a backup with every project name that is an alias here
/// replaced by its project (a JSON merge).
pub(super) fn remap_backup(
    backup: &super::Backup,
    aliases: &std::collections::HashMap<String, String>,
) -> super::Backup {
    let map = |name: &mut String| {
        if let Some(project) = aliases.get(name.trim().to_lowercase().as_str()) {
            *name = project.clone();
        }
    };
    let mut copy = backup.clone();
    copy.entries
        .iter_mut()
        .for_each(|row| map(&mut row.project));
    copy.activity
        .iter_mut()
        .for_each(|row| map(&mut row.project));
    copy.sessions
        .iter_mut()
        .for_each(|row| map(&mut row.project));
    copy.tasks.iter_mut().for_each(|row| map(&mut row.project));
    copy.messages
        .iter_mut()
        .for_each(|row| map(&mut row.project));
    copy.files
        .iter_mut()
        .for_each(|row| map(&mut row.info.project));
    copy.rules
        .iter_mut()
        .filter(|rule| rule.scope.trim().eq_ignore_ascii_case("project"))
        .for_each(|rule| map(&mut rule.target));
    copy
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{
        NewEntry, NewFile, NewMessage, NewRun, NewSession, NewTask, RuleInput, unix_now,
    };

    fn temp_db(label: &str) -> Db {
        let dir =
            std::env::temp_dir().join(format!("lore-rename-test-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Db::open(&dir.join("lore.db")).unwrap()
    }

    fn entry(db: &Db, project: &str, title: &str, body: &str) -> Entry {
        db.insert(&NewEntry {
            project: project.into(),
            kind: "update".into(),
            title: title.into(),
            body: body.into(),
            agent: "codex".into(),
            path: "/work".into(),
            commit: format!("{:040x}", title.len()),
            ..NewEntry::default()
        })
        .unwrap()
    }

    fn file(db: &Db, project: &str, path: &str, content: &str) -> i64 {
        db.save_file(&NewFile {
            project: project.into(),
            path: path.into(),
            description: format!("{path} of {project}"),
            content: content.into(),
            agent: "codex".into(),
            ..NewFile::default()
        })
        .unwrap()
        .file
        .id
    }

    /// One row of every kind that carries a project, under `project`;
    /// answers the run's id.
    fn fill(db: &Db, project: &str) -> String {
        static RUNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let run = format!(
            "run-{project}-{}",
            RUNS.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        );
        entry(
            db,
            project,
            "Shipped the zebrafinch importer",
            "The importer reads CSV.",
        );
        db.insert(&NewEntry {
            project: project.into(),
            kind: "note".into(),
            title: "A note".into(),
            body: "Notes move too.".into(),
            ..NewEntry::default()
        })
        .unwrap();
        let task = db
            .add_task(&NewTask {
                project: project.into(),
                title: "Do the thing".into(),
                created_by: "codex".into(),
                ..NewTask::default()
            })
            .unwrap();
        db.add_task_note(task.id, "owner", "a note on the task")
            .unwrap();
        file(db, project, "docs/ideas.md", "one");
        file(db, project, "docs/ideas.md", "two");
        file(db, project, "schema.sql", "create table t;");
        db.open_session(&NewSession {
            agent: "codex".into(),
            project: project.into(),
            title: "work".into(),
            ..NewSession::default()
        })
        .unwrap();
        for kind in ["handoff", "message"] {
            db.add_message(&NewMessage {
                kind: kind.into(),
                project: project.into(),
                from_agent: "codex".into(),
                to_agent: String::new(),
                body: format!("a {kind}"),
                session_id: None,
            })
            .unwrap();
        }
        db.record_activity("codex", "log", project, None, None, &[], "logged")
            .unwrap();
        db.add_rule(&RuleInput {
            scope: "project".into(),
            target: project.into(),
            body: "Write tests.".into(),
            enabled: true,
            position: 0,
        })
        .unwrap();
        db.insert_run(&NewRun {
            id: run.clone(),
            agent: "claude-builtin".into(),
            task_id: Some(task.id),
            kind: "task".into(),
            project: project.into(),
            token_hash: format!("hash-{run}"),
            token_expires_at: unix_now() + 600,
            ..NewRun::default()
        })
        .unwrap();
        run
    }

    fn counts(db: &Db, name: &str) -> ProjectCounts {
        project_counts(&db.lock(), name).unwrap()
    }

    fn request(from: &str, to: &str) -> RenameRequest {
        RenameRequest {
            from: from.into(),
            to: to.into(),
            merge: false,
            keep_alias: true,
            by: "claude".into(),
            session_id: None,
        }
    }

    fn rename(db: &Db, from: &str, to: &str) -> RenameOutcome {
        db.rename_project(&request(from, to)).unwrap().unwrap()
    }

    fn refused(db: &Db, request: RenameRequest) -> String {
        db.rename_project(&request).unwrap().unwrap_err()
    }

    #[test]
    fn a_rename_moves_every_row_of_every_table_and_keeps_the_ids() {
        let db = temp_db("every");
        let run = fill(&db, "shop");
        fill(&db, "other");
        let before = counts(&db, "shop");
        let expected = ProjectCounts {
            entries: 2,
            tasks: 1,
            task_notes: 1,
            files: 3,
            file_paths: 2,
            sessions: 1,
            messages: 2,
            activity: 1,
            rules: 1,
            agent_runs: 1,
        };
        assert_eq!(before, expected);
        let other = counts(&db, "other");
        let ids: Vec<i64> = db
            .recent(Some("shop"), None, 50)
            .unwrap()
            .iter()
            .map(|entry| entry.id)
            .collect();

        let outcome = rename(&db, "Shop ", "store");
        assert_eq!(
            (outcome.from.as_str(), outcome.to.as_str()),
            ("shop", "store")
        );
        assert_eq!(outcome.moved, expected);
        assert!(!outcome.merged && outcome.alias_kept && !outcome.undo);

        // Nothing is left under the old name, and the other project is
        // untouched.
        assert_eq!(counts(&db, "shop"), ProjectCounts::default());
        assert_eq!(counts(&db, "other"), other);
        // The note recording it is one more entry, and one more activity
        // line is the caller's.
        let after = counts(&db, "store");
        assert_eq!(
            after,
            ProjectCounts {
                entries: 3,
                ..expected.clone()
            }
        );
        // Same ids.
        for id in ids {
            assert_eq!(db.get(id).unwrap().unwrap().project, "store");
        }
        assert_eq!(db.run(&run).unwrap().unwrap().project, "store");
        assert_eq!(db.briefing_rules("codex", "store").unwrap().len(), 1);
        assert!(db.briefing_rules("codex", "shop").unwrap().is_empty());
        assert_eq!(db.pending_handoffs("store", "s_none").unwrap().len(), 1);
        let task = &db.tasks(Some("store"), &[], 10).unwrap()[0];
        assert_eq!(db.task_notes(&[task.id]).unwrap().len(), 1);
        let latest = db.file_at("store", "docs/ideas.md", None).unwrap().unwrap();
        assert_eq!(
            (latest.info.version, latest.content.as_slice()),
            (2, &b"two"[..])
        );

        // The full-text index finds the entries under the new project.
        let hits = db
            .search("zebrafinch", None, Some("store"), None, 10, 0.5)
            .unwrap();
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(
            db.search("zebrafinch", None, Some("shop"), None, 10, 0.5)
                .unwrap()
                .is_empty()
        );

        // The note says what happened.
        assert_eq!(outcome.note.project, "store");
        assert_eq!(outcome.note.kind, "note");
        assert_eq!(outcome.note.tags, "rename");
        assert_eq!(
            outcome.note.title,
            "project shop renamed to store by claude"
        );
        assert!(
            outcome.note.body.contains("2 entries"),
            "{}",
            outcome.note.body
        );

        // The alias, in the projects list too.
        assert_eq!(
            db.project_aliases().unwrap(),
            vec![("shop".to_string(), "store".to_string())]
        );
        let projects = db.projects().unwrap();
        let store = projects.iter().find(|p| p.project == "store").unwrap();
        assert_eq!(store.aliases, vec!["shop".to_string()]);
        assert!(projects.iter().all(|p| p.project != "shop"));
        // The per-agent heads come from the moved entries.
        assert_eq!(store.heads.len(), 1);
    }

    #[test]
    fn refusals_change_nothing() {
        let db = temp_db("refusals");
        fill(&db, "shop");
        fill(&db, "store");
        let before = (counts(&db, "shop"), counts(&db, "store"));
        assert!(refused(&db, request("shop", " SHOP")).contains("same name"));
        assert!(refused(&db, request("ghost", "store")).contains("nothing under"));
        assert!(refused(&db, request("", "store")).contains("must not be empty"));
        assert!(refused(&db, request("shop", "  ")).contains("must not be empty"));
        let exists = refused(&db, request("shop", "store"));
        assert!(
            exists.contains("already exists") && exists.contains("merge"),
            "{exists}"
        );
        assert_eq!((counts(&db, "shop"), counts(&db, "store")), before);
        // An alias is not a project.
        fill(&db, "cafe");
        rename(&db, "cafe", "bistro");
        let alias = refused(&db, request("cafe", "diner"));
        assert!(alias.contains("alias of `bistro`"), "{alias}");
        let preview = db.rename_preview("shop", "store").unwrap();
        assert!(preview.target_exists && preview.refusal.is_none());
        assert_eq!(preview.conflicting_paths, ["docs/ideas.md", "schema.sql"]);
    }

    /// A merge keeps every file version: a path held under both names gets
    /// its versions renumbered 1..n in the order they were saved, so the
    /// newest saved is the current one; ids stay.
    #[test]
    fn a_merge_keeps_both_version_histories_in_saving_order() {
        let db = temp_db("merge");
        let a1 = file(&db, "shop", "docs/ideas.md", "shop one");
        let b1 = file(&db, "store", "docs/ideas.md", "store one");
        let a2 = file(&db, "shop", "docs/ideas.md", "shop two");
        let b_only = file(&db, "store", "store.md", "store only");
        let a_only = file(&db, "shop", "shop.md", "shop only");
        // Times decide the order; ids break ties.
        for (id, at) in [
            (a1, "2026-01-01T00:00:00Z"),
            (b1, "2026-01-02T00:00:00Z"),
            (a2, "2026-01-03T00:00:00Z"),
        ] {
            db.execute_for_test(&format!(
                "UPDATE files SET created_at = '{at}' WHERE id = {id}"
            ));
        }
        entry(&db, "store", "store work", "b");
        entry(&db, "shop", "shop work", "a");
        let mut merge = request("shop", "store");
        merge.merge = true;
        let outcome = db.rename_project(&merge).unwrap().unwrap();
        assert!(outcome.merged);
        assert_eq!(outcome.renumbered_paths, ["docs/ideas.md"]);
        let versions: Vec<(i64, i64)> = db
            .file_versions("store", "docs/ideas.md")
            .unwrap()
            .iter()
            .map(|info| (info.id, info.version))
            .collect();
        let mut sorted = versions.clone();
        sorted.sort_by_key(|(_, version)| *version);
        assert_eq!(sorted, [(a1, 1), (b1, 2), (a2, 3)]);
        let current = db.file_at("store", "docs/ideas.md", None).unwrap().unwrap();
        assert_eq!(current.content, b"shop two");
        // Paths under one name only keep their numbers.
        assert_eq!(db.file(b_only).unwrap().unwrap().info.version, 1);
        let moved = db.file(a_only).unwrap().unwrap().info;
        assert_eq!((moved.project.as_str(), moved.version), ("store", 1));
        assert_eq!(counts(&db, "shop"), ProjectCounts::default());
        assert_eq!(counts(&db, "store").files, 5);
        assert_eq!(counts(&db, "store").entries, 3);
    }

    /// Every store write resolves the alias, whoever writes.
    #[test]
    fn writes_under_an_old_name_land_on_the_new_one() {
        let db = temp_db("writes");
        fill(&db, "shop");
        rename(&db, "shop", "store");
        fill(&db, "shop");
        assert_eq!(counts(&db, "shop"), ProjectCounts::default());
        let store = counts(&db, "store");
        assert_eq!((store.entries, store.tasks, store.sessions), (5, 2, 2));
        // The second save of `one` and `two` are versions 3 and 4 of the
        // same path; the schema's bytes are unchanged, so no new version.
        assert_eq!((store.files, store.messages, store.rules), (5, 4, 2));
        assert_eq!((store.activity, store.agent_runs), (2, 2));
        assert_eq!(
            db.resolve_project(" Shop ").unwrap(),
            ("store".to_string(), Some("shop".to_string()))
        );
        assert_eq!(
            db.resolve_project("store").unwrap(),
            ("store".to_string(), None)
        );
        // `log` under the old name: the entry says the new one.
        assert_eq!(entry(&db, "shop", "later", "x").project, "store");
    }

    #[test]
    fn alias_chains_collapse_and_a_rename_back_leaves_no_loop() {
        let db = temp_db("chains");
        fill(&db, "a");
        rename(&db, "a", "b");
        let second = rename(&db, "b", "c");
        assert_eq!(second.repointed, ["a"]);
        assert_eq!(
            db.project_aliases().unwrap(),
            vec![("a".into(), "c".into()), ("b".into(), "c".into())]
        );
        assert_eq!(db.resolve_project("a").unwrap().0, "c");

        // Back: c → b undoes the second rename (no alias c → b), and the
        // alias a now names b.
        let back = rename(&db, "c", "b");
        assert!(back.undo && !back.alias_kept);
        assert_eq!(back.removed_alias.as_deref(), Some("b"));
        assert_eq!(
            db.project_aliases().unwrap(),
            vec![("a".into(), "b".into())]
        );
        // And b → a undoes the first.
        let back = rename(&db, "b", "a");
        assert!(back.undo);
        assert!(db.project_aliases().unwrap().is_empty());
        assert_eq!(counts(&db, "a").tasks, 1);
        assert_eq!(counts(&db, "b"), ProjectCounts::default());
        assert_eq!(counts(&db, "c"), ProjectCounts::default());

        // Renaming another project to a name that is an alias makes it a
        // project: the alias goes, and the new rename's alias stays.
        rename(&db, "a", "b");
        fill(&db, "x");
        let onto = rename(&db, "x", "a");
        assert!(!onto.undo && onto.alias_kept);
        assert_eq!(onto.removed_alias.as_deref(), Some("a"));
        assert_eq!(
            db.project_aliases().unwrap(),
            vec![("x".into(), "a".into())]
        );
        assert_eq!(db.resolve_project("a").unwrap(), ("a".to_string(), None));
        assert_eq!(counts(&db, "b").tasks, 1);
        assert_eq!(counts(&db, "a").tasks, 1);

        // Without an alias the old name is free again; an alias can also
        // be removed by itself.
        let mut free = request("b", "d");
        free.keep_alias = false;
        let outcome = db.rename_project(&free).unwrap().unwrap();
        assert!(!outcome.alias_kept);
        assert_eq!(db.resolve_project("b").unwrap(), ("b".to_string(), None));
        assert_eq!(db.remove_project_alias("X").unwrap().as_deref(), Some("a"));
        assert_eq!(db.remove_project_alias("x").unwrap(), None);
        assert!(db.project_aliases().unwrap().is_empty());
    }

    /// A JSON backup carries the aliases; a restore puts them back with
    /// the rows, and a backup without any clears them. A merge files the
    /// incoming rows of an old name under the new one.
    #[test]
    fn the_json_backup_round_trips_a_rename() {
        let db = temp_db("backup");
        fill(&db, "shop");
        rename(&db, "shop", "store");
        let backup = db.export().unwrap();
        assert_eq!(
            backup.project_aliases.get("shop").map(String::as_str),
            Some("store")
        );
        let json = serde_json::to_string(&backup).unwrap();
        let fresh = temp_db("backup-restored");
        fresh
            .restore(&serde_json::from_str(&json).unwrap())
            .unwrap();
        assert_eq!(
            fresh.project_aliases().unwrap(),
            vec![("shop".into(), "store".into())]
        );
        let (here, there) = (counts(&db, "store"), counts(&fresh, "store"));
        // Runs are not part of the JSON backup, nor are the owner's task
        // notes (as before this change).
        assert_eq!(
            there,
            ProjectCounts {
                agent_runs: 0,
                task_notes: 0,
                ..here
            }
        );
        assert_eq!(counts(&fresh, "shop"), ProjectCounts::default());

        // A backup from before the rename feature (no aliases) clears them.
        let mut old: serde_json::Value = serde_json::from_str(&json).unwrap();
        old.as_object_mut().unwrap().remove("project_aliases");
        fresh
            .restore(&serde_json::from_value(old).unwrap())
            .unwrap();
        assert!(fresh.project_aliases().unwrap().is_empty());

        // A merge: another lore still has the rows under the old name.
        let elsewhere = temp_db("backup-elsewhere");
        entry(
            &elsewhere,
            "shop",
            "Written elsewhere",
            "Still under the old name there.",
        );
        file(&elsewhere, "shop", "elsewhere.md", "from the other lore");
        let incoming = elsewhere.export().unwrap();
        let before = counts(&db, "store");
        let (added, _) = db.merge(&incoming).unwrap();
        assert_eq!(added, 1);
        assert_eq!(counts(&db, "shop"), ProjectCounts::default());
        assert_eq!(counts(&db, "store").entries, before.entries + 1);
        assert_eq!(counts(&db, "store").files, before.files + 1);
        // The same backup again adds nothing: the rows are found under
        // the new name.
        let (added, _) = db.merge(&incoming).unwrap();
        assert_eq!(added, 0);
    }

    /// The rename on a copy of a database the production build wrote
    /// (`LORE_FIXTURE_DB`; the copy goes to `LORE_SCRATCH_DIR` or the
    /// temporary directory, the original is never opened for writing).
    #[test]
    #[ignore = "needs LORE_FIXTURE_DB pointing at a production-written database"]
    fn a_rename_on_a_copy_of_a_production_database() {
        let source = std::path::PathBuf::from(std::env::var("LORE_FIXTURE_DB").unwrap());
        let dir = std::env::var("LORE_SCRATCH_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir())
            .join(format!("fixture-rename-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let copy = dir.join("lore.db");
        std::fs::copy(&source, &copy).unwrap();
        let db = Db::open(&copy).unwrap();
        let projects = db.projects().unwrap();
        let busiest = projects
            .iter()
            .max_by_key(|project| project.entries)
            .expect("the fixture has projects")
            .project
            .clone();
        let target = format!("{busiest}-renamed");
        let before = counts(&db, &busiest);
        let total_entries = db.recent(None, None, 1_000_000).unwrap().len();
        let outcome = rename(&db, &busiest, &target);
        assert_eq!(outcome.moved, before);
        assert_eq!(counts(&db, &busiest), ProjectCounts::default());
        let after = counts(&db, &target);
        assert_eq!(after.entries, before.entries + 1);
        assert_eq!(
            ProjectCounts {
                entries: before.entries,
                ..after
            },
            before
        );
        assert_eq!(
            db.recent(None, None, 1_000_000).unwrap().len(),
            total_entries + 1
        );
        // Back again, and the full-text index still answers.
        let back = rename(&db, &target, &busiest);
        assert!(back.undo);
        assert!(db.project_aliases().unwrap().is_empty());
        let word = db
            .recent(Some(&busiest), None, 1)
            .unwrap()
            .first()
            .and_then(|entry| {
                entry
                    .title
                    .split_whitespace()
                    .find(|word| word.len() > 5 && word.chars().all(char::is_alphanumeric))
                    .map(str::to_string)
            });
        if let Some(word) = word {
            assert!(
                !db.search(&word, None, Some(&busiest), None, 5, 0.5)
                    .unwrap()
                    .is_empty(),
                "{word}"
            );
        }
        eprintln!(
            "fixture: renamed {busiest} ({}) to {target} and back; {} projects",
            before.describe(),
            projects.len()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
