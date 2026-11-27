//! The page's Notes and To-do views. Notes are entries of kind `note`,
//! kept per project; the to-do list is the board's open tasks together
//! with the entries of kind `todo` (note-style to-dos, not on the board).
//! Adding and finishing tasks go through the board's own routes
//! (`/admin/api/tasks`); these add what the board does not have.

use super::*;
use crate::db::{Entry, GENERAL_PROJECT, NewEntry, Patch};

/// Longest note title and text the page stores.
const NOTE_TITLE_MAX: usize = 200;
const NOTE_BODY_MAX: usize = 20_000;

#[derive(Deserialize)]
pub(super) struct NotesQuery {
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    q: Option<String>,
}

fn filter(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty())
}

/// `GET /admin/api/notes`: without a project and a search, the projects
/// that have notes (count, newest); else that project's notes, newest
/// first, or the notes matching `q` (keyword search).
pub(super) async fn list_notes(
    State(admin): State<Arc<Admin>>,
    Query(query): Query<NotesQuery>,
) -> Response {
    let project = filter(query.project);
    let q = query
        .q
        .map(|q| q.trim().to_string())
        .filter(|q| !q.is_empty());
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let projects: Vec<serde_json::Value> = state
            .db
            .note_projects()?
            .into_iter()
            .map(|(project, count, newest)| json!({ "project": project, "count": count, "newest": newest }))
            .collect();
        let notes: Vec<Entry> = match (&project, &q) {
            (None, None) => Vec::new(),
            (_, Some(q)) => state
                .db
                .search(q, None, project.as_deref(), Some("note"), 50, 1.0)?
                .into_iter()
                .map(|hit| hit.entry)
                .collect(),
            (Some(project), None) => state.db.recent(Some(project), Some("note"), 200)?,
        };
        Ok(json!({ "projects": projects, "notes": notes }))
    })
    .await;
    respond(result)
}

#[derive(Deserialize)]
pub(super) struct NoteForm {
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    body: Option<String>,
}

fn checked(name: &str, value: Option<&str>, max: usize) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("the {name} must not be empty"));
    }
    if value.chars().count() > max {
        return Err(format!("the {name} must be at most {max} characters"));
    }
    Ok(Some(value.to_string()))
}

/// `POST /admin/api/notes` (`write`): a note in a project, written by the
/// signed-in user.
pub(super) async fn add_note(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    Json(form): Json<NoteForm>,
) -> Response {
    let Some(project) = filter(form.project) else {
        return bad_request("name the project the note belongs to");
    };
    let (title, body) = match (
        checked(
            "title",
            Some(form.title.as_deref().unwrap_or("")),
            NOTE_TITLE_MAX,
        ),
        checked(
            "text",
            Some(form.body.as_deref().unwrap_or("")),
            NOTE_BODY_MAX,
        ),
    ) {
        (Ok(Some(title)), Ok(Some(body))) => (title, body),
        (Err(why), _) | (_, Err(why)) => return bad_request(&why),
        _ => return bad_request("a note needs a title and a text"),
    };
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let entry = state.db.insert(&NewEntry {
            project,
            kind: "note".into(),
            title,
            body,
            tags: String::new(),
            files: String::new(),
            agent: me.username.clone(),
            path: String::new(),
            repo: String::new(),
            commit: String::new(),
            branch: String::new(),
            dirty: false,
            session_id: None,
        })?;
        note_activity(
            &state,
            "log",
            &format!(
                "{} added the note #{} in {}: {}",
                me.username, entry.id, entry.project, entry.title
            ),
        );
        Ok(json!(entry))
    })
    .await;
    respond(result)
}

/// `PUT /admin/api/notes/{id}` (`write`): a note's new title or text.
/// Anything that is not a note is refused.
pub(super) async fn edit_note(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    Path(id): Path<i64>,
    Json(form): Json<NoteForm>,
) -> Response {
    let patch = match (
        checked("title", form.title.as_deref(), NOTE_TITLE_MAX),
        checked("text", form.body.as_deref(), NOTE_BODY_MAX),
    ) {
        (Ok(title), Ok(body)) => Patch {
            title,
            body,
            ..Default::default()
        },
        (Err(why), _) | (_, Err(why)) => return bad_request(&why),
    };
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Entry>> {
        match state.db.get(id)? {
            Some(entry) if entry.kind == "note" => {}
            _ => return Ok(None),
        }
        let entry = state.db.amend(id, &patch)?;
        if let Some(entry) = &entry {
            note_activity(
                &state,
                "amend",
                &format!(
                    "{} changed the note #{}: {}",
                    me.username, entry.id, entry.title
                ),
            );
        }
        Ok(entry)
    })
    .await;
    match result {
        Ok(Ok(Some(entry))) => Json(entry).into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "changing a note failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
pub(super) struct TodosQuery {
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

/// `GET /admin/api/todos`: the to-do list across every project (or one):
/// board tasks by status (`open`: open and claimed, the default; `done`;
/// `all`) and, unless `done`, the note-style to-dos.
pub(super) async fn list_todos(
    State(admin): State<Arc<Admin>>,
    Query(query): Query<TodosQuery>,
) -> Response {
    let project = filter(query.project);
    let status = filter(query.status).unwrap_or_else(|| "open".into());
    let statuses: &'static [&'static str] = match status.as_str() {
        "done" => &["done"],
        "all" => &[],
        _ => &["open", "claimed"],
    };
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let tasks = state.db.tasks(project.as_deref(), statuses, 200)?;
        let entries = if status == "done" {
            Vec::new()
        } else {
            state.db.recent(project.as_deref(), Some("todo"), 200)?
        };
        let projects = state.db.projects()?.into_iter().map(|p| p.project).collect::<Vec<_>>();
        let task_notes = state
            .db
            .task_notes(&tasks.iter().map(|task| task.id).collect::<Vec<_>>())?;
        Ok(json!({ "tasks": tasks, "task_notes": task_notes, "entries": entries, "projects": projects, "general": GENERAL_PROJECT }))
    })
    .await;
    respond(result)
}

/// `POST /admin/api/todos/from-entry/{id}` (`write`): a note-style to-do
/// moved to the board: a task with its title and text in its project, and
/// a line in the entry pointing at the task.
pub(super) async fn todo_from_entry(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    Path(id): Path<i64>,
) -> Response {
    let state = admin.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<Task>> {
        // One move at a time (see `MOVE_TO_BOARD`).
        let _moving = crate::db::MOVE_TO_BOARD.blocking_lock();
        let Some(entry) = state.db.get(id)? else {
            return Ok(None);
        };
        if entry.kind != "todo" {
            anyhow::bail!("entry #{id} is not a note-style to-do");
        }
        if let Some(task) = crate::db::moved_to_board(&entry.body) {
            anyhow::bail!("entry #{id} was already moved to the board as task #{task}");
        }
        if entry.body.chars().count() > crate::db::BODY_MAX_CHARS {
            anyhow::bail!(
                "its text is longer than a task may be ({} characters); shorten the entry first",
                crate::db::BODY_MAX_CHARS
            );
        }
        let mut title: String = entry.title.chars().take(200).collect();
        if title.trim().is_empty() {
            title = format!("To-do #{id}");
        }
        let task = state.db.add_task(&NewTask {
            project: entry.project.clone(),
            title,
            body: entry.body.clone(),
            assignee: String::new(),
            created_by: ADMIN_ACTOR.into(),
            session_id: None,
            targets: crate::db::TaskTargets::default(),
            manual: false,
            manual_by: String::new(),
        })?;
        state.db.set_task_author(task.id, &page_author(&me))?;
        state.db.amend(
            id,
            &Patch {
                body: Some(format!(
                    "{}\n\n{}",
                    entry.body.trim_end(),
                    crate::db::moved_to_board_line(task.id)
                )),
                ..Default::default()
            },
        )?;
        note_activity(
            &state,
            "task_add",
            &format!(
                "{} moved the to-do #{id} to the board as task #{}",
                me.username, task.id
            ),
        );
        Ok(Some(task))
    })
    .await;
    match result {
        Ok(Ok(Some(task))) => Json(task).into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "moving a to-do failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
pub(super) struct TaskNoteForm {
    #[serde(default)]
    body: String,
}

/// `POST /admin/api/tasks/{id}/notes` (`write`): the signed-in user's note
/// on a task, whatever its status; the task itself does not change.
pub(super) async fn add_task_note(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    Path(id): Path<i64>,
    Json(form): Json<TaskNoteForm>,
) -> Response {
    let state = admin.clone();
    let result =
        tokio::task::spawn_blocking(move || -> anyhow::Result<Option<crate::db::TaskNote>> {
            let note = state.db.add_task_note(id, &me.username, &form.body)?;
            if let Some(note) = &note {
                note_activity(
                    &state,
                    "task_update",
                    &format!(
                        "{} noted on task #{}: {}",
                        me.username,
                        note.task_id,
                        note.body.chars().take(80).collect::<String>()
                    ),
                );
            }
            Ok(note)
        })
        .await;
    match result {
        Ok(Ok(Some(note))) => Json(note).into_response(),
        Ok(Ok(None)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => bad_request(&error.to_string()),
        Err(error) => {
            tracing::error!(%error, "adding a task note failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
pub(super) struct HandOffForm {
    /// A built-in agent, or empty for any.
    #[serde(default)]
    agent: String,
}

/// `POST /admin/api/tasks/{id}/hand-off` (`agents`): starts a built-in
/// agent's run on an open, unclaimed task now, manual or not, under the
/// checks a delegation passes. The manual flag stays as it is.
pub(super) async fn hand_off(
    State(admin): State<Arc<Admin>>,
    Extension(me): Extension<SignedIn>,
    Path(id): Path<i64>,
    Json(form): Json<HandOffForm>,
) -> Response {
    let Some(runner) = admin.task_runner.clone() else {
        return bad_request("this lore has no built-in agents");
    };
    let agent = form.agent.trim().to_lowercase();
    match runner
        .hand_off(
            id,
            (!agent.is_empty()).then_some(agent.as_str()),
            &format!("user:{}", me.username),
        )
        .await
    {
        Ok(said) => Json(json!({ "ok": true, "message": said })).into_response(),
        Err(why) => bad_request(&why),
    }
}
