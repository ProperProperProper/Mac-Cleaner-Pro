//! Local history log (SQLite, same file and `cleanups` schema as the original
//! Python app, so earlier history is kept). A second table records every
//! security action: when, what, the exact commands, before/after and how to undo.
//! Nothing here ever leaves the Mac. Secret values are never written here.

use rusqlite::{Connection, params};
use std::path::{Path, PathBuf};

pub fn default_db_path() -> PathBuf {
    crate::util::app_support().join("history.db")
}

#[derive(Debug, Clone, PartialEq)]
pub struct CleanupRow {
    pub ts: String,
    pub category: String,
    pub items: i64,
    pub bytes_freed: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActionRow {
    pub id: i64,
    pub ts: String,
    pub check_title: String,
    pub action: String,
    pub commands: String,
    pub before: String,
    pub after: String,
    pub result: String,
    pub undo_json: Option<String>,
    pub undone: bool,
}

pub struct History {
    conn: Connection,
}

impl History {
    pub fn open_default() -> Result<Self, String> {
        Self::open(&default_db_path())
    }

    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS cleanups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                category TEXT NOT NULL,
                items INTEGER NOT NULL,
                bytes_freed INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS security_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                check_title TEXT NOT NULL,
                action TEXT NOT NULL,
                commands TEXT NOT NULL,
                before TEXT NOT NULL,
                after TEXT NOT NULL,
                result TEXT NOT NULL,
                undo_json TEXT,
                undone INTEGER NOT NULL DEFAULT 0
            );",
        )
        .map_err(|e| e.to_string())?;
        Ok(History { conn })
    }

    /// per_category: (label, item_count, bytes_freed). Rows with 0 items are skipped
    /// (same as the Python app).
    pub fn record_cleanup(&self, per_category: &[(String, u64, u64)]) -> Result<(), String> {
        let ts = crate::util::now_string();
        for (label, count, freed) in per_category {
            if *count > 0 {
                self.conn
                    .execute(
                        "INSERT INTO cleanups (ts, category, items, bytes_freed) VALUES (?1, ?2, ?3, ?4)",
                        params![ts, label, *count as i64, *freed as i64],
                    )
                    .map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    pub fn load_cleanups(&self, limit: usize) -> Result<Vec<CleanupRow>, String> {
        let mut st = self
            .conn
            .prepare("SELECT ts, category, items, bytes_freed FROM cleanups ORDER BY id DESC LIMIT ?1")
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map(params![limit as i64], |r| {
                Ok(CleanupRow {
                    ts: r.get(0)?,
                    category: r.get(1)?,
                    items: r.get(2)?,
                    bytes_freed: r.get(3)?,
                })
            })
            .map_err(|e| e.to_string())?;
        Ok(rows.flatten().collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_action(
        &self,
        check_title: &str,
        action: &str,
        commands: &str,
        before: &str,
        after: &str,
        result: &str,
        undo_json: Option<&str>,
    ) -> Result<i64, String> {
        self.conn
            .execute(
                "INSERT INTO security_actions (ts, check_title, action, commands, before, after, result, undo_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![crate::util::now_string(), check_title, action, commands, before, after, result, undo_json],
            )
            .map_err(|e| e.to_string())?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn mark_undone(&self, id: i64) -> Result<(), String> {
        self.conn
            .execute("UPDATE security_actions SET undone = 1 WHERE id = ?1", params![id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn load_actions(&self, limit: usize) -> Result<Vec<ActionRow>, String> {
        let mut st = self
            .conn
            .prepare(
                "SELECT id, ts, check_title, action, commands, before, after, result, undo_json, undone
                 FROM security_actions ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map(params![limit as i64], |r| {
                Ok(ActionRow {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    check_title: r.get(2)?,
                    action: r.get(3)?,
                    commands: r.get(4)?,
                    before: r.get(5)?,
                    after: r.get(6)?,
                    result: r.get(7)?,
                    undo_json: r.get(8)?,
                    undone: r.get::<_, i64>(9)? != 0,
                })
            })
            .map_err(|e| e.to_string())?;
        Ok(rows.flatten().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let p = std::env::temp_dir().join(format!("mcp-hist-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let h = History::open(&p).unwrap();
        h.record_cleanup(&[("Trash".into(), 3, 300), ("Logs".into(), 0, 0)]).unwrap();
        let rows = h.load_cleanups(10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].category, "Trash");
        assert_eq!(rows[0].bytes_freed, 300);

        let id = h
            .record_action("Firewall", "Turn on", "socketfilterfw --setglobalstate on", "off", "on", "ok", Some("[]"))
            .unwrap();
        h.mark_undone(id).unwrap();
        let a = h.load_actions(10).unwrap();
        assert_eq!(a.len(), 1);
        assert!(a[0].undone);
        assert_eq!(a[0].undo_json.as_deref(), Some("[]"));
        std::fs::remove_file(&p).unwrap();
    }
}
