//! Отчёт `tmnode doctor` (формат `tmnode.report/1`, docs/tmnode.md).
//!
//! JSON — контракт: его читают admin-сервис и скрипты, поэтому
//! идентификаторы проверок и значения статусов не меняются внутри версии
//! формата. Новые проверки и новые поля `data` добавлять можно, менять
//! смысл существующих — только с новой версией формата.

use std::fmt::Write as _;

use serde::Serialize;
use serde_json::{Map, Value};

pub const REPORT_FORMAT: &str = "tmnode.report/1";

/// Итог проверки. Порядок — от лучшего к худшему: итог отчёта — худший из
/// статусов его проверок.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Всё в порядке.
    Ok,
    /// Проверка неприменима или ей не хватило предыдущей (причина — в
    /// `summary`).
    Skip,
    /// Работает, но требует внимания.
    Warn,
    /// `tmnode` не смог выяснить ответ (нет прав, нет утилиты): о ноде это
    /// ничего не говорит, но и здоровой её не показывает.
    Error,
    /// Нода сломана или сломается.
    Fail,
}

impl Status {
    fn marker(self) -> &'static str {
        match self {
            Self::Ok => "✓",
            Self::Skip => "–",
            Self::Warn => "!",
            Self::Error => "?",
            Self::Fail => "✗",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    /// Стабильный идентификатор, например `host.disk`.
    pub id: &'static str,
    pub status: Status,
    /// Одна строка для человека.
    pub summary: String,
    /// Что сделать, если статус не `ok`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// Машиночитаемые подробности. Секретов здесь не бывает.
    #[serde(skip_serializing_if = "Map::is_empty")]
    pub data: Map<String, Value>,
}

impl Check {
    pub fn new(id: &'static str, status: Status, summary: impl Into<String>) -> Self {
        Self {
            id,
            status,
            summary: summary.into(),
            hint: None,
            data: Map::new(),
        }
    }

    pub fn ok(id: &'static str, summary: impl Into<String>) -> Self {
        Self::new(id, Status::Ok, summary)
    }

    pub fn skip(id: &'static str, summary: impl Into<String>) -> Self {
        Self::new(id, Status::Skip, summary)
    }

    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn data(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.data.insert(key.to_owned(), value.into());
        self
    }
}

/// Что проверялось.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Target {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_key: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Counts {
    pub ok: usize,
    pub skip: usize,
    pub warn: usize,
    pub error: usize,
    pub fail: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub format: &'static str,
    pub tmnode_version: &'static str,
    /// Unix-время составления отчёта, секунды.
    pub generated_at: u64,
    pub target: Target,
    pub status: Status,
    pub counts: Counts,
    pub checks: Vec<Check>,
}

impl Report {
    pub fn new(target: Target, checks: Vec<Check>, generated_at: u64) -> Self {
        let mut counts = Counts::default();
        for check in &checks {
            match check.status {
                Status::Ok => counts.ok += 1,
                Status::Skip => counts.skip += 1,
                Status::Warn => counts.warn += 1,
                Status::Error => counts.error += 1,
                Status::Fail => counts.fail += 1,
            }
        }
        let status = checks.iter().map(|c| c.status).max().unwrap_or(Status::Ok);
        Self {
            format: REPORT_FORMAT,
            tmnode_version: env!("CARGO_PKG_VERSION"),
            generated_at,
            target,
            status,
            counts,
            checks,
        }
    }

    /// Код выхода: 0 — нода в порядке (предупреждения допустимы, со
    /// `strict` — нет), 1 — есть `fail` или `error`. Код 2 (неверный вызов)
    /// выдаёт CLI до составления отчёта.
    pub fn exit_code(&self, strict: bool) -> i32 {
        let limit = if strict { Status::Skip } else { Status::Warn };
        if self.status <= limit { 0 } else { 1 }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("report is always serializable")
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let what = self
            .target
            .addr
            .as_deref()
            .or(self.target.container.as_deref())
            .unwrap_or("нода");
        let _ = writeln!(out, "tmnode doctor — {what}\n");
        let width = self.checks.iter().map(|c| c.id.len()).max().unwrap_or(0);
        for check in &self.checks {
            let _ = writeln!(
                out,
                "  {} {:width$}  {}",
                check.status.marker(),
                check.id,
                check.summary
            );
            if let Some(hint) = &check.hint
                && check.status != Status::Ok
            {
                let _ = writeln!(out, "    {:width$}  → {hint}", "");
            }
        }
        let c = &self.counts;
        let _ = writeln!(
            out,
            "\nИтог: ок {}, предупреждений {}, ошибок {}, не удалось проверить {}, пропущено {}",
            c.ok, c.warn, c.fail, c.error, c.skip
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(statuses: &[Status]) -> Report {
        let checks = statuses
            .iter()
            .map(|s| Check::new("x.y", *s, "что-то"))
            .collect();
        Report::new(Target::default(), checks, 1)
    }

    #[test]
    fn overall_status_is_the_worst_one() {
        assert_eq!(report(&[]).status, Status::Ok);
        assert_eq!(report(&[Status::Ok, Status::Skip]).status, Status::Skip);
        assert_eq!(report(&[Status::Warn, Status::Ok]).status, Status::Warn);
        assert_eq!(report(&[Status::Fail, Status::Error]).status, Status::Fail);
        assert_eq!(report(&[Status::Error, Status::Warn]).status, Status::Error);
    }

    #[test]
    fn exit_code_follows_strictness() {
        assert_eq!(report(&[Status::Ok, Status::Skip]).exit_code(true), 0);
        assert_eq!(report(&[Status::Warn]).exit_code(false), 0);
        assert_eq!(report(&[Status::Warn]).exit_code(true), 1);
        assert_eq!(report(&[Status::Error]).exit_code(false), 1);
        assert_eq!(report(&[Status::Fail]).exit_code(false), 1);
    }

    #[test]
    fn json_carries_the_contract_fields() {
        let checks = vec![
            Check::ok("endpoint.tcp", "порт открыт").data("connect_ms", 12),
            Check::new("host.disk", Status::Warn, "мало места").hint("расширьте диск"),
        ];
        let target = Target {
            addr: Some("203.0.113.10:18081".into()),
            ..Target::default()
        };
        let json: Value = serde_json::from_str(&Report::new(target, checks, 42).to_json()).unwrap();

        assert_eq!(json["format"], "tmnode.report/1");
        assert_eq!(json["generated_at"], 42);
        assert_eq!(json["status"], "warn");
        assert_eq!(json["counts"]["ok"], 1);
        assert_eq!(json["counts"]["warn"], 1);
        assert_eq!(json["target"]["addr"], "203.0.113.10:18081");
        assert!(json["target"].get("config").is_none());
        assert_eq!(json["checks"][0]["id"], "endpoint.tcp");
        assert_eq!(json["checks"][0]["data"]["connect_ms"], 12);
        assert!(json["checks"][0].get("hint").is_none());
        assert_eq!(json["checks"][1]["hint"], "расширьте диск");
        assert!(json["checks"][1].get("data").is_none());
    }

    #[test]
    fn text_shows_hints_only_for_problems() {
        let checks = vec![
            Check::ok("endpoint.tcp", "порт открыт").hint("не показывать"),
            Check::new("host.disk", Status::Fail, "мало места").hint("расширьте диск"),
        ];
        let text = Report::new(Target::default(), checks, 0).to_text();
        assert!(text.contains("✓ endpoint.tcp"));
        assert!(text.contains("✗ host.disk"));
        assert!(text.contains("→ расширьте диск"));
        assert!(!text.contains("не показывать"));
        assert!(text.contains("ок 1, предупреждений 0, ошибок 1"));
    }
}
