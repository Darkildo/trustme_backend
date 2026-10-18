//! `tmnode` — обслуживание ноды TrustMe: развёртывание, проверка,
//! обновление (docs/tmnode.md).
//!
//! Логика живёт в библиотеке, CLI — тонкая оболочка над ней: тот же код
//! позже вызовет агент admin-сервиса, управляющий парком нод.

pub mod cli;
pub mod doctor;
pub mod node_config;
pub mod report;
pub mod system;
