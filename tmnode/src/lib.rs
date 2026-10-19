//! `tmnode` — обслуживание ноды TrustMe: развёртывание, проверка,
//! обновление (docs/tmnode.md).
//!
//! Логика живёт в библиотеке, CLI — тонкая оболочка над ней: тот же код
//! позже вызовет агент admin-сервиса, управляющий парком нод.

pub mod agent;
pub mod cli;
pub mod doctor;
pub mod install;
pub mod node_config;
pub mod ops;
pub mod protocol;
pub mod report;
pub mod system;
