//! Обновление ноды и `tmnode` на подставном сервере: точный список команд
//! docker, откат, отказы, самообновление, продолжение после перезапуска и
//! восстановление после падения.

mod common;

use common::host::{
    Behaviour, Ctr, INSIDE, NODE, NOW, PATH_ENV, PREV, RELEASES, Setup, Steps, VolumeMount, image,
    image_id, node_ctr, secret, setup, sha256,
};
use tmnode::agent::{self, AdminApi, Next};
use tmnode::ops;
use tmnode::protocol::{
    EnrollRequest, EnrollResponse, Heartbeat, HeartbeatResponse, TmnodeRelease, UpdateOrder,
    UpdateState, UpdateStatus, UpdateStep,
};
use tmnode::update::{Origin, Outcome, Saved};

const MANAGED: &str = "managed";

fn order(id: &str, node: Option<&str>) -> UpdateOrder {
    UpdateOrder {
        id: id.into(),
        node_version: node.map(Into::into),
        tmnode: None,
        allow_downgrade: false,
    }
}

fn with_tmnode(mut order: UpdateOrder, version: &str, sha: &str) -> UpdateOrder {
    order.tmnode = Some(TmnodeRelease {
        version: version.into(),
        sha256: sha.into(),
    });
    order
}

fn done(outcome: Outcome) -> UpdateStatus {
    match outcome {
        Outcome::Done(status) => status,
        other => panic!("ожидался итог, получено {other:?}"),
    }
}

/// Команды пересоздания контейнера ноды до `docker start` нового.
fn recreate_commands(s: &Setup, version: &str) -> Vec<String> {
    vec![
        format!("docker pull {}", image(version)),
        format!("docker inspect --type container {NODE}"),
        format!("docker inspect --type container {PREV}"),
        format!("docker image inspect {}", image_id("0.6.0")),
        format!("docker stop -t 30 {NODE}"),
        format!("docker rename {NODE} {PREV}"),
        format!("docker update --restart no {PREV}"),
        format!(
            "docker create --name {NODE} --restart unless-stopped --network trustme \
             -p 18081:18081/tcp -v {}:{INSIDE} --env-file {} {}",
            common::DATA,
            s.env_file().display(),
            image(version)
        ),
        format!("docker start {NODE}"),
    ]
}

fn rollback_commands() -> Vec<String> {
    vec![
        format!("docker logs --tail 20 {NODE}"),
        format!("docker inspect --type container {NODE}"),
        format!("docker rm -f {NODE}"),
        format!("docker rename {PREV} {NODE}"),
        format!("docker update --restart unless-stopped {NODE}"),
        format!("docker start {NODE}"),
    ]
}

/// Секрет из окружения контейнера нигде не всплыл.
fn assert_no_secret(s: &Setup, status: &UpdateStatus) {
    let secret = secret();
    assert!(!serde_json::to_string(status).unwrap().contains(&secret));
    assert!(!s.state_file().contains(&secret));
    assert!(
        !s.host.commands().iter().any(|c| c.contains(&secret)),
        "секрет в командной строке"
    );
    assert!(
        s.host.file(&s.env_file()).is_none(),
        "файл окружения остался"
    );
}

#[tokio::test]
async fn node_is_updated_and_verified() {
    let s = setup("node_ok", MANAGED, "");
    let steps = Steps::default();
    let status = done(
        s.updater("0.6.0", Origin::Admin)
            .execute(&order("01upd", Some("0.7.0")), &steps)
            .await,
    );
    assert_eq!(status.state, UpdateState::Succeeded, "{:?}", status.error);
    assert_eq!(status.step, Some(UpdateStep::Verify));
    assert_eq!(status.from_node_image, Some(image("0.6.0")));
    assert_eq!(status.node_image, Some(image("0.7.0")));
    assert_eq!(status.tmnode.as_deref(), Some("0.6.0"));
    assert_eq!((status.started_at, status.finished_at), (NOW, Some(NOW)));
    assert_eq!(steps.names(), ["pull_image", "recreate", "verify"]);
    assert!(
        steps
            .0
            .borrow()
            .iter()
            .all(|s| s.state == UpdateState::Running)
    );

    let mut expected = recreate_commands(&s, "0.7.0");
    expected.push(format!("docker rm {PREV}"));
    assert_eq!(s.host.commands(), expected);

    let node = s.host.ctr(NODE).unwrap();
    assert!(node.running && node.image == image("0.7.0"));
    assert!(s.host.ctr(PREV).is_none());

    // Окружение: заданное прежним образом (PATH, RUST_LOG=info) отброшено,
    // заданное при запуске — перенесено.
    assert_eq!(
        s.host.created_env.borrow().as_slice(),
        [format!(
            "BIND_PORT=18081\nSTORAGE_PATH={INSIDE}\nNODE_IDENTITY_KEY={}\nMETRICS_ENABLED=true\n",
            secret()
        )]
    );
    assert_eq!(node.env[0], PATH_ENV);

    let saved: Saved = serde_json::from_str(&s.state_file()).unwrap();
    assert_eq!(saved.status, status);
    assert!(!saved.local && !saved.acknowledged);
    assert_no_secret(&s, &status);
}

#[tokio::test]
async fn recreated_container_keeps_ports_volumes_networks_and_restart_policy() {
    let s = setup("node_params", MANAGED, "");
    let old = Ctr {
        restart: "on-failure:3".into(),
        extra_networks: vec!["monitoring".into()],
        ports: vec![
            ("18081/tcp".into(), String::new(), "18081".into()),
            ("9000/tcp".into(), "127.0.0.1".into(), "9000".into()),
        ],
        mounts: vec![
            VolumeMount {
                source: common::DATA.into(),
                destination: INSIDE.into(),
                rw: true,
            },
            VolumeMount {
                source: "blobs".into(),
                destination: "/srv/blobs".into(),
                rw: false,
            },
        ],
        ..node_ctr("0.6.0")
    };
    s.host
        .containers
        .borrow_mut()
        .insert(NODE.into(), old.clone());

    let status = done(
        s.updater("0.6.0", Origin::Admin)
            .execute(&order("01par", Some("0.7.0")), &())
            .await,
    );
    assert_eq!(status.state, UpdateState::Succeeded, "{:?}", status.error);
    let commands = s.host.commands();
    assert!(commands.contains(&format!(
        "docker create --name {NODE} --restart on-failure:3 --network trustme \
         -p 18081:18081/tcp -p 127.0.0.1:9000:9000/tcp -v {}:{INSIDE} -v blobs:/srv/blobs:ro \
         --env-file {} {}",
        common::DATA,
        s.env_file().display(),
        image("0.7.0")
    )));
    assert!(commands.contains(&format!("docker network connect monitoring {NODE}")));

    let new = s.host.ctr(NODE).unwrap();
    assert_eq!(new.ports, old.ports);
    assert_eq!(new.mounts, old.mounts);
    assert_eq!(new.network, old.network);
    assert_eq!(new.extra_networks, old.extra_networks);
    assert_eq!(new.restart, old.restart);
    assert_eq!(new.image_id, image_id("0.7.0"));
}

#[tokio::test]
async fn changed_key_rolls_back_to_the_previous_container() {
    let s = setup("rollback_key", MANAGED, "");
    s.host.set_behaviour("0.7.0", Behaviour::RotatesKey);
    let steps = Steps::default();
    let status = done(
        s.updater("0.6.0", Origin::Admin)
            .execute(&order("01key", Some("0.7.0")), &steps)
            .await,
    );
    assert_eq!(status.state, UpdateState::RolledBack);
    assert_eq!(status.step, Some(UpdateStep::Rollback));
    assert_eq!(status.node_image, Some(image("0.6.0")));
    let error = status.error.clone().unwrap();
    assert!(error.contains("ключ ноды сменился"), "{error}");
    // Хвост журнала: последние строки, секрет вычищен.
    assert!(error.contains("docker logs message-service:"), "{error}");
    assert!(
        error.contains("паника") && !error.contains("строка 10\n"),
        "{error}"
    );
    assert!(error.contains("NODE_IDENTITY_KEY=***"), "{error}");
    assert_eq!(
        steps.names(),
        ["pull_image", "recreate", "verify", "rollback"]
    );
    // Ключ сменился — ждать нечего: откат с первой проверки.
    assert_eq!(*s.host.sleeps.borrow(), 0);

    let mut expected = recreate_commands(&s, "0.7.0");
    expected.extend(rollback_commands());
    assert_eq!(s.host.commands(), expected);

    let node = s.host.ctr(NODE).unwrap();
    assert!(node.running);
    assert_eq!(node, node_ctr("0.6.0"));
    assert!(s.host.ctr(PREV).is_none());
    assert_no_secret(&s, &status);
}

#[tokio::test]
async fn failed_handshake_is_retried_for_two_minutes_then_rolled_back() {
    let s = setup("rollback_handshake", MANAGED, "");
    s.host.set_behaviour("0.7.0", Behaviour::NoHandshake);
    let status = done(
        s.updater("0.6.0", Origin::Admin)
            .execute(&order("01hs", Some("0.7.0")), &())
            .await,
    );
    assert_eq!(status.state, UpdateState::RolledBack);
    let error = status.error.unwrap();
    assert!(
        error.contains("за 120 с") && error.contains("endpoint.handshake"),
        "{error}"
    );
    // 24 проверки по 5 секунд.
    assert_eq!(*s.host.sleeps.borrow(), 23);
    assert_eq!(s.host.ctr(NODE).unwrap().image, image("0.6.0"));
}

#[tokio::test]
async fn container_that_does_not_start_is_replaced_by_the_previous_one() {
    let s = setup("rollback_crash", MANAGED, "");
    s.host.set_behaviour("0.7.0", Behaviour::Crashes);
    let status = done(
        s.updater("0.6.0", Origin::Admin)
            .execute(&order("01crash", Some("0.7.0")), &())
            .await,
    );
    assert_eq!(status.state, UpdateState::RolledBack);
    assert!(status.error.unwrap().contains("не работает"));
    assert!(s.host.ctr(NODE).unwrap().running);

    // docker create упал — новый контейнер не появился, прежний запущен.
    let s = setup("create_fails", MANAGED, "");
    s.host.failing.borrow_mut().push("docker create".into());
    let status = done(
        s.updater("0.6.0", Origin::Admin)
            .execute(&order("01create", Some("0.7.0")), &())
            .await,
    );
    assert_eq!(status.state, UpdateState::Failed);
    assert!(status.error.unwrap().contains("работает прежний"));
    assert_eq!(s.host.ctr(NODE).unwrap(), node_ctr("0.6.0"));
    assert!(s.host.file(&s.env_file()).is_none());
}

#[tokio::test]
async fn orders_the_agent_must_refuse() {
    let refused = |label: &str, mode: &str, extra: &str, order: UpdateOrder, origin: Origin| {
        let label = label.to_owned();
        let mode = mode.to_owned();
        let extra = extra.to_owned();
        async move {
            let s = setup(&label, &mode, &extra);
            let status = done(s.updater("0.6.0", origin).execute(&order, &()).await);
            assert_eq!(
                status.state,
                UpdateState::Refused,
                "{label}: {:?}",
                status.error
            );
            assert_eq!(status.step, Some(UpdateStep::Check), "{label}");
            assert!(
                s.host.commands().is_empty(),
                "{label}: {:?}",
                s.host.commands()
            );
            assert!(s.releases.fetched.borrow().is_empty(), "{label}");
            assert_eq!(s.host.ctr(NODE).unwrap(), node_ctr("0.6.0"));
            status.error.unwrap()
        }
    };

    let why = refused(
        "local",
        "local",
        "",
        order("a", Some("0.7.0")),
        Origin::Admin,
    )
    .await;
    assert!(why.contains("managed"), "{why}");
    let why = refused(
        "cli_on_managed",
        MANAGED,
        "",
        order("a", Some("0.7.0")),
        Origin::Local,
    )
    .await;
    assert!(why.contains("из панели"), "{why}");
    let pinned = "[updates]\nchannel = \"pinned\"\nversion = \"0.6.5\"\n";
    let why = refused(
        "pinned",
        MANAGED,
        pinned,
        order("a", Some("0.7.0")),
        Origin::Admin,
    )
    .await;
    assert!(why.contains("закреплена версия 0.6.5"), "{why}");
    let why = refused(
        "down",
        MANAGED,
        "",
        order("a", Some("0.5.0")),
        Origin::Admin,
    )
    .await;
    assert!(why.contains("allow_downgrade"), "{why}");
    let bad_sha = with_tmnode(order("a", Some("0.7.0")), "0.7.0", "xyz");
    let why = refused("sha", MANAGED, "", bad_sha, Origin::Admin).await;
    assert!(why.contains("64 hex"), "{why}");
    let why = refused("ver", MANAGED, "", order("a", Some("0.7")), Origin::Admin).await;
    assert!(why.contains("X.Y.Z"), "{why}");
    let why = refused(
        "vee",
        MANAGED,
        "",
        order("a", Some("v0.7.0")),
        Origin::Admin,
    )
    .await;
    assert!(why.contains("X.Y.Z"), "{why}");
    let why = refused("empty", MANAGED, "", order("a", None), Origin::Admin).await;
    assert!(why.contains("пустое"), "{why}");
    let old_tmnode = with_tmnode(order("a", None), "0.1.9", &"a".repeat(64));
    let why = refused("tm_down", MANAGED, "", old_tmnode, Origin::Admin).await;
    assert!(why.contains("tmnode 0.6.0 новее 0.1.9"), "{why}");
    let why = refused(
        "id",
        MANAGED,
        "",
        order("a b", Some("0.7.0")),
        Origin::Admin,
    )
    .await;
    assert!(why.contains("id"), "{why}");
}

#[tokio::test]
async fn allowed_orders_go_ahead() {
    // Закреплённая версия совпадает с заданием.
    let s = setup(
        "pinned_ok",
        MANAGED,
        "[updates]\nchannel = \"pinned\"\nversion = \"0.7.0\"\n",
    );
    let status = done(
        s.updater("0.6.0", Origin::Admin)
            .execute(&order("p", Some("0.7.0")), &())
            .await,
    );
    assert_eq!(status.state, UpdateState::Succeeded, "{:?}", status.error);

    // Понижение с allow_downgrade.
    let s = setup("down_ok", MANAGED, "");
    let mut down = order("d", Some("0.5.0"));
    down.allow_downgrade = true;
    let status = done(s.updater("0.6.0", Origin::Admin).execute(&down, &()).await);
    assert_eq!(status.state, UpdateState::Succeeded, "{:?}", status.error);
    assert_eq!(s.host.ctr(NODE).unwrap().image, image("0.5.0"));

    // Текущая версия — эта часть уже выполнена: ничего не трогаем.
    let s = setup("same", MANAGED, "");
    let status = done(
        s.updater("0.6.0", Origin::Admin)
            .execute(&order("s", Some("0.6.0")), &())
            .await,
    );
    assert_eq!(status.state, UpdateState::Succeeded);
    assert!(s.host.commands().is_empty());

    // Своя нода без админки — через tmnode update.
    let s = setup("local_ok", "local", "");
    let status = done(
        s.updater("0.6.0", Origin::Local)
            .execute(&order("local-1", Some("0.7.0")), &())
            .await,
    );
    assert_eq!(status.state, UpdateState::Succeeded, "{:?}", status.error);
    let saved: Saved = serde_json::from_str(&s.state_file()).unwrap();
    assert!(saved.local);
    // В админку задание из tmnode update не уходит.
    assert!(s.updater("0.6.0", Origin::Admin).report().is_none());
}

#[tokio::test]
async fn image_that_cannot_be_pulled_changes_nothing() {
    let s = setup("pull_fails", MANAGED, "");
    let status = done(
        s.updater("0.6.0", Origin::Admin)
            .execute(&order("n", Some("0.9.0")), &())
            .await,
    );
    assert_eq!(status.state, UpdateState::Failed);
    assert!(status.error.unwrap().contains("docker pull"));
    assert_eq!(
        s.host.commands(),
        [format!("docker pull {}", image("0.9.0"))]
    );
    assert_eq!(s.host.ctr(NODE).unwrap(), node_ctr("0.6.0"));
}

#[tokio::test]
async fn checksums_must_match_both_the_release_and_the_order() {
    let binary = b"new tmnode 0.7.0".to_vec();

    // SHA256SUMS релиза не совпадает с заданием.
    let s = setup("sums_vs_order", MANAGED, "");
    s.releases.publish("0.7.0", &binary);
    let status = done(
        s.updater("0.6.0", Origin::Admin)
            .execute(
                &with_tmnode(order("t", Some("0.7.0")), "0.7.0", &"ab".repeat(32)),
                &(),
            )
            .await,
    );
    assert_eq!(status.state, UpdateState::Failed);
    assert!(status.error.unwrap().contains("SHA256SUMS"));
    assert_eq!(
        s.releases.fetched.borrow().as_slice(),
        [format!("{RELEASES}/v0.7.0/SHA256SUMS")]
    );
    assert_eq!(s.host.file(&s.tmnode_path).unwrap(), b"old tmnode");

    // Задание и SHA256SUMS согласны, а файл — другой.
    let s = setup("file_vs_sums", MANAGED, "");
    s.releases.publish("0.7.0", b"tampered");
    s.releases.publish_sums("0.7.0", &sha256(&binary));
    let status = done(
        s.updater("0.6.0", Origin::Admin)
            .execute(
                &with_tmnode(order("t", Some("0.7.0")), "0.7.0", &sha256(&binary)),
                &(),
            )
            .await,
    );
    assert_eq!(status.state, UpdateState::Failed);
    assert!(status.error.unwrap().contains("скачанного"));
    assert!(s.host.commands().is_empty());
    assert_eq!(s.host.file(&s.tmnode_path).unwrap(), b"old tmnode");

    // Бинарь сходится, но печатает не ту версию.
    let s = setup("wrong_version", MANAGED, "");
    s.releases.publish("0.7.0", &binary);
    *s.host.new_binary_says.borrow_mut() = "tmnode 0.2.9\n".into();
    let status = done(
        s.updater("0.6.0", Origin::Admin)
            .execute(
                &with_tmnode(order("t", Some("0.7.0")), "0.7.0", &sha256(&binary)),
                &(),
            )
            .await,
    );
    assert_eq!(status.state, UpdateState::Failed);
    assert!(status.error.unwrap().contains("tmnode 0.2.9"));
    assert_eq!(s.host.file(&s.tmnode_path).unwrap(), b"old tmnode");
    assert!(
        s.host
            .file(&s.tmnode_path.with_file_name("tmnode.new"))
            .is_none()
    );
    assert_eq!(status.tmnode.as_deref(), Some("0.6.0"));
}

/// Прежний агент меняет бинарь и завершается; новый дочитывает задание.
#[tokio::test]
async fn tmnode_replaces_itself_and_the_new_agent_finishes_the_order() {
    let s = setup("self_update", MANAGED, "");
    let binary = b"new tmnode 0.7.0".to_vec();
    s.releases.publish("0.7.0", &binary);
    *s.host.new_binary_says.borrow_mut() = "tmnode 0.7.0\n".into();
    let job = with_tmnode(order("01self", Some("0.7.0")), "0.7.0", &sha256(&binary));
    let steps = Steps::default();

    let outcome = s
        .updater("0.6.0", Origin::Admin)
        .execute(&job, &steps)
        .await;
    let Outcome::Restart(status) = outcome else {
        panic!("ожидался перезапуск: {outcome:?}");
    };
    assert_eq!(
        (status.state, status.step),
        (UpdateState::Running, Some(UpdateStep::RestartAgent))
    );
    assert_eq!(
        (status.from_tmnode.as_deref(), status.tmnode.as_deref()),
        (Some("0.6.0"), Some("0.7.0"))
    );
    assert_eq!(steps.names(), ["download_tmnode", "restart_agent"]);
    assert_eq!(
        s.releases.fetched.borrow().as_slice(),
        [
            format!("{RELEASES}/v0.7.0/SHA256SUMS"),
            format!("{RELEASES}/v0.7.0/tmnode-x86_64-linux")
        ]
    );
    let new = s.tmnode_path.with_file_name("tmnode.new");
    assert_eq!(s.host.commands(), [format!("{} version", new.display())]);
    {
        let files = s.host.files.borrow();
        assert_eq!(files[&s.tmnode_path], (binary.clone(), 0o755));
        assert_eq!(
            files[&s.tmnode_path.with_file_name("tmnode.prev")].0,
            b"old tmnode"
        );
        assert!(!files.contains_key(&new));
    }
    let saved: Saved = serde_json::from_str(&s.state_file()).unwrap();
    assert_eq!(saved.status, status);

    // Тот же агент второй раз задание не начинает.
    s.host.commands.borrow_mut().clear();

    // Новый агент после перезапуска службы.
    let steps = Steps::default();
    let status = done(
        s.updater("0.7.0", Origin::Admin)
            .resume(&steps)
            .await
            .expect("задание дочитано"),
    );
    assert_eq!(status.state, UpdateState::Succeeded, "{:?}", status.error);
    assert_eq!(
        (status.from_tmnode.as_deref(), status.tmnode.as_deref()),
        (Some("0.6.0"), Some("0.7.0"))
    );
    assert_eq!(status.node_image, Some(image("0.7.0")));
    assert_eq!(steps.names(), ["pull_image", "recreate", "verify"]);
    let mut expected = recreate_commands(&s, "0.7.0");
    expected.push(format!("docker rm {PREV}"));
    assert_eq!(s.host.commands(), expected);

    // Дочитывать больше нечего, повтор задания — тот же итог.
    assert!(
        s.updater("0.7.0", Origin::Admin)
            .resume(&())
            .await
            .is_none()
    );
}

#[tokio::test]
async fn agent_that_did_not_change_after_restart_reports_failure() {
    let s = setup("self_update_lost", MANAGED, "");
    let binary = b"new tmnode 0.7.0".to_vec();
    s.releases.publish("0.7.0", &binary);
    *s.host.new_binary_says.borrow_mut() = "tmnode 0.7.0".into();
    let job = with_tmnode(order("01lost", Some("0.7.0")), "0.7.0", &sha256(&binary));
    let up = s.updater("0.6.0", Origin::Admin);
    assert!(matches!(up.execute(&job, &()).await, Outcome::Restart(_)));

    // Служба поднялась прежним бинарём (скажем, его вернули руками).
    let status = done(up.resume(&()).await.unwrap());
    assert_eq!(status.state, UpdateState::Failed);
    assert!(status.error.unwrap().contains("работает tmnode 0.6.0"));
    assert_eq!(s.host.ctr(NODE).unwrap(), node_ctr("0.6.0"));
}

#[tokio::test]
async fn tmnode_release_is_the_tmnode_version_not_the_node_one() {
    // Нода ставится из v0.7.0, tmnode — из своего релиза v0.8.0.
    let s = setup("tmnode_release", MANAGED, "");
    let binary = b"new tmnode 0.8.0".to_vec();
    s.releases.publish("0.8.0", &binary);
    s.releases.publish("0.7.0", b"tmnode 0.7.0 binary");
    *s.host.new_binary_says.borrow_mut() = "tmnode 0.8.0".into();
    let job = with_tmnode(order("01rel", Some("0.7.0")), "0.8.0", &sha256(&binary));
    let outcome = s.updater("0.6.0", Origin::Admin).execute(&job, &()).await;
    assert!(matches!(outcome, Outcome::Restart(_)), "{outcome:?}");
    assert_eq!(
        s.releases.fetched.borrow().as_slice(),
        [
            format!("{RELEASES}/v0.8.0/SHA256SUMS"),
            format!("{RELEASES}/v0.8.0/tmnode-x86_64-linux")
        ]
    );
    assert_eq!(s.host.file(&s.tmnode_path).unwrap(), binary);
    let status = done(s.updater("0.8.0", Origin::Admin).resume(&()).await.unwrap());
    assert_eq!(status.state, UpdateState::Succeeded, "{:?}", status.error);
    assert_eq!(status.node_image, Some(image("0.7.0")));
    assert_eq!(status.tmnode.as_deref(), Some("0.8.0"));
}

#[tokio::test]
async fn only_tmnode_is_updated_even_on_a_stable_image() {
    let s = setup("tmnode_only_stable", MANAGED, "");
    let stable = "ghcr.io/darkildo/trustme_backend:stable".to_owned();
    s.host.containers.borrow_mut().get_mut(NODE).unwrap().image = stable.clone();
    let binary = b"new tmnode".to_vec();
    s.releases.publish("0.7.0", &binary);
    *s.host.new_binary_says.borrow_mut() = "tmnode 0.7.0".into();
    let job = with_tmnode(order("01tm", None), "0.7.0", &sha256(&binary));

    let outcome = s.updater("0.6.0", Origin::Admin).execute(&job, &()).await;
    assert!(matches!(outcome, Outcome::Restart(_)), "{outcome:?}");
    assert_eq!(
        s.releases.fetched.borrow()[0],
        format!("{RELEASES}/v0.7.0/SHA256SUMS")
    );
    let status = done(s.updater("0.7.0", Origin::Admin).resume(&()).await.unwrap());
    assert_eq!(status.state, UpdateState::Succeeded, "{:?}", status.error);
    assert_eq!(status.node_image, Some(stable.clone()));
    assert_eq!(
        (status.from_tmnode.as_deref(), status.tmnode.as_deref()),
        (Some("0.6.0"), Some("0.7.0"))
    );
    // Ноду не трогали: только `tmnode.new version`.
    assert_eq!(s.host.commands().len(), 1, "{:?}", s.host.commands());
    assert_eq!(s.host.ctr(NODE).unwrap().image, stable);
}

#[tokio::test]
async fn the_same_order_runs_once() {
    let s = setup("repeat", MANAGED, "");
    let up = s.updater("0.6.0", Origin::Admin);
    let job = order("01once", Some("0.7.0"));
    let first = done(up.execute(&job, &()).await);
    assert_eq!(first.state, UpdateState::Succeeded);
    let ran = s.host.commands().len();

    let again = done(up.execute(&job, &()).await);
    assert_eq!(again, first);
    assert_eq!(s.host.commands().len(), ran, "повтор ничего не делает");

    // Отказ тоже итог: повтор не переспрашивает.
    let s = setup("repeat_refused", "local", "");
    let up = s.updater("0.6.0", Origin::Admin);
    let first = done(up.execute(&order("01no", Some("0.7.0")), &()).await);
    let again = done(up.execute(&order("01no", Some("0.7.0")), &()).await);
    assert_eq!(first, again);
    assert_eq!(first.state, UpdateState::Refused);
}

/// `update.json` агента, упавшего на шаге `step`.
fn crashed_on(s: &Setup, step: UpdateStep) {
    let saved = Saved {
        order: order("01crash", Some("0.7.0")),
        status: UpdateStatus {
            id: "01crash".into(),
            state: UpdateState::Running,
            step: Some(step),
            error: None,
            started_at: NOW - 60,
            finished_at: None,
            from_node_image: Some(image("0.6.0")),
            node_image: Some(image("0.6.0")),
            from_tmnode: Some("0.6.0".into()),
            tmnode: Some("0.6.0".into()),
        },
        local: false,
        acknowledged: false,
        restart_policy: Some("unless-stopped".into()),
    };
    use tmnode::install::Runner;
    s.host
        .write_file(
            &s.layout.etc_dir.join("update.json"),
            serde_json::to_string(&saved).unwrap().as_bytes(),
            0o600,
            None,
        )
        .unwrap();
    // Окружение для docker create осталось на диске.
    s.host
        .write_file(&s.env_file(), b"NODE_IDENTITY_KEY=x\n", 0o600, None)
        .unwrap();
}

/// Прежний контейнер уже переименован и остановлен.
fn renamed_old(s: &Setup) {
    let mut containers = s.host.containers.borrow_mut();
    let mut old = containers.remove(NODE).unwrap();
    old.running = false;
    old.restart = String::new();
    containers.insert(PREV.into(), old);
}

#[tokio::test]
async fn crash_in_the_middle_of_recreate_is_rolled_back() {
    // Новый контейнер так и не создан.
    let s = setup("crash_recreate", MANAGED, "");
    renamed_old(&s);
    crashed_on(&s, UpdateStep::Recreate);
    let status = done(s.updater("0.6.0", Origin::Admin).resume(&()).await.unwrap());
    assert_eq!(status.state, UpdateState::RolledBack, "{:?}", status.error);
    assert!(status.error.unwrap().contains("recreate"));
    assert_eq!(status.node_image, Some(image("0.6.0")));
    assert_eq!(
        s.host.commands(),
        [
            format!("docker inspect --type container {PREV}"),
            format!("docker inspect --type container {NODE}"),
            format!("docker inspect --type container {NODE}"),
            format!("docker rename {PREV} {NODE}"),
            format!("docker update --restart unless-stopped {NODE}"),
            format!("docker start {NODE}"),
        ]
    );
    assert_eq!(s.host.ctr(NODE).unwrap(), node_ctr("0.6.0"));
    assert!(s.host.file(&s.env_file()).is_none());

    // Новый создан, но не работает.
    let s = setup("crash_recreate_dead", MANAGED, "");
    renamed_old(&s);
    let mut dead = node_ctr("0.7.0");
    dead.running = false;
    s.host.containers.borrow_mut().insert(NODE.into(), dead);
    crashed_on(&s, UpdateStep::Recreate);
    let status = done(s.updater("0.6.0", Origin::Admin).resume(&()).await.unwrap());
    assert_eq!(status.state, UpdateState::RolledBack);
    assert!(s.host.commands().contains(&format!("docker rm -f {NODE}")));
    assert_eq!(s.host.ctr(NODE).unwrap(), node_ctr("0.6.0"));
}

#[tokio::test]
async fn crash_after_the_new_container_started_finishes_the_check() {
    let s = setup("crash_verify", MANAGED, "");
    renamed_old(&s);
    s.host
        .containers
        .borrow_mut()
        .insert(NODE.into(), node_ctr("0.7.0"));
    crashed_on(&s, UpdateStep::Recreate);
    let steps = Steps::default();
    let status = done(
        s.updater("0.6.0", Origin::Admin)
            .resume(&steps)
            .await
            .unwrap(),
    );
    assert_eq!(status.state, UpdateState::Succeeded, "{:?}", status.error);
    assert_eq!(status.node_image, Some(image("0.7.0")));
    assert_eq!(steps.names(), ["verify"]);
    assert_eq!(
        s.host.commands().last().unwrap(),
        &format!("docker rm {PREV}")
    );
    assert!(s.host.ctr(PREV).is_none());

    // Проверка уже прошла и прежний удалён — итог не успел записаться.
    let s = setup("crash_verify_done", MANAGED, "");
    s.host
        .containers
        .borrow_mut()
        .insert(NODE.into(), node_ctr("0.7.0"));
    crashed_on(&s, UpdateStep::Verify);
    let status = done(s.updater("0.6.0", Origin::Admin).resume(&()).await.unwrap());
    assert_eq!(status.state, UpdateState::Succeeded);

    // Упал до переименования: прежний контейнер остановлен — запустить.
    let s = setup("crash_before_rename", MANAGED, "");
    s.host
        .containers
        .borrow_mut()
        .get_mut(NODE)
        .unwrap()
        .running = false;
    crashed_on(&s, UpdateStep::Recreate);
    let status = done(s.updater("0.6.0", Origin::Admin).resume(&()).await.unwrap());
    assert_eq!(status.state, UpdateState::Failed);
    assert!(status.error.unwrap().contains("прежний контейнер запущен"));
    assert!(s.host.ctr(NODE).unwrap().running);

    // Упал посреди отката: довести его.
    let s = setup("crash_rollback", MANAGED, "");
    renamed_old(&s);
    s.host
        .containers
        .borrow_mut()
        .insert(NODE.into(), node_ctr("0.7.0"));
    crashed_on(&s, UpdateStep::Rollback);
    let status = done(s.updater("0.6.0", Origin::Admin).resume(&()).await.unwrap());
    assert_eq!(status.state, UpdateState::RolledBack);
    assert_eq!(s.host.ctr(NODE).unwrap(), node_ctr("0.6.0"));

    // Упал на скачивании: машина не менялась.
    let s = setup("crash_pull", MANAGED, "");
    crashed_on(&s, UpdateStep::PullImage);
    let status = done(s.updater("0.6.0", Origin::Admin).resume(&()).await.unwrap());
    assert_eq!(status.state, UpdateState::Failed);
    assert!(s.host.commands().is_empty());
}

#[tokio::test]
async fn a_new_order_first_finishes_the_interrupted_one() {
    let s = setup("interrupted_then_new", MANAGED, "");
    renamed_old(&s);
    crashed_on(&s, UpdateStep::Recreate);
    let status = done(
        s.updater("0.6.0", Origin::Admin)
            .execute(&order("01next", Some("0.7.0")), &())
            .await,
    );
    assert_eq!(status.id, "01next");
    assert_eq!(status.state, UpdateState::Succeeded, "{:?}", status.error);
    assert_eq!(s.host.ctr(NODE).unwrap().image, image("0.7.0"));
}

/// Панель, которая присылает задание, пока его не уберут.
struct Panel {
    beats: std::cell::RefCell<Vec<Heartbeat>>,
    order: std::cell::RefCell<Option<UpdateOrder>>,
}

impl Panel {
    fn sending(order: UpdateOrder) -> Self {
        Self {
            beats: Default::default(),
            order: std::cell::RefCell::new(Some(order)),
        }
    }
}

impl AdminApi for Panel {
    async fn enroll(&self, _request: &EnrollRequest) -> anyhow::Result<EnrollResponse> {
        anyhow::bail!("не нужен")
    }

    async fn heartbeat(&self, beat: &Heartbeat) -> anyhow::Result<HeartbeatResponse> {
        self.beats.borrow_mut().push(beat.clone());
        Ok(HeartbeatResponse {
            interval_secs: 30,
            runtime: None,
            update: self.order.borrow().clone(),
        })
    }
}

#[tokio::test]
async fn agent_runs_the_order_and_reports_until_the_panel_stops() {
    let s = setup("agent_tick", MANAGED, "");
    let panel = Panel::sending(order("01agent", Some("0.7.0")));
    let up = s.updater("0.6.0", Origin::Admin);

    // Обычный heartbeat, затем — по одному перед каждым долгим шагом.
    assert_eq!(agent::tick(&panel, &up).await.unwrap(), Next::Wait(5));
    {
        let beats = panel.beats.borrow();
        assert_eq!(beats.len(), 4);
        assert_eq!(beats[0].node_image, Some(image("0.6.0")));
        assert!(beats[0].update.is_none() && beats[0].report.is_some());
        let steps: Vec<_> = beats[1..]
            .iter()
            .map(|b| {
                let update = b.update.as_ref().unwrap();
                assert_eq!(update.state, UpdateState::Running);
                assert!(b.report.is_none());
                assert_eq!(b.node_key, beats[0].node_key);
                update.step.unwrap()
            })
            .collect();
        assert_eq!(
            steps,
            [
                UpdateStep::PullImage,
                UpdateStep::Recreate,
                UpdateStep::Verify
            ]
        );
    }
    let ran = s.host.commands().len();

    // Итог уходит в следующем heartbeat; повтор задания ничего не делает.
    assert_eq!(agent::tick(&panel, &up).await.unwrap(), Next::Wait(30));
    {
        let beats = panel.beats.borrow();
        let last = beats.last().unwrap();
        assert_eq!(last.update.as_ref().unwrap().state, UpdateState::Succeeded);
        assert_eq!(last.node_image, Some(image("0.7.0")));
    }
    assert_eq!(s.host.commands().len(), ran);

    // Панель убрала задание: итог прислан в последний раз.
    *panel.order.borrow_mut() = None;
    agent::tick(&panel, &up).await.unwrap();
    assert!(panel.beats.borrow().last().unwrap().update.is_some());
    agent::tick(&panel, &up).await.unwrap();
    assert!(panel.beats.borrow().last().unwrap().update.is_none());
    assert_eq!(s.host.commands().len(), ran);
}

#[tokio::test]
async fn agent_service_exits_after_replacing_itself_and_the_new_one_resumes() {
    let s = setup("agent_self", MANAGED, "");
    let binary = b"new tmnode 0.7.0".to_vec();
    s.releases.publish("0.7.0", &binary);
    *s.host.new_binary_says.borrow_mut() = "tmnode 0.7.0\n".into();
    let panel = Panel::sending(with_tmnode(
        order("01svc", Some("0.7.0")),
        "0.7.0",
        &sha256(&binary),
    ));

    // run_forever возвращается — main завершает процесс, systemd
    // (Restart=always) поднимает службу новым бинарём.
    let mut log = Vec::new();
    agent::run_forever(&panel, &s.updater("0.6.0", Origin::Admin), |line| {
        log.push(line.to_owned())
    })
    .await;
    assert!(log.iter().any(|l| l.contains("tmnode заменён")), "{log:?}");
    let last = panel.beats.borrow().last().cloned().unwrap();
    assert_eq!(last.update.unwrap().step, Some(UpdateStep::RestartAgent));
    assert_eq!(s.host.file(&s.tmnode_path).unwrap(), binary);

    // Новый агент при старте службы дочитывает задание.
    panel.beats.borrow_mut().clear();
    let new = s.updater("0.7.0", Origin::Admin);
    let status = done(agent::resume(&panel, &new).await.unwrap().unwrap());
    assert_eq!(status.state, UpdateState::Succeeded, "{:?}", status.error);
    {
        let beats = panel.beats.borrow();
        assert!(beats.iter().all(|b| b.tmnode_version == "0.7.0"));
        assert_eq!(beats.len(), 3, "pull_image, recreate, verify");
    }
    assert!(agent::resume(&panel, &new).await.unwrap().is_none());
}

#[test]
fn update_flags() {
    let args = ops::parse_update(&[
        "--node-version",
        "0.7.0",
        "--tmnode-version",
        "0.7.0",
        "--allow-downgrade",
        "--json",
    ])
    .unwrap();
    assert_eq!(args.node_version.unwrap().to_string(), "0.7.0");
    assert_eq!(args.tmnode_version.unwrap().to_string(), "0.7.0");
    assert!(args.allow_downgrade && args.json && !args.resume);
    assert!(ops::parse_update(&["--resume"]).unwrap().resume);
    for bad in [
        &[][..],
        &["--node-version"],
        &["--node-version", "0.7"],
        &["--node-version", "v0.7.0"],
        &["--tmnode-version", "0.7.0;reboot"],
        &["--resume", "--node-version", "0.7.0"],
        &["--bogus"],
    ] {
        assert!(ops::parse_update(bad).is_err(), "{bad:?}");
    }
}

#[tokio::test]
async fn tmnode_version_alone_is_enough_for_tmnode_update() {
    let s = setup("cli_tmnode_only", "local", "");
    s.host.containers.borrow_mut().get_mut(NODE).unwrap().image =
        "ghcr.io/darkildo/trustme_backend:stable".into();
    let binary = b"new tmnode 0.7.0".to_vec();
    s.releases.publish("0.7.0", &binary);
    *s.host.new_binary_says.borrow_mut() = "tmnode 0.7.0\n".into();
    let outcome = ops::update(
        &s.updater("0.6.0", Origin::Local),
        &ops::parse_update(&["--tmnode-version", "0.7.0"]).unwrap(),
        &mut Vec::new(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(outcome, Outcome::Restart(_)), "{outcome:?}");
    let saved: Saved = serde_json::from_str(&s.state_file()).unwrap();
    assert_eq!(saved.order.node_version, None);
    assert_eq!(saved.order.tmnode.unwrap().sha256, sha256(&binary));
    assert_eq!(
        s.releases.fetched.borrow()[0],
        format!("{RELEASES}/v0.7.0/SHA256SUMS")
    );
}

#[tokio::test]
async fn tmnode_update_without_the_panel() {
    let args = |rest: &[&str]| ops::parse_update(rest).unwrap();

    // Нода под управлением админки — только из панели, даже дочитывание.
    let s = setup("cli_managed", MANAGED, "");
    renamed_old(&s);
    crashed_on(&s, UpdateStep::Recreate);
    let err = ops::update(
        &s.updater("0.6.0", Origin::Local),
        &args(&["--node-version", "0.7.0"]),
        &mut Vec::new(),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("из панели"));
    assert!(s.host.commands().is_empty());

    // Своя нода: SHA-256 бинаря — из SHA256SUMS релиза.
    let s = setup("cli_local", "local", "");
    let binary = b"new tmnode 0.7.0".to_vec();
    s.releases.publish("0.7.0", &binary);
    *s.host.new_binary_says.borrow_mut() = "tmnode 0.7.0\n".into();
    let mut log = Vec::new();
    let outcome = ops::update(
        &s.updater("0.6.0", Origin::Local),
        &args(&["--node-version", "0.7.0", "--tmnode-version", "0.7.0"]),
        &mut log,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(outcome, Outcome::Restart(_)), "{outcome:?}");
    let log = String::from_utf8(log).unwrap();
    assert!(log.contains("→ скачиваю tmnode"), "{log}");
    let saved: Saved = serde_json::from_str(&s.state_file()).unwrap();
    assert!(saved.local && saved.order.id.starts_with("local-"));
    assert_eq!(saved.order.tmnode.unwrap().sha256, sha256(&binary));

    // Новый бинарь: tmnode update --resume.
    let mut log = Vec::new();
    let outcome = ops::update(
        &s.updater("0.7.0", Origin::Local),
        &args(&["--resume"]),
        &mut log,
    )
    .await
    .unwrap()
    .unwrap();
    let status = done(outcome);
    assert_eq!(status.state, UpdateState::Succeeded, "{:?}", status.error);
    assert!(
        String::from_utf8(log)
            .unwrap()
            .contains("→ проверяю новую ноду")
    );

    let mut text = Vec::new();
    ops::print_update(&mut text, &status, false);
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("готово"), "{text}");
    assert!(text.contains(&format!("{} → {}", image("0.6.0"), image("0.7.0"))));
    assert!(text.contains("0.6.0 → 0.7.0"));
    let mut json = Vec::new();
    ops::print_update(&mut json, &status, true);
    let json: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(json["state"], "succeeded");

    // Дочитывать нечего; tmnode уже той версии.
    let up = s.updater("0.7.0", Origin::Local);
    assert!(
        ops::update(&up, &args(&["--resume"]), &mut Vec::new())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        ops::update(&up, &args(&["--tmnode-version", "0.7.0"]), &mut Vec::new())
            .await
            .unwrap()
            .is_none()
    );
}
