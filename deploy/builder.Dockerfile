# Сборочное окружение ноды. Собирается один раз и переиспользуется:
# пакеты ставятся в образ, а не в одноразовый контейнер на каждом деплое,
# поэтому выкатка не зависит от доступности зеркала Debian.
#
# build-essential/cmake/perl нужны не Rust'у, а aws-lc-sys — C-бэкенду
# rustls, который собирается из исходников.
FROM rust:1.97-slim-bookworm

# Ретраи и принудительный IPv4: у хоста есть AAAA-запись без рабочего
# маршрута, а зеркало Fastly изредка отваливается по IPv4. Разовая сборка
# не должна падать из-за одной неудачной попытки.
RUN printf 'Acquire::Retries "3";\nAcquire::ForceIPv4 "true";\n' \
      > /etc/apt/apt.conf.d/99-deploy-resilience \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        perl \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*
