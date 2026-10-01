# Рантайм ноды. База — та же дистрибуция, в которой собран бинарь
# (см. deploy/build-message-runtime.sh), поэтому glibc совпадает.
#
# TLS: клиент FCM/APNs собран на rustls с rustls-native-certs, то есть корни
# берутся из системного хранилища — ca-certificates обязателен, без него
# пуши отвалятся на верификации сертификата.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    # uid/gid совпадают с владельцем файлов в существующем томе данных,
    # чтобы права на sled-каталоге сошлись, когда базовый docker-compose.yml
    # на хосте перестанет запускать контейнер с user "0:0".
    && groupadd --system --gid 999 trust \
    && useradd --system --uid 10001 --gid 999 --create-home --shell /usr/sbin/nologin trust

COPY trust_message_tcp /usr/local/bin/trust_message_tcp

RUN chown trust:trust /usr/local/bin/trust_message_tcp \
    && chmod 755 /usr/local/bin/trust_message_tcp

USER trust

CMD ["/usr/local/bin/trust_message_tcp"]
