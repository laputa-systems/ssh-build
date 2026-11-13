FROM alpine:3.22
RUN apk add --no-cache openssh-server tmux=3.5a-r1 && adduser -D -s /bin/sh xinfra && passwd -u xinfra
COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
