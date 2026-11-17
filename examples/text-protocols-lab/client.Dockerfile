# The workload: real clients (redis-cli, the nats CLI, curl, ssh-keyscan) plus ./bin/probe,
# mounted by docker-compose.yml, to time them and to send raw protocol lines.
FROM alpine:3.22
RUN apk add --no-cache curl redis openssh-client
COPY --from=natsio/nats-box:latest /usr/local/bin/nats /usr/local/bin/nats
CMD ["sleep", "infinity"]
