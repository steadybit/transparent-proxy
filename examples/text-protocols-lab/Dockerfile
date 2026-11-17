# A shell in the client's network namespace with iptables, where the proxy is run
# as ./transparent-proxy. The binary (built on the host by run.sh into ./bin) is
# mounted into /lab by docker-compose.yml.
FROM alpine:3.22
RUN apk add --no-cache iptables
WORKDIR /lab
CMD ["sh"]
