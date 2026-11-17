# The workload: curl for HTTPS, mosquitto_pub for MQTT over TLS, and GNU date
# for millisecond timings taken inside the container (docker exec's own overhead
# would hide a 200ms latency).
FROM alpine:3.22
RUN apk add --no-cache curl mosquitto-clients coreutils openssl
CMD ["sleep", "infinity"]
