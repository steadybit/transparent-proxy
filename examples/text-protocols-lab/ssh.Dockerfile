# ssh.test: an OpenSSH server, a dependency the attack does not target.
FROM alpine:3.22
RUN apk add --no-cache openssh && ssh-keygen -A
CMD ["/usr/sbin/sshd", "-D", "-e"]
