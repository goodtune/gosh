# Integration-test image: a genuine sshd with mosh-server installed, the
# environment a real gosh session bootstraps against. Debian rather than
# Alpine so mosh-server runs against a stock glibc locale setup.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server mosh locales \
    && rm -rf /var/lib/apt/lists/* \
    && sed -i 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen \
    && locale-gen

# Password login for the test user; mosh-server needs a real account with a
# shell. The credentials are test-rig-only and the container is never
# reachable beyond the docker host's mapped ports.
RUN useradd -m -s /bin/bash gosh \
    && echo 'gosh:gosh-integration' | chpasswd \
    && mkdir -p /run/sshd \
    && printf '%s\n' \
        'PasswordAuthentication yes' \
        'AcceptEnv LANG LC_*' \
        > /etc/ssh/sshd_config.d/gosh-test.conf

# The fixed UDP port the test asks mosh-server to bind (-p 60001), so the
# container runtime can map it deterministically.
EXPOSE 22/tcp 60001/udp

CMD ["/usr/sbin/sshd", "-D", "-e"]
