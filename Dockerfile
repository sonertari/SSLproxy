ARG GCP_REGISTRY=us-central1-docker.pkg.dev/corsha-tf-gcp-dev-d9bef0/corsha
ARG JFROG_REGISTRY=corsha-docker.jfrog.io
ARG TARGETPLATFORM=linux/amd64

# --- Build Stage ---
FROM --platform=${TARGETPLATFORM} ${GCP_REGISTRY}/ubuntu@sha256:9b1d5e67cab555f2711517ab093e3646b88852e2f51dbe7c3a061a842ee99fcb AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    libevent-dev \
    libnet-dev \
    libpcap-dev \
    libsqlite3-dev \
    libssl-dev \
    libxml2-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy the entire local workspace into the builder
COPY . /src

# Build SSLProxy. Ensure /lib64 exists so that the final COPY --from=builder /lib64 /lib64
# is fully compatible on both ARM64 and AMD64.
RUN cd /src \
    && make -j"$(nproc)" && make install DESTDIR=/install \
    && mkdir -p /lib64 \
    && mkdir -p /install/etc/sslproxy \
    && cp /install/usr/local/share/examples/sslproxy/sslproxy.conf /install/etc/sslproxy/sslproxy.conf

# --- Runtime Stage ---
FROM --platform=${TARGETPLATFORM} ${GCP_REGISTRY}/distroless/static-debian12@sha256:6c8e62544dfb33087ab275c463747c75a5bb634a383af5e91625da882a5fe175

COPY --from=builder /install/usr/local/bin/sslproxy /usr/local/bin/sslproxy
COPY --from=builder /install/etc/sslproxy /etc/sslproxy

# Unconditionally copy platform-specific shared libraries
COPY --from=builder /lib /lib
COPY --from=builder /usr/lib /usr/lib
COPY --from=builder /lib64 /lib64

ENTRYPOINT ["sslproxy"]
CMD ["-f", "/etc/sslproxy/sslproxy.conf", "-d"]
