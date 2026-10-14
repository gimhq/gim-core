# Build image for the Android artifacts of gim-core (libgim_core.so + Kotlin
# bindings). Used by bindings/android/build.sh; not meant to be run directly.
FROM rust:1.99-bookworm

LABEL ai-agent=true

# C toolchain pieces needed by bundled SQLite (rusqlite) and the rustls crypto
# backends, plus unzip/file for the NDK and artifact checks.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang cmake perl make pkg-config unzip file \
    && rm -rf /var/lib/apt/lists/*

ARG NDK_VERSION=r27d
ARG NDK_SHA256=601246087a682d1944e1e16dd85bc6e49560fe8b6d61255be2829178c8ed15d9
RUN curl -fsSL -o /tmp/ndk.zip \
        "https://dl.google.com/android/repository/android-ndk-${NDK_VERSION}-linux.zip" \
    && echo "${NDK_SHA256}  /tmp/ndk.zip" | sha256sum -c - \
    && unzip -q /tmp/ndk.zip -d /opt \
    && mv "/opt/android-ndk-${NDK_VERSION}" /opt/android-ndk \
    && rm /tmp/ndk.zip
ENV ANDROID_NDK_HOME=/opt/android-ndk \
    ANDROID_NDK_ROOT=/opt/android-ndk

# The runtime mounts a shared CARGO_HOME over the default one, so cargo-ndk is
# installed elsewhere and copied onto PATH.
ARG CARGO_NDK_VERSION=4.1.2
RUN CARGO_HOME=/opt/cargo-tools cargo install cargo-ndk --locked --version "${CARGO_NDK_VERSION}" \
    && cp /opt/cargo-tools/bin/cargo-ndk /usr/local/bin/ \
    && rm -rf /opt/cargo-tools

RUN rustup target add aarch64-linux-android x86_64-linux-android
