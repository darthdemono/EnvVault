# A throwaway Linux desktop for looking at the real app (Phase 40).
#
# The desktop app is a WebKitGTK window, and neither jsdom (no layout) nor
# Chromium (a different engine) can answer "what does it look like there". This
# image holds everything needed to build the app, start it on a virtual display
# and drive it with WebDriver, so a screenshot is a real window rendered by the
# real engine with the real IPC bridge behind it, and nothing touches the host's
# screen or home directory.
#
#   docker build -t unv-viewer tools/viewer
#   tools/viewer/run.sh            # builds dist/, builds the app, writes PNGs
FROM rust:1.90-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
      libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev \
      libayatana-appindicator3-dev librsvg2-dev libsqlcipher-dev libssl-dev pkg-config \
      xvfb xauth dbus dbus-x11 webkit2gtk-driver imagemagick python3 \
      fonts-dejavu-core fonts-noto-color-emoji fonts-liberation \
      build-essential file ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The WebDriver bridge between a W3C client and the app's WebKitWebDriver.
RUN cargo install tauri-driver --locked

# The repo's .cargo/config.toml links with mold.
RUN apt-get update && apt-get install -y --no-install-recommends mold clang \
    && rm -rf /var/lib/apt/lists/*

ENV CARGO_TARGET_DIR=/cargo-target \
    CARGO_PROFILE_RELEASE_OPT_LEVEL=1 \
    CARGO_PROFILE_RELEASE_LTO=false \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
    CARGO_PROFILE_RELEASE_STRIP=false \
    NO_AT_BRIDGE=1 \
    GDK_BACKEND=x11 \
    WEBKIT_DISABLE_COMPOSITING_MODE=1 \
    WEBKIT_DISABLE_DMABUF_RENDERER=1
WORKDIR /src
