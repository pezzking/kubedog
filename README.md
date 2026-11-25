# Kubedog

A fast desktop app for Kubernetes clusters. It talks to clusters through your own `kubectl`, so it works with
whatever your kubeconfig can reach, and it adds pages of its own for what runs in a cluster (Argo CD, OpenShift,
Postgres, Proxmox and more). Every cluster starts protected: nothing is changed without unlocking and confirming.

This repository holds the downloads. Every version is under [Releases](../../releases).

## Install

You need `kubectl` on your `PATH`.

### macOS (Apple silicon) and Linux, with Homebrew

```sh
brew install pezzking/tap/kubedog
kubedog
```

To update: `brew upgrade kubedog`.

### Linux, by hand

Download `kubedog-<version>-linux-amd64.tar.gz` (or `-arm64`) from [Releases](../../releases), then:

```sh
tar xzf kubedog-*-linux-*.tar.gz
sudo install kubedog-*/kubedog /usr/local/bin/
kubedog
```

It needs a desktop (X11 or Wayland) with OpenGL or Vulkan, and glibc 2.28 or newer (Debian 10, Ubuntu 18.10,
RHEL 8 and later).

### Windows

Download `kubedog-<version>-windows-amd64.zip` (Intel or AMD; `-arm64` for an ARM computer such as a Snapdragon
laptop) from [Releases](../../releases), unpack it and start `kubedog.exe`.
Windows may say the publisher is unknown: the program isn't signed yet. Choose "More info", then "Run anyway".

### macOS, by hand

Download `kubedog-<version>-macos-arm64.tar.gz`. A download made with a browser is held back by macOS because the
program isn't signed by Apple yet; Homebrew is the way that works without that. If you do download it by hand:

```sh
tar xzf kubedog-*-macos-arm64.tar.gz
xattr -dr com.apple.quarantine kubedog-*/
./kubedog-*/kubedog
```

## Check a download

Every release has a `SHA256SUMS` file:

```sh
shasum -a 256 -c SHA256SUMS --ignore-missing
```

## How well each system is tried

| System | State |
|---|---|
| macOS, Apple silicon | Built and used daily |
| Linux, amd64 and arm64 | Built, and seen to start on Debian 11; its window hasn't been looked at yet. Some parts are still written for macOS (opening an outside terminal app, the file chooser) |
| Windows, amd64 and arm64 | Built, **not yet tried on a Windows computer**. Expect rough edges; the built-in shell and outside terminals are written for macOS |

## Licence

Apache License 2.0, see [LICENSE](LICENSE). Notices for what Kubedog is built with come with every download
(`THIRD-PARTY.md`, `THIRD-PARTY-LIBRARIES.txt`).
