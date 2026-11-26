# Working on Kubedog

Kubedog is written in Rust with [egui](https://github.com/emilk/egui) / eframe. You need Rust (stable):
<https://rustup.rs>. The tests need no cluster.

## Build and run

```sh
cargo run                 # build and start (debug build; libraries are optimised, see Cargo.toml)
cargo build --release     # optimised build: target/release/kubedog
cargo test                # unit tests
target/release/kubedog --version
```

## Making a release

```sh
scripts/release.sh --build-only   # builds and packs all five in target/dist; nothing leaves this computer
scripts/release.sh --build-only --notarize   # the same, and the Mac app goes to Apple for its check; nothing is published
scripts/release.sh                # the same, then asks, then Apple's check, then uploads
```

It runs on a Mac (a Mac build can only be made on one) and builds the Linux and Windows programs from there; what
it needs once is at the top of the script. The version is the one in `Cargo.toml`: raise it first. After the
question it has Apple check the Mac app, tags the version here, makes a release on GitHub with the five downloads, the
Mac disk image, the Windows installer and `SHA256SUMS`, and writes the Homebrew formula and cask. The Mac program is
signed with the "Developer ID Application" certificate in the keychain (found by its kind; no name is in the script) and
comes as `Kubedog.app` in a `.dmg`; what that needs once is at the top of the script too. Notes for
a release go in `plans/release-notes-<version>.md`. Names that must never appear in a program go, one per line, in
`plans/never-publish.txt`; the script stops when it finds one.

## Platforms

Kubedog is built for macOS (Apple silicon), Linux (amd64, arm64) and Windows (amd64, arm64). It's used daily on
**macOS**. The Linux builds have been seen to start on Debian 11; the Windows builds haven't been tried on a Windows
computer yet. Settings are kept where each system expects them: `~/Library/Application Support/Kubedog`,
`~/.config/kubedog` (or `$XDG_CONFIG_HOME`), `%APPDATA%\Kubedog`.

A few parts are still written for macOS and need work on the other two:

| Where | What is macOS-only | What to do on Linux / Windows |
|---|---|---|
| `src/menu.rs` (+ `muda` in `Cargo.toml`) | The menu bar | Already skipped elsewhere (`cfg(target_os = "macos")`); `muda` also supports Windows and Linux (GTK) if wanted |
| `src/app/clusters.rs` `browse_kubeconfig`, `src/app/packets.rs` | File picker via `osascript` | A native dialog crate such as `rfd`; until then the path is typed |
| `src/app/terminal.rs` | External terminal apps started with `open -a` and a zsh script | Per-platform launchers (`x-terminal-emulator`, Windows Terminal `wt`, ...) |
| `src/app.rs` (context shell) | The local shell: zsh on macOS, `$SHELL` on Linux | `powershell`/`cmd` on Windows |
| `src/app.rs` (port forwards) | "Open in browser" uses `/usr/bin/open` | `xdg-open` on Linux, `start` on Windows |
| `src/app.rs` `raw_input_hook` | Menu "Paste" reads `pbpaste` | Only used by the macOS menu; nothing needed |
| `src/main.rs` | macOS window options (transparent title bar) | Harmless elsewhere |

The pod shell (`kubectl exec`), port forwards, logs and every list go through `kubectl` and are not
platform-specific.

## Where things are

| File | What it does |
|---|---|
| `src/main.rs` | Starts the program, opens the window, `--screenshot` mode |
| `src/app.rs` | The window: start-up, background work, lists, object pages, dialogs, settings storage, shortcuts |
| `src/app/clusters.rs` | Start page, kubeconfig files, cluster names, namespaces per cluster |
| `src/app/update.rs` | Asking GitHub once a day for the newest version, and saying how to update |
| `src/app/settings.rs` | The Settings page (General, Clusters, Kubeconfig files, Grafana, Terminal, Logs, Shortcuts, About) |
| `src/app/dash.rs` | Cluster and Workloads overview dashboards |
| `src/app/nodeview.rs` | A node's page: gauges, history, allocation, busiest pods |
| `src/app/columns.rs` | Which columns a list shows and their order, the drag-and-drop column menu, the top-right icons |
| `src/app/pod.rs` | A pod's Overview (health, container cards, start) and Containers tab |
| `src/app/podxray.rs` | The X-ray: ways in (ingresses, OpenShift and Gateway API routes), services, containers, what it holds |
| `src/app/podnet.rs` | A pod's Network and Environment tabs |
| `src/app/podplace.rs` | A pod's Scheduling and What if tabs |
| `src/app/podfiles.rs` | A pod's Storage and Files tabs |
| `src/app/crds.rs` | Custom resources: sidebar tree, lists (printer columns, a small JSONPath reader), object pages |
| `src/app/pg.rs` | Postgres clusters run by CloudNativePG |
| `src/app/hive.rs` | The Pod Hive, nodes seen from pods, sizing advice, the account's rights |
| `src/app/grafana.rs` | The Grafana option: its settings, certificates, queries and pages |
| `src/app/login.rs` | Reading from services with the login in their secret (port forward + curl), the Superpowers sidebar section |
| `src/app/elastic.rs`, `src/app/pulsar.rs` | The Elasticsearch and Pulsar pages |
| `src/app/face.rs` | The top of every object's page: health in a sentence, conditions, facts |
| `src/app/work.rs` | Workload pages |
| `src/app/objects.rs` | Pages of all other kinds, and the workloads summary and map |
| `src/app/powers.rs` | Superpowers: Auto, On, Off, and finding out what's there |
| `src/app/ops.rs`, `argo.rs`, `opsec.rs`, `opinfra.rs`, `opnet.rs` | Operators' pages |
| `src/app/incident.rs`, `detect.rs`, `loghunt.rs`, `connect.rs`, `compare.rs` | Incident Room |
| `src/app/picks.rs` | Several rows of a list at once |
| `src/app/readiness.rs` | Readiness |
| `src/app/shells.rs` | Shell: terminals set up for a cluster, the question before changes, the ready commands |
| `src/app/favs.rs` | Favorite pages in the sidebar |
| `src/app/rowmenu.rs` | The right-click menu on list rows |
| `src/app/side.rs` | The order of the sidebar, and Settings > Sidebar |
| `src/app/netlab.rs`, `nettest.rs`, `netpath.rs` | Network Lab: the page with the overview, tests from this computer, the path as it should be |
| `src/app/nettry.rs` | Network Lab: tests from inside a pod, the matrix, the list of what was run |
| `src/app/ovntrace.rs` | Network Lab: the path as OVN computes it |
| `src/app/packets.rs` | Network Lab: the packet decoder, capture files, what went wrong in them, capturing (see `THIRD-PARTY.md`) |
| `src/app/nethelp.rs` | Network Lab: helpers, their images, limits and settings |
| `src/app/aifacts.rs` | AI: the facts, the filter for secrets, stand-ins for names |
| `src/app/aiharness.rs` | AI: finding, starting and ending Claude Code and Codex |
| `src/app/ai.rs`, `aichat.rs` | AI: routing, asking, settings; the panel |
| `src/app/aipage.rs` | AI: the facts of the page that's open |
| `src/app/aitools.rs` | AI: look-ups, what's allowed and how they're run |
| `src/app/openshift.rs`, `oscatalog.rs` | OpenShift, and its catalog |
| `src/app/proxmox.rs` | Proxmox |
| `src/app/companion.rs` | The Ai-health-agent and its cases |
| `src/app/workload.rs` | References (uses / used by) and deployment Revisions |
| `src/app/search.rs` | The ⌘K search box |
| `src/app/netmap.rs` | Service Map, ingress TLS certificate check |
| `src/app/certs.rs` | Certificates: a small DER/X.509 reader, and how a secret shows them |
| `src/app/storage.rs` | Storage usage per volume claim (kubelet stats) |
| `src/app/terminal.rs` | Built-in terminal (portable-pty + vt100) and external terminal apps |
| `src/kube.rs` | Running `kubectl`/`helm` in the background, kubeconfig lookup, time helpers |
| `src/resources.rs` | Resource kinds, sidebar groups, table columns and cells, quantities |
| `src/logparse.rs` | Log level detection |
| `src/theme.rs` | Themes (backgrounds), accent colours, text sizes |
| `src/menu.rs` | macOS menu bar |
| `src/logo.rs` | The logo inside the program (window and Dock icon, start page, About) |
| `assets/fonts/` | The fonts that can be chosen, each with its licence (SIL Open Font License) |
| `assets/icons/` | The icon set: PNGs, `kubedog-macos.icns` and `kubedog-windows.ico` for release builds |

## Testing without clicking

`kubedog --screenshot out.png` draws the window off to the side, saves a picture and quits. It only
reads from clusters and never saves settings. Environment variables choose what to show:

- `KUBEDOG_SHOT_PAGE=pods|deployments|nodes|node|detail|logs|yaml|settings|...`
- `KUBEDOG_SHOT_CTXS`, `KUBEDOG_SHOT_NS`, `KUBEDOG_SHOT_OBJ`, `KUBEDOG_SHOT_THEME`, `KUBEDOG_SHOT_ACCENT`, `KUBEDOG_SHOT_SYSTEM=light|dark`, `KUBEDOG_SHOT_SIZE=WxH`
- `KUBEDOG_SHOT_PREFS=<json>` (sample settings, kept in memory only)
- `KUBEDOG_SHOT_MOUSE="click 900,20; drag 910,300 910,120; hold 1,1 2,2"` (a scripted mouse, in points)
- `KUBEDOG_SHOT_PAGE=crd|crdobj` with `KUBEDOG_SHOT_CRD=plural.group`; `KUBEDOG_SHOT_SEARCH=text`;
  `KUBEDOG_SHOT_NS=a,b`; `KUBEDOG_SHOT_NSMENU=1`; `KUBEDOG_SHOT_FOLD=api.group,...`;
  `KUBEDOG_SHOT_PAGE=deploy` with `KUBEDOG_SHOT_TAB=revisions`

- `KUBEDOG_SHOT_PAGE=escluster|pucluster` with `KUBEDOG_SHOT_OBJ`, `KUBEDOG_SHOT_NS`, and `KUBEDOG_SHOT_LOGIN=1` to log in (reads only)
- `KUBEDOG_SHOT_PAGE=observatory` with `KUBEDOG_SHOT_GRAFANA=answers.json` (made-up answers, nothing is asked)
- `KUBEDOG_SHOT_PAGE=proxmox` with `KUBEDOG_SHOT_PROXMOX=answers.json` (made-up answers, nothing is asked)
- `KUBEDOG_SHOT_PICK=name,name` or `failed` ticks rows; `KUBEDOG_SHOT_UNLOCK=1` shows confirmations (nothing is ever run)
- `KUBEDOG_SHOT_PROTECTED=1` shows what a change in a protected cluster says
- `KUBEDOG_SHOT_PAGE=shell` with `KUBEDOG_SHOT_SHELL=1` shows a made-up screen; no shell is started in a screenshot; `KUBEDOG_SHOT_WSL=Ubuntu,Debian` makes up WSL Linuxes
- `KUBEDOG_SHOT_PAGE=netlab` with `KUBEDOG_SHOT_TAB=0..`, and `KUBEDOG_SHOT_NETTEST=results.json` (made-up results, nothing is tested), `KUBEDOG_SHOT_NETTRY=results.json` (made-up tests from pods), `KUBEDOG_SHOT_TRACE=answer.txt`, `KUBEDOG_SHOT_PCAP=file.pcap`
- `KUBEDOG_SHOT_PAGE=hive`, with `KUBEDOG_SHOT_RIGHTS=1` to ask what the account may do
- `KUBEDOG_SHOT_PAGE=detail` with `KUBEDOG_SHOT_TAB=containers|environment|network|scheduling|storage|files|whatif`; commands in a
  container only run with `KUBEDOG_SHOT_EXEC=1` (`KUBEDOG_SHOT_FILES=container`, `_PATH`, `_FILE`, `_DF=container`)
- `KUBEDOG_SHOT_UPDATE=9.9.9` makes up a newer version for the top bar and Settings > About; GitHub is never asked in a screenshot
- `KUBEDOG_SHOT_ZOOM=0.6` (see more of a long page), `KUBEDOG_SHOT_SCROLL=600`, `KUBEDOG_SHOT_THRESHOLD=50`

- `KUBEDOG_SHOT_AI=1` (or `confirm`, `look`, or `chat` for the chat about a page) shows the AI panel with a made-up answer; nothing is ever asked in a screenshot

The full list is in `maybe_screenshot` in `src/app.rs`.
