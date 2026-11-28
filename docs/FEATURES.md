# Everything Kubedog does

The short version is in the [README](../README.md). This is the whole list.

- **Clusters:** a start page with every context from your kubeconfig files.
  - Settings can be opened from the start page (the gear at the top right, or ⌘,), before any cluster is open.
  - The highlighted block is the selected cluster, whose details are shown next to the list; the tick in its circle
    says which clusters are picked to open. The two are apart: a click on a block selects, a click on a circle ticks.
  - Add more kubeconfig files, or paste a kubeconfig.
  - Give clusters short names and colours, and save groups of clusters to open together.
  - For accounts that can only see some namespaces, list them per cluster (wildcards allowed).
- **Several clusters at once:** each cluster has its own colour stripe in every list, the namespace
  menu is grouped by cluster, and every confirmation says which cluster it acts on.
- **Lists of every common kind:** workloads, networking, configuration, storage, access control,
  CRDs.
  - CPU and memory bars, a filter box and sorting.
  - Columns you can show, hide and reorder: the sliders icon at the top right opens a list where you
    drag rows to order them and tick them to show them (or drag the table's headers). Extra columns
    are available, such as CPU and memory requests and limits, images and labels.
  - Column widths that use the room a big window gives.
  - The Context and Namespace columns are as wide as the longest name in them, so short names leave the room to the rest.
- **Object pages:** Overview, YAML, Events (only for kinds that have events) and Logs.
  - **Pods:** whether it's well and why not, its conditions, a live X-ray (ingresses and routes, the
    services behind them, its containers as tanks of memory, what they hold; all of it clickable), a card per container (CPU, memory, what's asked for
    and allowed, image, logs, shell, files) and how it came up. Tabs: Containers; Environment (secret
    values blurred, read when clicked); Network; Scheduling (tolerations and wishes in words, and which
    nodes would take it); Storage (disks and `df`); Files (a read-only explorer that runs `ls` and
    `head` in the container after a click); and What if (it's deleted, its node fails, its memory keeps
    growing, its configuration changes).
  - **Nodes:** gauges, usage history, allocation, the busiest pods, pods per namespace, conditions
    and taints.
  - **Secrets:** certificates are decoded in full; other values are blurred until clicked. Config maps and
    secrets can be edited as key/value pairs.
- **Logs:** for pods and whole workloads, with level detection and filtering, live follow and a
  time range.
- **Custom resources:** every CRD of the open clusters in the sidebar, grouped by API group (with
  sub-groups such as cert-manager.io → acme) and a filter.
  - Each kind opens a list with its own printer columns; Argo CD Applications have Project, Sync,
    Health, Repository, Revision, Destination, Auto-sync, Prune and Self-heal, in a GitOps group.
  - Each object has Overview (fields, conditions, labels, spec and status), YAML and Events tabs, and
    can be deleted.
- **Incident Room:** what broke and why.
  - *What changed:* a timeline of changes (with before and after), rollouts, warnings, restarts and who
    wrote what. Details of changes are remembered while Kubedog is open.
  - *Why is it broken:* follows an object's chain (ways in, services, pods, nodes, disks, configuration,
    what it calls, recent changes) and names the likely cause with its evidence.
  - *Errors in logs:* several apps at once, the same errors put together, new ones marked.
  - *Can A reach B:* from services, endpoints and network policies, with the rule that decides.
  - *Compare clusters* (or a saved snapshot; values are in it as fingerprints only) and *Drift from Git*.
- **Network Lab:** is the network well, from what the cluster says itself (what makes the network, OpenShift's
  own connection checks, services with nothing behind them, address pools, and from Grafana full connection
  tables and dropped packets), and **tests from this computer**: a typed address, or every route, ingress and
  load balancer at once, step by step (name, connection, TLS, answer) with where it stops. Only by a click;
  certificates are always checked, redirects are shown and not followed. **Can A reach B** (also in the Incident
  Room): the path as it should be, from outside or a pod through routes, service and endpoints to the pod, or out
  of the cluster, with network policies, admin and baseline policies, egress firewalls and IPs, networks of their
  own, and traffic-policy traps; every step says yes, no, maybe or not known. **From a pod:** one or many pods to
  one or many services or addresses, tried for real with what their containers have (behind the lock and a
  confirmation), as a table next to what was expected, and a list of what was run. On OVN-Kubernetes also **Ask OVN**:
  `ovn-trace` in the OVN pod computes the path of a made-up packet and names the rule that drops it. (Tried with
  OVN itself, not yet in a cluster.) **Packets:** opens pcap and pcapng files and says what went wrong in them, from
  headers only: names not found, refused and unanswered connections, resets, packets sent again, TLS alerts,
  packets that are too big; each conversation as a picture of arrows. None of it goes to AI. **Helpers** (off for every
  cluster until switched on in Settings > Superpowers > Network Lab, then behind the lock and a confirmation): a short
  capture at a pod or node, and tests beside an app that has no tools, from a namespace or from a node. A helper has
  Kubedog's label only, no token, ends by itself and is removed. (Tried in a kind cluster, not on OpenShift.)
- **Shell:** full-size terminals, each set up for one cluster: kubectl, helm, argocd (`acd` uses your cluster rights
  instead of a login), the CloudNativePG plugin, oc, k9s and whatever else is on the computer use that cluster and
  namespace. `kx` and `kn` switch them for that shell only; your own kubeconfig is never changed. While a cluster is
  protected, zsh and bash ask before a command that changes something (a reminder, not a wall: scripts and programs like
  k9s don't ask). A panel lists ready commands for the tools you have; a click types one, you press Enter.
  On Windows it's PowerShell, or a Linux in WSL (Settings > Terminal, or the + menu): the tools are that Linux's, the
  clusters are the ones opened in Kubedog. Kubedog doesn't install tools there: kubectl has to be in that Linux, and
  helm, argocd and the others if you want them; the shell and the panel say which are missing. A Linux that runs now is
  listed first, whatever it's called. (The Linux side was tried in Ubuntu and Debian; not yet in WSL itself.)
- **The whole app through WSL (Windows, Settings > Terminal):** with a Linux chosen for the Shell, a tick makes all of
  Kubedog work through it: kubectl and helm run in that Linux, and the clusters are the ones in its own kubeconfig
  (`~/.kube/config` there, or what `KUBECONFIG` says in its shell), so logins made there work in Kubedog. The
  kubeconfig files added in Kubedog aren't used meanwhile. Not yet tried on a Windows PC with WSL.
- **Readiness:** before an upgrade, a drain rehearsal, what expires, who may do what, what's wasted,
  what's unsafe.
- **Operators:** pages for Argo CD, External Secrets and Vault, cert-manager, KEDA, Rook Ceph,
  Prometheus, gateways and routes, GPUs, backups (Velero, Kasten); Strimzi, Redis, MongoDB, RabbitMQ,
  Flux, Tekton, Kyverno and Gatekeeper, Crossplane, Longhorn, MetalLB and Keycloak by their own columns
  and conditions. They appear by themselves when a cluster has them.
- **AI (optional, off by default):** an AI button at the top right opens a chat about the page you're on
  (lists, overviews, objects, configuration, networking, superpowers); go to another page and ask on. Explain
  buttons are in lists next to logs and shell, on objects, in the Incident Room and on log errors.
  - Auto uses Claude Code, then Codex, Ollama or LM Studio if they're on this computer, and nothing else.
    Your own server (OpenAI-compatible), Anthropic with a key, or your own command can be chosen.
  - It gets numbered facts Kubedog found, and answers point to them. It has no access to the cluster itself.
  - *Look-ups* (off, ask each time, or by itself): it names one of a few ways of reading (a list, an object,
    events, logs, usage); Kubedog checks it, runs kubectl and gives the result back as facts. No secrets, no
    commands in pods, no changes, only the conversation's clusters, and the same filter and routing.
    Suggested changes are text; Kubedog never applies them.
  - The model is picked from a pulldown, in Settings and in the panel: Codex, Ollama and LM Studio say which
    they have, Claude Code has its four kinds, a server is asked when you click. Others can be typed.
  - Claude Code is started without tools of its own and ended if it has any. Codex still lists some tools,
    but what runs them is switched off and it's ended when it reports using one. On macOS the system also
    keeps both out of your home folder (except their own). Elsewhere Codex has to be allowed first.
  - *Settings > AI* decides what may be sent where (facts, log lines, values; this computer, your server,
    cloud; every AI carries the marker of its place), stand-ins for names, and per cluster which AI or never. Before the first
    question about a
    cluster goes to a cloud, you see what will be sent. Ollama's cloud models count as cloud.
  - What looks like a secret is taken out (a filter can miss things); secret values are never read for it.
    Keys are in the system's keychain. Kubedog doesn't keep conversations, and asks
    Claude Code and Codex not to.
- **Ai-health-agent (off by default, per cluster):** watches workloads, nodes and volumes with Kubedog's own rules,
  from lists that are read anyway, and opens a case in the Incident Room for what stays broken. If you let it,
  AI investigates new cases by itself, at most a few an hour; then facts go out without asking each time.
- **OpenShift:** updates (what's offered, known risks, what's in the way, old APIs still used and by whom),
  cluster operators, installed operators and what waits for approval, machine pools and machines, certificate
  requests, routers, and security: apps whose constraint (SCC) gives more rights than they ask for. The software catalog: operators to search and
  filter, what's installed, channels, what to watch out for, and the YAML to install one (to copy; Kubedog
  doesn't install); templates, images and Helm repositories. Reading only.
- **Proxmox (optional):** hosts, virtual machines and containers, storage, tasks and high availability of
  Proxmox VE; what's wrong or could go wrong; which Kubernetes node runs on which host, what goes when a host
  goes, and workloads with all pods on one host. Reading only, with an API token (role PVEAuditor). The
  certificate is always checked (your own authority can be added); the token's secret is kept in memory, or
  in the system's keychain if you tick it. Set up in Settings > Superpowers.
- **Lists:** a click on a name opens it; the rest of the row is for ticking (⌘, ⇧) and its menu.
- **Right click** on a row of a list: open it, logs, shell, port forward, YAML, events; for a pod also restart
  or open its deployment (stateful set, daemon set) and open its node; restart, scale, cordon or drain where that fits;
  copy its name; delete. With several ticked, also what can be done with all of them. Changes go through the lock.
- **Protection:** every cluster starts protected; Settings > Clusters can let one, or all, start with changes allowed
  (changes still ask before they're done).
- **Favorites:** a star on every page of the sidebar (shown under the mouse) puts it in Favorites at the top; starred
  namespaces are first in the namespace menu and starred on the Namespaces page.
- **A login that has ended is said, and OpenShift's can be renewed from Kubedog:** when a cluster answers that you
  aren't logged in any more, a card above the page says so, with a row per cluster. For a login made with `oc login`, a
  **Log in** button runs `oc login --web` for that cluster's address: your browser opens for the sign-in, and `oc` saves
  the new login in your kubeconfig file and makes that cluster the current one for your terminals, as it always does.
  Kubedog then asks the cluster whether the login works, says so when the sign-in was for another user, and reads
  everything again. Kubedog never sees a password. It needs `oc` on the computer (the card says so when it's missing);
  with the whole app in WSL, the card gives the line to run in the Linux instead. Other kinds of login only get the
  notice. The card can be put away with "Not now".
- **A newer version is told, not installed** (Settings > About): once a day Kubedog asks github.com which version is
  the newest; nothing about you or your clusters is sent. When yours is older, the top bar says so, and Settings > About
  gives the Homebrew line to run or opens the download page. Where Homebrew installed Kubedog, an **Update with
  Homebrew** button does it for you after a click: Homebrew reads its lists, updates Kubedog and nothing else, what it
  says is shown, and a **Restart Kubedog** button starts the new one. One version can be skipped and the look can be switched
  off. After a look without an answer Kubedog waits a day before the next.
- **Air-gapped** (Settings > About): a switch that makes Kubedog never ask the internet by itself, which today means
  it doesn't look for a new version. Kubedog switches it on by itself after three looks, a day apart, in which
  github.com couldn't be reached, and says so there; **Look now** tries once more, and an answer switches it off again. An installation can fix it
  on: the Windows installer has a tick for it (or `/AIRGAPPED` on its command line, with `/S` for no questions), which
  puts an empty file named `airgapped` next to the program; `KUBEDOG_AIRGAPPED=1` does the same anywhere. Then the
  switch can't be turned off in the app. A settings file can switch it on, never off. What you set up yourself (AI,
  Grafana, Proxmox, Elasticsearch) still goes where you point it.
- **Tools installed with mise are found**: `kubectl`, `oc`, `helm`, kubectl's plugins and the AI programs (Claude
  Code, Codex). mise puts its programs on the PATH only inside a shell, which an app started from the Dock or the
  Start menu isn't in, so Kubedog looks in mise's own folder: per tool the version mise calls the latest, and the
  program itself rather than mise's stand-in for it.
- **Settings as a file** (Settings > General): everything from Settings written to one file, the namespaces listed per
  cluster included, and read in again on another computer or after a reinstall. No password or key is in it. What a
  file never changes: your kubeconfig files (they go along by where they are, and are added when they're there),
  your logins, which clusters start with changes allowed, and AI stays off unless it's on already. You're shown what
  the file holds and asked before anything changes.
- **Settings > Sidebar:** the order of the menu on the left, by dragging or with arrows.
- **Settings > Superpowers:** Auto, On or Off for each; Off reads nothing for it.
- **Superpowers:** a sidebar section under Workloads with what the open clusters really have:
  Postgres, Elasticsearch, Pulsar.
- **Pod Hive:** a honeycomb of pods, filled as far as each uses its memory or CPU limit (by namespace,
  workload or node), usage over time, workloads close to their limits, workloads that ask for far more
  than they use, quotas, and what your account may do.
- **Accounts with a few namespaces** (Rancher projects, for example): list the namespaces per cluster and
  everything that needs no cluster-wide right works: custom kinds are found without reading their
  definitions, nodes are shown as seen from your pods, Helm is read per namespace, and pages say what
  the account can't read.
- **Nodes from a Grafana (optional, per cluster):** for accounts that may not read nodes, and for history.
  Cards per node, what needs a look, a heat timeline up to 7 days, and a page per node. Once Grafana shows a
  cluster's nodes, the notice that your account can't list nodes is no longer shown for that cluster. Set it up in
  Settings > Special monitoring: address, login, data source (Prometheus with node exporter figures), and your own
  certificate authority (file, paste or drop). Reads only; certificates are always checked. The password is asked
  for once per run and kept in memory only, or, with a tick, kept in the system's keychain once Grafana accepts it,
  so it isn't asked again. It is never in the settings, and a settings file doesn't carry it or say that it's kept.
- **Postgres (CloudNativePG):**
  - A page per cluster: a live replication map, health checks, write activity and lag, instances,
    backups and the window that can be restored, addresses, databases, roles, certificates.
  - The map also shows on the pod page of each instance.
  - With the `kubectl cnpg` plugin: live state, psql (read-only while the cluster is protected),
    back up, reload, restart and switch over. Every change asks first.
- **Elasticsearch (ECK):** nodes with heap, CPU and disk, health checks (shards, disk, masters,
  copies, rejected work, licence), activity, a map of where the space goes, the biggest indices.
- **Pulsar:** topics with their writers and readers, waiting messages, brokers, health checks. Found by
  its pods (the Helm chart, or a standalone pod).
- Elasticsearch and Pulsar are read with the login in their own secret, after you allow it per
  cluster. The login is read again for every refresh, passed to curl over a pipe, never shown or
  saved, and only used for GET requests through a short-lived port forward.
- **Namespaces:** tick several in the namespace menu to see them together (with a search box).
- **Search (⌘K):** pages and every object read so far, across clusters.
- **References, labels and annotations** in one table of three columns on every Overview: what an object
  belongs to, uses and is used by (as links), and its labels and annotations (a click copies, long ones
  open).
- **Every object's page** starts with its health in a sentence, its conditions and the facts an admin
  looks for, then what matters for its kind:
  - **Deployments, StatefulSets, DaemonSets, ReplicaSets, Jobs, CronJobs:** a live map (ingresses and
    routes, services, one tank per pod, configuration, secrets, disks), rollout status and strategy,
    pod placement over nodes, autoscaler and disruption budget, usage against requests and limits,
    containers and pods; tabs for Containers, Environment and Scheduling. Run now and Suspend for
    cron jobs, Pause and Resume rollout for deployments.
  - **Services, Ingresses, NetworkPolicies:** endpoints and where traffic goes, backends with their
    readiness, policy rules in words with the pods they select.
  - **The rest:** who uses a config map, secret, account or claim; autoscaler metrics; quota use;
    role rules with the risky ones marked and who they're bound to; namespaces with their workloads;
    storage classes with their claims; webhooks, leases, budgets and custom resources.
- **Revisions** of Deployments, StatefulSets and DaemonSets: the rollout history with rolling back to a revision.
- **Extra kinds:** Priority Classes, Runtime Classes, Mutating and Validating Webhooks, and
  Certificate Signing Requests.
- **Actions:** scale, restart, delete, cordon, drain, port forward, shell, and Helm uninstall.
  - **Several at once:** in every list, custom resources too (not nodes, namespaces, definitions, events and the
    cluster's own volume bookkeeping): the boxes left of a row, ⌘-click, ⇧-click for a range, ⌘A for all that's shown.
    Delete, or restart for workloads. One confirmation says what happens: what's made again, what goes down, what
    still uses them, whether data is lost. Each row also has the icons.
  - Every cluster starts **protected**; you unlock it for the session before changing anything.
  - Every change asks for confirmation first.
- **Shells:** a built-in terminal docked at the bottom (⌘J), or your terminal app.
- **Dashboards:** cluster and workloads overviews, a Service Map, and storage usage per volume claim.
- **Comfort:**
  - Back and Forward as in a browser: ⌘[ ⌘] or ⌘← ⌘→ (Alt+← Alt+→ elsewhere) and the mouse's side buttons, all the same as the ← on a page;
  - picks up where you left off (clusters, page, namespace, zoom, window size);
  - themes Auto (follows the system), Dark, Light and Sand, and apart from that a colour for names,
    links and buttons: orange, blue, green, teal, purple, pink or grey;
  - five fonts (Ubuntu, Inter, IBM Plex Sans, Atkinson Hyperlegible, JetBrains Mono) and seven text sizes;
  - a macOS menu bar, "G then a letter" page shortcuts, and ⌃1–9 for cluster groups.
