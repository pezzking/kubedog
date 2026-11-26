//! The Shell: full-size terminals, each set up for one cluster. Every tool in it (kubectl, helm, argocd, the
//! CloudNativePG plugin...) finds that cluster through a small kubeconfig of the shell's own, put in front of the
//! person's files: it only names the cluster and the namespace, so switching in a shell never touches those files.
//! While a cluster is protected in Kubedog, the shell asks before a command that changes something. What a person
//! types is theirs: that question is a reminder, not a wall.

use super::incident::chip_button;
use super::work::said;
use super::*;
use std::path::{Path, PathBuf};

/// A tool, with ready commands: (what's typed, what it does, does it change something).
struct Tool {
    program: &'static str,
    label: &'static str,
    ready: &'static [(&'static str, &'static str, bool)],
}

const TOOLS: &[Tool] = &[
    Tool {
        program: "kubectl",
        label: "Kubernetes",
        ready: &[
            ("kn ", "this shell's namespace: kn shop; kn alone lists them", false),
            ("kx ", "this shell's cluster: kx other; kx alone lists them", false),
            ("kubectl get pods", "pods here", false),
            ("kubectl get events --sort-by=.lastTimestamp", "what happened", false),
            ("kubectl top pods", "CPU and memory", false),
            ("kubectl describe pod ", "all about a pod", false),
            ("kubectl logs -f --tail=100 ", "follow a pod's log", false),
            ("kubectl get all", "what runs here", false),
            ("kubectl rollout status deployment/", "how a rollout goes", false),
            ("kubectl rollout history deployment/", "versions of a deployment", false),
            ("kubectl diff -f ", "what a file would change", false),
            ("kubectl auth can-i --list", "what you may do", false),
            ("kubectl explain ", "fields of a kind", false),
            ("kubectl exec -it  -- sh", "a shell in a pod", false),
            ("kubectl rollout restart deployment/", "restart a deployment", true),
            ("kubectl scale --replicas=  deployment/", "change the number of pods", true),
            ("kubectl apply -f ", "apply a file", true),
        ],
    },
    Tool {
        program: "helm",
        label: "Helm",
        ready: &[
            ("helm list -A", "all releases", false),
            ("helm status ", "one release", false),
            ("helm history ", "its versions", false),
            ("helm get values ", "its settings (can hold secrets)", false),
            ("helm get manifest ", "what it made", false),
            ("helm template ", "what a chart would make", false),
            ("helm search repo ", "look for a chart", false),
            ("helm rollback ", "back to an older version", true),
            ("helm upgrade --install  ", "install or upgrade", true),
        ],
    },
    Tool {
        program: "argocd",
        label: "Argo CD",
        ready: &[
            ("acd app list", "applications, with your cluster rights (no login)", false),
            ("acd app get ", "one application", false),
            ("acd app diff ", "what differs from Git", false),
            ("acd app history ", "what was deployed when", false),
            ("acd app sync --dry-run ", "what a sync would do", false),
            ("argocd login --sso ", "log in to its server", false),
            ("acd app sync ", "bring it to what Git says", true),
            ("acd app rollback ", "back to an older one", true),
        ],
    },
    Tool {
        program: "kubectl-cnpg",
        label: "Postgres (CloudNativePG)",
        ready: &[
            ("kubectl get clusters.postgresql.cnpg.io -A", "Postgres clusters", false),
            ("kubectl cnpg status ", "how one is doing", false),
            ("kubectl cnpg psql ", "a psql in it", false),
            ("kubectl cnpg logs cluster ", "its logs", false),
            ("kubectl cnpg backup ", "make a backup", true),
            ("kubectl cnpg promote ", "another primary", true),
            ("kubectl cnpg restart ", "restart it", true),
        ],
    },
    Tool { program: "oc", label: "OpenShift", ready: &[("oc status", "this project", false), ("oc whoami", "who you are", false), ("oc get clusteroperators", "the platform's parts", false), ("oc get clusterversion", "version and updates", false), ("oc adm top nodes", "nodes", false), ("oc rollout latest ", "a new deployment", true)] },
    Tool { program: "k9s", label: "k9s", ready: &[("k9s", "a full-screen view (it doesn't ask)", false), ("k9s --readonly", "the same, reading only", false)] },
    Tool { program: "stern", label: "stern", ready: &[("stern ", "logs of many pods at once", false)] },
    Tool { program: "kustomize", label: "Kustomize", ready: &[("kustomize build ", "what a folder makes", false)] },
    Tool { program: "flux", label: "Flux", ready: &[("flux get all -A", "everything it keeps", false), ("flux events", "what it did", false), ("flux reconcile kustomization ", "do it now", true)] },
    Tool { program: "istioctl", label: "Istio", ready: &[("istioctl proxy-status", "are the proxies up to date", false), ("istioctl analyze", "look for mistakes", false)] },
    Tool { program: "cilium", label: "Cilium", ready: &[("cilium status", "the network", false)] },
    Tool { program: "velero", label: "Velero", ready: &[("velero backup get", "backups", false), ("velero schedule get", "schedules", false), ("velero backup create ", "make a backup", true)] },
    Tool { program: "kubectl-argo-rollouts", label: "Argo Rollouts", ready: &[("kubectl argo rollouts list rollouts", "rollouts", false), ("kubectl argo rollouts get rollout ", "one", false)] },
    Tool { program: "tkn", label: "Tekton", ready: &[("tkn pipelinerun list", "runs", false), ("tkn pipelinerun logs -f ", "a run's log", false)] },
    Tool { program: "cmctl", label: "cert-manager", ready: &[("cmctl status certificate ", "a certificate", false), ("cmctl renew ", "renew it", true)] },
    Tool { program: "kubeseal", label: "Sealed Secrets", ready: &[("kubeseal --fetch-cert", "the key to seal with", false)] },
    Tool { program: "virtctl", label: "Virtual machines", ready: &[("virtctl console ", "a machine's console", false)] },
    Tool { program: "vault", label: "Vault", ready: &[("vault status", "is it open", false)] },
    Tool { program: "yq", label: "yq", ready: &[("kubectl get -o yaml  | yq ", "pick from YAML", false)] },
    Tool { program: "jq", label: "jq", ready: &[("kubectl get -o json  | jq ", "pick from JSON", false)] },
];

#[derive(Default)]
pub(super) struct Shells {
    pub dock: terminal::Dock,
    /// Which tools this computer has.
    found: Option<Vec<bool>>,
    find: String,
    hide_tools: bool,
    /// The person closed the last one: the next isn't opened by itself.
    closed: bool,
    size: f32,
    /// What the shells were last told about protection.
    told: String,
    /// The Linuxes on this Windows computer (WSL), the default one first.
    linuxes: Option<Vec<String>>,
    /// What the shell that's shown said last.
    seen: Option<(PathBuf, Instant, Seen)>,
}

/// What a shell wrote in its folder.
#[derive(Clone, Default)]
struct Seen {
    now: Option<(String, String)>,
    /// zsh, bash...; empty while it starts.
    kind: String,
    /// Runs in WSL.
    linux: bool,
    /// Which tools are there, once it has looked (only in WSL; else they're this computer's).
    tools: Option<Vec<bool>>,
}

fn look(dir: &Path) -> Seen {
    let read = |n: &str| std::fs::read_to_string(dir.join(n)).ok();
    Seen {
        now: read("now").and_then(|t| read_now(&t)),
        kind: read("kind").unwrap_or_default().trim().to_string(),
        linux: dir.join("start.sh").exists(),
        tools: read("tools").map(|t| TOOLS.iter().map(|x| t.lines().any(|l| l.trim() == x.program)).collect()),
    }
}

/// Does a shell of this kind ask before changes?
fn asks(kind: &str) -> bool {
    matches!(kind, "zsh" | "bash")
}

// ---------- Linux in Windows (WSL) ----------

/// The names in what Windows' registry says about WSL: the ones that run now first, then the default one. One that
/// runs is offered whatever it's called.
fn linuxes_in(reg: &str, running: &[String]) -> Vec<String> {
    let runs = |n: &str| running.iter().any(|r| r.eq_ignore_ascii_case(n));
    let mut l: Vec<(String, String)> = vec![];
    let (mut key, mut default) = (String::new(), String::new());
    for line in reg.lines().map(|l| l.trim()) {
        if line.starts_with("HKEY") {
            key = line.rsplit('\\').next().unwrap_or("").to_string();
            continue;
        }
        let mut p = line.splitn(3, "    ").map(|x| x.trim());
        match (p.next(), p.next(), p.next()) {
            (Some("DefaultDistribution"), _, Some(v)) => default = v.to_string(),
            (Some("DistributionName"), _, Some(v)) => {
                let v = v.trim();
                // Some are another program's inside, without a shell for people.
                let inner = ["docker-desktop", "rancher-desktop", "podman-"].iter().any(|x| v.starts_with(x));
                if !v.is_empty() && (!inner || runs(v)) && !v.starts_with('-') {
                    l.push((key.clone(), v.to_string()));
                }
            }
            _ => {}
        }
    }
    for r in running {
        if !l.iter().any(|x| x.1.eq_ignore_ascii_case(r)) {
            l.push((String::new(), r.clone()));
        }
    }
    l.sort_by_key(|x| (!runs(&x.1), !x.0.eq_ignore_ascii_case(&default), x.1.to_lowercase()));
    l.into_iter().map(|x| x.1).collect()
}

/// The names in what `wsl --list --running --quiet` wrote (two bytes a letter, unless it was told otherwise). A
/// sentence ("there are none") isn't a name.
fn running_in(out: &[u8]) -> Vec<String> {
    let wide = out.starts_with(&[0xff, 0xfe]) || out.get(1) == Some(&0);
    let t = if wide { String::from_utf16_lossy(&out.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>()) } else { String::from_utf8_lossy(out).to_string() };
    t.lines().map(|l| l.trim().trim_start_matches('\u{feff}').to_string()).filter(|l| !l.is_empty() && !l.starts_with('-') && l.chars().all(|c| c.is_alphanumeric() || "._-".contains(c))).collect()
}

fn system32(program: &str) -> PathBuf {
    kube::system32(program)
}

fn find_linuxes() -> Vec<String> {
    if !cfg!(windows) || !system32("wsl.exe").is_file() {
        return vec![];
    }
    let mut c = std::process::Command::new(system32("reg.exe"));
    c.args(["query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss", "/s"]).stdin(std::process::Stdio::null());
    kube::quiet(&mut c);
    let reg = c.output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    // Only where WSL is set up: elsewhere wsl.exe offers to install it.
    let running = if reg.contains("Lxss") { find_running() } else { vec![] };
    linuxes_in(&reg, &running)
}

/// The Linuxes that run now. Not waited for long: a WSL that's stuck doesn't answer.
fn find_running() -> Vec<String> {
    let mut c = std::process::Command::new(system32("wsl.exe"));
    c.args(["--list", "--running", "--quiet"]).env("WSL_UTF8", "1").stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null());
    kube::quiet(&mut c);
    let Ok(mut child) = c.spawn() else { return vec![] };
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        match child.try_wait() {
            Ok(Some(s)) if s.success() => break,
            Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(30)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return vec![];
            }
        }
    }
    let mut out = vec![];
    if let Some(mut o) = child.stdout.take() {
        let _ = std::io::Read::read_to_end(&mut o, &mut out);
    }
    running_in(&out)
}

/// Runs in the Linux, in the shell's folder: works out the paths as Linux sees them, and starts the person's shell.
const START_WSL: &str = r##"KUBEDOG_SHELL=$(pwd -P)
KUBEDOG_REST=
while IFS= read -r kd_p || [ -n "$kd_p" ]; do
  [ -n "$kd_p" ] || continue
  # One of the Linux's own files is taken as it is; one of Windows' is turned into its path here.
  case "$kd_p" in
    /*) kd_x=$kd_p;;
    *) kd_x=$(wslpath -u "$kd_p" </dev/null 2>/dev/null) || continue;;
  esac
  KUBEDOG_REST="$KUBEDOG_REST${KUBEDOG_REST:+:}$kd_x"
done < rest
KUBEDOG_FRONT="$KUBEDOG_SHELL/config${KUBEDOG_REST:+:$KUBEDOG_REST}"
KUBECONFIG=$KUBEDOG_FRONT
COLORTERM=truecolor
export KUBEDOG_SHELL KUBEDOG_REST KUBEDOG_FRONT KUBECONFIG COLORTERM
unset kd_p kd_x
cd "$HOME" || cd /
s=$SHELL
[ -x "$s" ] || s=$(getent passwd "$(id -un)" 2>/dev/null | cut -d: -f7)
[ -x "$s" ] || s=/bin/sh
kd_kind=${s##*/}
echo "$kd_kind" > "$KUBEDOG_SHELL/kind"
case "$kd_kind" in
  zsh)
    if [ -n "$ZDOTDIR" ]; then KUBEDOG_ZDOT=$ZDOTDIR; export KUBEDOG_ZDOT; fi
    ZDOTDIR=$KUBEDOG_SHELL exec "$s" -il;;
  bash) exec "$s" --rcfile "$KUBEDOG_SHELL/init.bash" -i;;
  fish) exec "$s" -il -C 'source "$KUBEDOG_SHELL/init.fish"';;
  *) ENV="$KUBEDOG_SHELL/init.plain" exec "$s" -i;;
esac
"##;

/// Which tools there are, where Windows can't see it; and a word when the first one is missing.
const TOOLS_WSL: &str = r##"
( (
  unalias -a 2>/dev/null
  for kd_t in kubectl oc helm argocd flux velero cmctl istioctl cilium tkn virtctl; do unset -f "$kd_t" 2>/dev/null; done
  for kd_t in @TOOLS@; do command -v "$kd_t" >/dev/null 2>&1 && echo "$kd_t"; done > "$KUBEDOG_SHELL/tools.new"
  mv -f "$KUBEDOG_SHELL/tools.new" "$KUBEDOG_SHELL/tools"
) >/dev/null 2>&1 & )
if ! ( unalias -a 2>/dev/null; unset -f kubectl 2>/dev/null; command -v kubectl >/dev/null 2>&1 ); then
  echo "kubectl isn't installed in this Linux, and Kubedog doesn't install it: the cluster can't be reached from here"
  echo "until you install it. The same goes for helm, argocd and the other tools you want to use here."
fi
"##;

// ---------- what a shell is set up with ----------

/// A shell that's known: how it's started, and which set-up it reads.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Flavour {
    Zsh,
    Bash,
    Fish,
    Power,
    Sh,
}

fn flavour(program: &str) -> Flavour {
    let name = program.rsplit(['/', '\\']).next().unwrap_or(program).trim_end_matches(".exe").to_lowercase();
    match name.as_str() {
        "zsh" => Flavour::Zsh,
        "bash" => Flavour::Bash,
        "fish" => Flavour::Fish,
        "pwsh" | "powershell" => Flavour::Power,
        _ => Flavour::Sh,
    }
}

/// The person's own shell.
fn own_shell() -> String {
    if cfg!(windows) {
        return kube::find_program("pwsh").or_else(|| kube::find_program("powershell")).map(|p| p.to_string_lossy().to_string()).unwrap_or("powershell.exe".into());
    }
    std::env::var("SHELL").ok().filter(|s| Path::new(s).is_file()).unwrap_or_else(|| if cfg!(target_os = "macos") { "/bin/zsh".into() } else { "/bin/sh".into() })
}

/// The kubeconfig that goes in front: it names the cluster to use and each one's namespace, and refers to the
/// person's files for everything else. Nothing secret is in it.
fn front_config(contexts: &[ContextInfo], current: &str, namespace: &dyn Fn(&ContextInfo) -> String) -> Value {
    let l: Vec<Value> = contexts
        .iter()
        .filter(|c| !c.cluster.is_empty())
        .map(|c| {
            let mut x = serde_json::json!({"cluster": c.cluster, "user": c.user});
            let ns = namespace(c);
            if !ns.is_empty() {
                x["namespace"] = ns.into();
            }
            serde_json::json!({"name": c.name, "context": x})
        })
        .collect();
    serde_json::json!({"apiVersion": "v1", "kind": "Config", "current-context": current, "contexts": l, "clusters": [], "users": [], "preferences": {}})
}

/// zsh and bash: what every shell gets after the person's own start-up files.
const INIT_SH: &str = r##"
kd_tell() { command kubectl config view --minify -o 'jsonpath={.current-context}{"\n"}{..namespace}{"\n"}' > "$KUBEDOG_SHELL/now" 2>/dev/null; }
kx() { if [ -n "$1" ]; then command kubectl config use-context "$1" && kd_tell; else command kubectl config get-contexts -o name; fi; }
kn() { if [ -n "$1" ]; then command kubectl config set-context --current --namespace="$1" >/dev/null && kd_tell && echo "namespace $1"; else command kubectl get namespaces -o name | sed 's#^namespace/##'; fi; }
kd_context() {
  local c= p= a=
  for a in "$@"; do
    case "$p" in --context|--kube-context) c=$a;; esac
    case "$a" in --context=*) c=${a#--context=};; --kube-context=*) c=${a#--kube-context=};; esac
    p=$a
  done
  if [ -z "$c" ]; then c=$(command kubectl config current-context 2>/dev/null); fi
  printf '%s' "$c"
}
kd_words() {
  local skip= a= n=0
  for a in "$@"; do
    if [ -n "$skip" ]; then skip=; continue; fi
    case "$a" in
      -n|--namespace|--context|--kube-context|--kubeconfig|--cluster|--user|-s|--server|--as|--token|--grpc-web-root-path) skip=1;;
      -o|--output|-f|--filename|-l|--selector|-v|--v|-c|--container) skip=1;;
      --) break;;
      -*) ;;
      *) printf '%s ' "$a"; n=$((n+1)); if [ "$n" = 3 ]; then break; fi;;
    esac
  done
}
kd_ask() {
  local tool=$1 ctx= ans=
  shift
  ctx=$(kd_context "$@")
  if grep -qxF -e "$ctx" "$KUBEDOG_SHELL/unlocked" 2>/dev/null; then return 0; fi
  printf '\033[33m%s\033[0m is protected in Kubedog, and this changes something:\n  %s %s\nGo on? [y/N] ' "$ctx" "$tool" "$*" > /dev/tty
  read -r ans < /dev/tty || return 1
  case "$ans" in y|Y|yes|j|J) return 0;; esac
  echo "Not done." > /dev/tty
  return 1
}
kd_changes() {
  local tool=$1 w= a=
  shift
  for a in "$@"; do case "$a" in --dry-run|--dry-run=client|--dry-run=server|-h|--help) return 1;; esac; done
  w=$(kd_words "$@")
  case "$tool:$w" in
    kubectl:rollout\ status*|kubectl:rollout\ history*) return 1;;
    kubectl:apply\ view-last*|kubectl:auth\ can-i*) return 1;;
    kubectl:apply*|kubectl:create*|kubectl:delete*|kubectl:edit*|kubectl:patch*|kubectl:replace*|kubectl:scale*|kubectl:autoscale*|kubectl:rollout*|kubectl:drain*|kubectl:cordon*|kubectl:uncordon*|kubectl:taint*|kubectl:label*|kubectl:annotate*|kubectl:set\ *|kubectl:expose*|kubectl:run\ *|kubectl:debug*|kubectl:cp\ *|kubectl:auth\ reconcile*|kubectl:certificate*) return 0;;
    kubectl:cnpg\ promote*|kubectl:cnpg\ restart*|kubectl:cnpg\ reload*|kubectl:cnpg\ destroy*|kubectl:cnpg\ fencing*|kubectl:cnpg\ hibernate*|kubectl:cnpg\ maintenance*|kubectl:cnpg\ backup*|kubectl:cnpg\ snapshot*|kubectl:cnpg\ pgbench*|kubectl:cnpg\ fio*|kubectl:cnpg\ publication*|kubectl:cnpg\ subscription*) return 0;;
    kubectl:argo\ rollouts\ promote*|kubectl:argo\ rollouts\ abort*|kubectl:argo\ rollouts\ undo*|kubectl:argo\ rollouts\ set*|kubectl:argo\ rollouts\ restart*|kubectl:argo\ rollouts\ retry*|kubectl:argo\ rollouts\ pause*) return 0;;
    kubectl:new-app*|kubectl:new-project*|kubectl:start-build*|kubectl:import-image*|kubectl:policy*|kubectl:adm\ drain*|kubectl:adm\ cordon*|kubectl:adm\ uncordon*|kubectl:adm\ policy*|kubectl:adm\ upgrade*|kubectl:adm\ must-gather*|kubectl:adm\ taint*|kubectl:adm\ prune*) return 0;;
    helm:install*|helm:upgrade*|helm:uninstall*|helm:delete*|helm:rollback*|helm:test*) return 0;;
    argocd:app\ list*|argocd:app\ get*|argocd:app\ diff*|argocd:app\ history*|argocd:app\ logs*|argocd:app\ manifests*|argocd:app\ resources*|argocd:app\ wait*) return 1;;
    argocd:app\ *|argocd:appset\ create*|argocd:appset\ delete*|argocd:cluster\ add*|argocd:cluster\ rm*|argocd:repo\ add*|argocd:repo\ rm*|argocd:proj\ create*|argocd:proj\ delete*|argocd:proj\ edit*|argocd:proj\ set*|argocd:proj\ add*|argocd:proj\ remove*|argocd:account\ update*) return 0;;
    flux:reconcile*|flux:suspend*|flux:resume*|flux:delete*|flux:create*|flux:install*|flux:uninstall*|flux:bootstrap*) return 0;;
    velero:backup\ create*|velero:backup\ delete*|velero:restore\ create*|velero:install*|velero:uninstall*|velero:schedule\ create*|velero:schedule\ delete*) return 0;;
    cmctl:renew*|cmctl:approve*|cmctl:deny*|cmctl:upgrade*|istioctl:install*|istioctl:upgrade*|istioctl:uninstall*|cilium:install*|cilium:upgrade*|cilium:uninstall*|tkn:*\ start*|tkn:*\ delete*|tkn:*\ cancel*|virtctl:start*|virtctl:stop*|virtctl:restart*|virtctl:migrate*|virtctl:pause*) return 0;;
  esac
  return 1
}
kd_run() {
  local tool=$1 as=$1
  shift
  case "$tool" in oc) as=kubectl;; esac
  if kd_changes "$as" "$@" && ! kd_ask "$tool" "$@"; then return 130; fi
  command "$tool" "$@"
}
for kd_t in kubectl oc helm argocd flux velero cmctl istioctl cilium tkn virtctl; do
  unalias "$kd_t" 2>/dev/null
  eval "function $kd_t { kd_run $kd_t \"\$@\"; }"
done
unset kd_t
alias k=kubectl
# Argo CD with your rights in the cluster instead of a login.
function acd {
  if kd_changes argocd "$@" && ! kd_ask argocd "$@"; then return 130; fi
  KUBECONFIG="$KUBEDOG_SHELL/argocd:$KUBEDOG_REST" command argocd --core --kube-context "$(command kubectl config current-context)" "$@"
}
kd_tell
"##;

/// zsh: the person's own files first, from where they are.
fn zsh_files(user_dir: &str) -> Vec<(&'static str, String)> {
    let mut v = vec![];
    for f in [".zshenv", ".zprofile", ".zlogin"] {
        v.push((f, format!("ZDOTDIR={user_dir}\n[ -f \"$ZDOTDIR/{f}\" ] && . \"$ZDOTDIR/{f}\"\nif [ \"$ZDOTDIR\" != \"$KUBEDOG_SHELL\" ]; then KUBEDOG_ZDOT=$ZDOTDIR; fi\nZDOTDIR=$KUBEDOG_SHELL\n")));
    }
    // Shells started from this one read these files too.
    v.push((
        ".zshrc",
        "ZDOTDIR=${KUBEDOG_ZDOT:-$HOME}\n[ -f \"$ZDOTDIR/.zshrc\" ] && . \"$ZDOTDIR/.zshrc\"\n[[ \"$HISTFILE\" == \"$KUBEDOG_SHELL\"* ]] && HISTFILE=\"$ZDOTDIR/.zsh_history\"\nif ! (( $+functions[compdef] )); then autoload -Uz compinit && compinit -C -d \"$KUBEDOG_SHELL/zcompdump\"; fi\n. \"$KUBEDOG_SHELL/init.sh\"\nfor kd_t in kubectl helm argocd oc; do if (( $+commands[$kd_t] )) && ! (( $+_comps[$kd_t] )); then source <(command $kd_t completion zsh 2>/dev/null) 2>/dev/null; compdef _$kd_t $kd_t 2>/dev/null; fi; done; unset kd_t\nautoload -Uz add-zsh-hook && add-zsh-hook precmd kd_tell_if\nZDOTDIR=$KUBEDOG_SHELL\n".to_string(),
    ));
    v
}

/// Tells Kubedog when the cluster or namespace was changed another way (kubectl config, oc project).
const TELL_IF: &str = "kd_tell_if() { if [ \"$KUBEDOG_SHELL/config\" -nt \"$KUBEDOG_SHELL/now\" ]; then kd_tell; fi; }\n";

/// bash: telling, and completion where the person has that.
const BASH_MORE: &str = r##"
PROMPT_COMMAND="kd_tell_if${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
if type _get_comp_words_by_ref >/dev/null 2>&1; then for kd_t in kubectl helm argocd oc; do if type -P "$kd_t" >/dev/null; then source <(command $kd_t completion bash 2>/dev/null); fi; done; fi
"##;

/// A plain sh: switching only.
const INIT_PLAIN: &str = r##"kd_tell() { :; }
kn() { kubectl config set-context --current --namespace="$1"; }
kx() { kubectl config use-context "$1"; }
"##;

const INIT_FISH: &str = r##"
function kd_tell; command kubectl config view --minify -o 'jsonpath={.current-context}{"\n"}{..namespace}{"\n"}' > $KUBEDOG_SHELL/now 2>/dev/null; end
function kx; if test -n "$argv[1]"; command kubectl config use-context $argv[1]; and kd_tell; else; command kubectl config get-contexts -o name; end; end
function kn; if test -n "$argv[1]"; command kubectl config set-context --current --namespace=$argv[1] >/dev/null; and kd_tell; and echo "namespace $argv[1]"; else; command kubectl get namespaces -o name | string replace 'namespace/' ''; end; end
function acd; KUBECONFIG="$KUBEDOG_SHELL/argocd:$KUBEDOG_REST" command argocd --core --kube-context (command kubectl config current-context) $argv; end
alias k kubectl
kd_tell
"##;

const INIT_POWER: &str = r##"
function kd_tell { kubectl config view --minify -o 'jsonpath={.current-context}{"\n"}{..namespace}{"\n"}' 2>$null | Set-Content -Path (Join-Path $env:KUBEDOG_SHELL 'now') }
function kx($c) { if ($c) { kubectl config use-context $c; kd_tell } else { kubectl config get-contexts -o name } }
function kn($n) { if ($n) { kubectl config set-context --current --namespace=$n | Out-Null; kd_tell; "namespace $n" } else { kubectl get namespaces -o name } }
Set-Alias k kubectl
kd_tell
"##;

/// A shell that's ready to start: program, arguments, environment, its folder.
struct Start {
    program: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
    dir: PathBuf,
}

/// Makes a folder only this person can look into; never one that's there already.
fn own_dir() -> Result<PathBuf, String> {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    let d = std::env::temp_dir().join(format!("kubedog-shell-{}-{t:x}-{}", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)));
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(&d).map_err(|e| format!("a folder for the shell couldn't be made: {e}"))?;
    Ok(d)
}

/// Folders left behind by a Kubedog that isn't there anymore (it crashed) are cleared, once.
fn sweep() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if cfg!(windows) {
            return;
        }
        for e in std::fs::read_dir(std::env::temp_dir()).into_iter().flatten().flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let Some(pid) = name.strip_prefix("kubedog-shell-").and_then(|r| r.split('-').next()).and_then(|p| p.parse::<u32>().ok()) else { continue };
            let lives = std::process::Command::new("/bin/ps").args(["-p", &pid.to_string()]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().map(|s| s.success()).unwrap_or(true);
            if !lives && e.file_type().is_ok_and(|t| t.is_dir()) {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    });
}

/// What to set a shell up for.
struct For<'a> {
    contexts: &'a [ContextInfo],
    ctx: &'a str,
    ns: Option<&'a str>,
    /// Where Argo CD runs in a cluster.
    argo: &'a dyn Fn(&str) -> String,
    /// The person's own kubeconfig files, as KUBECONFIG has them.
    rest: &'a str,
    /// The kubectl Kubedog uses, for a computer without one of its own.
    kubectl: Option<&'a Path>,
}

/// The files every shell has.
fn common(dir: &Path, f: &For) -> Result<(), String> {
    let write = |name: &str, text: &str| std::fs::write(dir.join(name), text).map_err(|e| e.to_string());
    let config = front_config(f.contexts, f.ctx, &|c| match f.ns.filter(|_| c.name == f.ctx) {
        Some(n) => n.to_string(),
        None => c.namespace.clone(),
    });
    write("config", &config.to_string())?;
    write("argocd", &front_config(f.contexts, f.ctx, &|c| (f.argo)(&c.name)).to_string())?;
    write("unlocked", "")?;
    write("now", "")
}

/// A shell in a Linux in Windows (WSL). No path and nothing that needs quotes is on its command line.
fn prepare_wsl(linux: &str, f: &For) -> Result<Start, String> {
    let dir = own_dir()?;
    let r = (|| -> Result<Start, String> {
        let write = |name: &str, text: &str| std::fs::write(dir.join(name), text).map_err(|e| e.to_string());
        common(&dir, f)?;
        // One per line: the Linux side turns them into its own paths.
        write("rest", &f.rest.split(kube::LIST_SEP).filter(|x| !x.is_empty()).map(|x| format!("{x}\n")).collect::<String>())?;
        let tools = TOOLS.iter().map(|t| t.program).collect::<Vec<_>>().join(" ");
        let set = "export KUBECONFIG=\"$KUBEDOG_FRONT\"\n";
        write("start.sh", START_WSL)?;
        write("init.sh", &format!("{set}{TELL_IF}{INIT_SH}{}", TOOLS_WSL.replace("@TOOLS@", &tools)))?;
        for (n, t) in zsh_files("${KUBEDOG_ZDOT:-$HOME}") {
            write(n, &t)?;
        }
        // This isn't a login shell, so what one reads is read here.
        write("init.bash", &format!("[ -f /etc/profile ] && . /etc/profile\nif [ -f ~/.bash_profile ]; then . ~/.bash_profile; elif [ -f ~/.bash_login ]; then . ~/.bash_login; elif [ -f ~/.profile ]; then . ~/.profile; elif [ -f ~/.bashrc ]; then . ~/.bashrc; fi\n. \"$KUBEDOG_SHELL/init.sh\"\n{BASH_MORE}"))?;
        write("init.fish", &format!("set -gx KUBECONFIG $KUBEDOG_FRONT\n{INIT_FISH}"))?;
        write("init.plain", &format!("{set}{INIT_PLAIN}"))?;
        // Long names, without the \\?\ Windows puts in front.
        let cd = std::fs::canonicalize(&dir).map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
        let cd = match cd.strip_prefix(r"\\?\") {
            Some(c) if !c.starts_with("UNC") => c.to_string(),
            _ => dir.to_string_lossy().to_string(),
        };
        let args = ["-d", linux, "--cd", &cd, "--exec", "sh", "./start.sh"].iter().map(|a| a.to_string()).collect();
        Ok(Start { program: system32("wsl.exe").to_string_lossy().to_string(), args, env: vec![], dir: dir.clone() })
    })();
    if r.is_err() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    r
}

fn prepare(program: &str, f: &For) -> Result<Start, String> {
    let dir = own_dir()?;
    let r = (|| -> Result<Start, String> {
        let write = |name: &str, text: &str| std::fs::write(dir.join(name), text).map_err(|e| e.to_string());
        common(&dir, f)?;
        write("kind", &format!("{:?}", flavour(program)).to_lowercase())?;
        let d = dir.to_string_lossy().to_string();
        let sep = kube::LIST_SEP;
        // Last in the search: the person's own kubectl comes first. (oc, called kubectl, acts as one.)
        let mut path = kube::child_path();
        if let Some(k) = f.kubectl {
            #[cfg(unix)]
            {
                std::fs::create_dir(dir.join("bin")).map_err(|e| e.to_string())?;
                let _ = std::os::unix::fs::symlink(k, dir.join("bin").join("kubectl"));
                path = format!("{path}{sep}{d}/bin");
            }
            #[cfg(not(unix))]
            if let Some(p) = k.parent() {
                path = format!("{path}{sep}{}", p.display());
            }
        }
        let front = if f.rest.is_empty() { format!("{d}{}config", std::path::MAIN_SEPARATOR) } else { format!("{d}{}config{sep}{}", std::path::MAIN_SEPARATOR, f.rest) };
        let mut env: Vec<(String, String)> = vec![("KUBECONFIG".into(), front.clone()), ("KUBEDOG_SHELL".into(), d.clone()), ("KUBEDOG_REST".into(), f.rest.into()), ("PATH".into(), path)];
        // After the person's own files, which may set it too.
        let set = format!("export KUBECONFIG={} KUBEDOG_SHELL={} KUBEDOG_REST={}\nPATH=\"$PATH:$KUBEDOG_SHELL/bin\"\n", sh_quote(&front), sh_quote(&d), sh_quote(f.rest));
        let args: Vec<String> = match flavour(program) {
            Flavour::Zsh => {
                let user = std::env::var("ZDOTDIR").ok().filter(|z| !z.is_empty());
                for (n, t) in zsh_files("${KUBEDOG_ZDOT:-$HOME}") {
                    write(n, &t)?;
                }
                write("init.sh", &format!("{set}{TELL_IF}{INIT_SH}"))?;
                env.push(("ZDOTDIR".into(), d.clone()));
                if let Some(z) = user {
                    env.push(("KUBEDOG_ZDOT".into(), z));
                }
                vec!["-il".into()]
            }
            Flavour::Bash => {
                write("init.sh", &format!("if [ -f ~/.bash_profile ]; then . ~/.bash_profile; elif [ -f ~/.bashrc ]; then . ~/.bashrc; fi\n{set}{TELL_IF}{INIT_SH}{BASH_MORE}"))?;
                vec!["--rcfile".into(), format!("{d}/init.sh"), "-i".into()]
            }
            Flavour::Fish => {
                write("init.fish", &format!("set -gx KUBECONFIG {}\nset -gx KUBEDOG_SHELL {}\nset -gx KUBEDOG_REST {}\n{INIT_FISH}", sh_quote(&front), sh_quote(&d), sh_quote(f.rest)))?;
                vec!["-il".into(), "-C".into(), format!("source {}", sh_quote(&format!("{d}/init.fish")))]
            }
            Flavour::Power => {
                write("init.ps1", INIT_POWER)?;
                vec!["-NoLogo".into(), "-NoExit".into(), "-ExecutionPolicy".into(), "Bypass".into(), "-File".into(), format!("{d}{}init.ps1", std::path::MAIN_SEPARATOR)]
            }
            Flavour::Sh => {
                write("init.sh", &format!("{set}{INIT_PLAIN}"))?;
                env.push(("ENV".into(), format!("{d}/init.sh")));
                vec!["-i".into()]
            }
        };
        Ok(Start { program: program.into(), args, env, dir: dir.clone() })
    })();
    if r.is_err() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    r
}

/// What a shell said it's on: (cluster, namespace).
fn read_now(t: &str) -> Option<(String, String)> {
    let mut l = t.lines();
    let c = l.next()?.trim().trim_start_matches('\u{feff}').to_string();
    (!c.is_empty()).then(|| (c, l.next().unwrap_or("").trim().to_string()))
}

impl KubedogApp {
    /// The shells there are to choose from: (what's kept in the settings, what it's called). More than one only on
    /// Windows with WSL.
    pub(super) fn shell_kinds(&mut self) -> Vec<(String, String)> {
        let shot = self.screenshot.is_some();
        let l = self.shells.linuxes.get_or_insert_with(|| match std::env::var("KUBEDOG_SHOT_WSL") {
            Ok(v) if shot => v.split(',').map(String::from).collect(),
            _ => find_linuxes(),
        });
        let own = if cfg!(windows) || !l.is_empty() { "PowerShell" } else { "Your shell" };
        std::iter::once((String::new(), own.to_string())).chain(l.iter().map(|n| (format!("wsl:{n}"), format!("{n} (WSL)")))).collect()
    }

    /// The one Settings says, if it's there.
    pub(super) fn shell_kind(&mut self) -> String {
        let kinds = self.shell_kinds();
        kinds.into_iter().map(|k| k.0).find(|k| *k == self.prefs.shell).unwrap_or_default()
    }

    /// What the shell that's shown says: looked at once a second.
    fn shell_seen(&mut self) -> Option<(String, Seen)> {
        let (c, dir) = self.shells.dock.current()?;
        let Some(dir) = dir else { return Some((c, Seen { kind: "zsh".into(), ..Default::default() })) };
        if self.shells.seen.as_ref().is_none_or(|s| s.0 != dir || s.1.elapsed() > Duration::from_millis(900)) {
            self.shells.seen = Some((dir.clone(), Instant::now(), look(&dir)));
        }
        self.shells.seen.as_ref().map(|s| (c, s.2.clone()))
    }

    fn open_shell_room(&mut self, ctx: &str, kind: &str) {
        if self.screenshot.is_some() || self.power_off("shell") {
            return;
        }
        if self.demo {
            return self.toast("Demo data: shells are turned off.".into(), true);
        }
        let contexts = self.contexts.clone();
        let argo: HashMap<String, String> = self.active.iter().filter_map(|c| self.refs(c, Kind::Deployments, "").unwrap_or_default().into_iter().find(|d| d["metadata"]["labels"]["app.kubernetes.io/part-of"] == "argocd" || d["metadata"]["name"] == "argocd-server").map(|d| (c.clone(), d["metadata"]["namespace"].as_str().unwrap_or("argocd").to_string()))).collect();
        let ns = self.ns_filter.clone();
        let rest = match &self.kubectl.wsl {
            // The whole app goes through a Linux: its shells use that Linux's own kubeconfig.
            Some(w) => w.kubeconfig.join(&kube::LIST_SEP.to_string()),
            None => self.kubectl.kubeconfig.clone().unwrap_or_else(|| kube::home().map(|h| h.join(".kube/config").to_string_lossy().to_string()).unwrap_or_default()),
        };
        let kubectl = self.kubectl.bin.clone();
        let shell = own_shell();
        sweep();
        let f = For { contexts: &contexts, ctx, ns: ns.as_deref(), argo: &|c| argo.get(c).cloned().unwrap_or("argocd".into()), rest: &rest, kubectl: kubectl.as_deref() };
        let linux = kind.strip_prefix("wsl:");
        let s = match linux {
            Some(l) => prepare_wsl(l, &f),
            None => prepare(&shell, &f),
        };
        let s = match s {
            Ok(s) => s,
            Err(e) => return self.toast(e, true),
        };
        let egui_ctx = self.egui_ctx.clone();
        let label = match linux {
            Some(l) => format!("{} ({l})", ctx_label(ctx)),
            None => ctx_label(ctx),
        };
        let used: Vec<String> = self.shells.dock.tabs().0.into_iter().map(|t| t.0).collect();
        let title = (1..).map(|n| if n == 1 { label.clone() } else { format!("{label} {n}") }).find(|t| !used.contains(t)).unwrap_or(label);
        let dir = s.dir.clone();
        // Told before it starts, so its first question is right.
        self.shells.told.clear();
        match self.shells.dock.spawn_for(title, &s.program, &s.args, &s.env, None, &egui_ctx, ctx.to_string(), Some(s.dir)) {
            Ok(()) => self.shells.closed = false,
            Err(e) => {
                let _ = std::fs::remove_dir_all(dir);
                self.toast(format!("The shell couldn't be started: {e}"), true);
            }
        }
        self.tell_shells();
    }

    /// Which clusters may be changed without a question: those that are unlocked in Kubedog.
    fn tell_shells(&mut self) {
        let mut l: Vec<String> = self.unlocked.iter().filter(|c| !c.contains('\n')).cloned().collect();
        l.sort();
        let dirs = self.shells.dock.dirs();
        let t = l.join("\n") + "\n";
        let key = format!("{t}|{}", dirs.len());
        if self.shells.told == key {
            return;
        }
        self.shells.told = key;
        for d in dirs {
            // In one go, so a shell never reads half of it.
            let tmp = d.join("unlocked.new");
            if std::fs::write(&tmp, &t).is_ok() {
                let _ = std::fs::rename(&tmp, d.join("unlocked"));
            }
        }
    }

    /// The keyboard is the shell's.
    pub(super) fn shell_typing(&self) -> bool {
        self.view == View::Shells && self.selected.is_none() && self.shells.dock.focused && self.shells.dock.has_sessions() && self.dialog.is_none() && self.palette.is_none()
    }

    pub(super) fn shells_view(&mut self, ui: &mut Ui) {
        if self.power_off("shell") {
            self.header(ui, false, None, false);
            said(ui, "The Shell is switched off in Settings > Superpowers.", TEXT_SUBTLE());
            return;
        }
        if self.shells.size == 0.0 {
            self.shells.size = 13.0;
        }
        // For pictures: no shell is started.
        if self.screenshot.is_some() && !self.shells.dock.has_sessions() && std::env::var("KUBEDOG_SHOT_SHELL").is_ok() {
            let c = self.active.first().cloned().unwrap_or_default();
            self.shells.dock.picture("made-up", &c, "\x1b[1;32m~\x1b[0m \x1b[36mmade-up\x1b[0m:\x1b[33mshop\x1b[0m ❯ kubectl get pods\nNAME                     READY   STATUS    RESTARTS   AGE\nweb-5c9d8b7f6-mm2kd      1/1     \x1b[32mRunning\x1b[0m   0          3d\napi-7d9f84c5d-x2x7q      1/1     \x1b[32mRunning\x1b[0m   2          9d\nworker-66447f8df-wcbsg   0/1     \x1b[31mError\x1b[0m     14         2h\n\x1b[1;32m~\x1b[0m \x1b[36mmade-up\x1b[0m:\x1b[33mshop\x1b[0m ❯ kubectl delete pod worker-66447f8df-wcbsg\n\x1b[33mmade-up\x1b[0m is protected in Kubedog, and this changes something:\n  kubectl delete pod worker-66447f8df-wcbsg\nGo on? [y/N] \nNot done.\n\x1b[1;32m~\x1b[0m \x1b[36mmade-up\x1b[0m:\x1b[33mshop\x1b[0m ❯ ");
        }
        if !self.shells.dock.has_sessions() && !self.shells.closed && self.active.len() == 1 && self.screenshot.is_none() && !self.demo {
            // Only once: a shell that can't start isn't tried over and over.
            self.shells.closed = true;
            let (c, k) = (self.active[0].clone(), self.shell_kind());
            if k.is_empty() && !self.prefs.shell.is_empty() {
                self.toast(format!("{} isn't on this computer anymore: this is the usual shell.", self.prefs.shell.trim_start_matches("wsl:")), true);
            }
            self.open_shell_room(&c, &k);
        }
        self.tell_shells();
        self.shell_keys(ui);
        ui.add_space(2.0);
        self.shell_bar(ui);
        ui.add_space(6.0);
        if !self.shells.dock.has_sessions() {
            self.shell_start(ui);
            return;
        }
        if !self.shells.hide_tools {
            egui::Panel::right("shell-tools").resizable(true).default_size(u(300.0)).size_range(200.0..=520.0).frame(Frame::new().fill(BG_DEFAULT()).inner_margin(Margin { left: 12, right: 0, top: 0, bottom: 0 })).show(ui, |ui| self.shell_tools(ui));
        }
        let size = self.shells.size;
        egui::CentralPanel::default().frame(Frame::new().inner_margin(Margin { left: 0, right: 0, top: 0, bottom: 8 })).show(ui, |ui| self.shells.dock.screen(ui, size));
        // What it's on can change without anything being drawn.
        ui.ctx().request_repaint_after(Duration::from_secs(1));
    }

    /// ⌘T, ⌘1-9 and ⌘K, where ⌘ isn't a key the shell gets.
    fn shell_keys(&mut self, ui: &Ui) {
        if !cfg!(target_os = "macos") || !self.shell_typing() {
            return;
        }
        let (t, k, n) = ui.input_mut(|i| {
            let mut key = |k| i.consume_key(egui::Modifiers::COMMAND, k);
            let digits = [Key::Num1, Key::Num2, Key::Num3, Key::Num4, Key::Num5, Key::Num6, Key::Num7, Key::Num8, Key::Num9];
            (key(Key::T), key(Key::K), digits.into_iter().position(&mut key))
        });
        if t {
            if let Some((c, _)) = self.shells.dock.current() {
                let kind = self.shell_kind();
                self.open_shell_room(&c, &kind);
            }
        }
        if k {
            self.open_search();
        }
        if let Some(n) = n {
            self.shells.dock.show_tab(n);
        }
    }

    fn shell_bar(&mut self, ui: &mut Ui) {
        let kinds = self.shell_kinds();
        let usual = self.shell_kind();
        let mut open: Option<(String, String)> = None;
        let mut close: Option<usize> = None;
        let mut show: Option<usize> = None;
        let mut lock: Option<String> = None;
        ui.horizontal(|ui| {
            let (tabs, at) = self.shells.dock.tabs();
            for (i, (t, alive)) in tabs.iter().enumerate() {
                let on = i == at;
                let r = ui.add(egui::Button::new(RichText::new(format!("{}{}", truncate(t, 28), if *alive { "" } else { " (ended)" })).size(z(13.0)).color(if on { TEXT_DEFAULT() } else { TEXT_SUBTLE() })).fill(if on { BG_MUTED() } else { Color32::TRANSPARENT }).stroke(Stroke::NONE).corner_radius(CornerRadius::same(6)));
                if r.clicked() {
                    show = Some(i);
                }
                if ui.add(egui::Button::new(RichText::new("×").size(z(14.0)).color(TEXT_PLACEHOLDER())).frame(false)).on_hover_text("Close this shell").clicked() {
                    close = Some(i);
                }
                ui.add_space(4.0);
            }
            if self.active.len() == 1 && kinds.len() == 1 {
                if button(ui, "+", false, false) {
                    open = self.active.first().map(|c| (c.clone(), usual.clone()));
                }
            } else {
                let l = self.active.clone();
                ui.menu_button("+", |ui| {
                    for c in l {
                        for (k, name) in &kinds {
                            let t = if kinds.len() > 1 { format!("{} · {name}", ctx_label(&c)) } else { ctx_label(&c) };
                            if ui.button(t).clicked() {
                                open = Some((c.clone(), k.clone()));
                                ui.close();
                            }
                        }
                    }
                });
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if columns::top_icon(ui, false, columns::draw_gear).on_hover_text("Settings (⌘,)").clicked() {
                    self.set_view(View::Settings);
                }
                if chip_button(ui, "Tools", !self.shells.hide_tools) {
                    self.shells.hide_tools = !self.shells.hide_tools;
                }
                if button(ui, "A+", false, false) {
                    self.shells.size = (self.shells.size + 1.0).min(24.0);
                }
                if button(ui, "A−", false, false) {
                    self.shells.size = (self.shells.size - 1.0).max(8.0);
                }
                if let Some((c, seen)) = self.shell_seen() {
                    let (c, ns) = seen.now.unwrap_or((c, String::new()));
                    let open = self.unlocked.contains(&c);
                    if seen.kind.is_empty() {
                        ui.label(RichText::new("starting…").size(z(12.0)).color(TEXT_SUBTLE()));
                    } else if asks(&seen.kind) {
                        let r = ui.add(egui::Button::new(RichText::new(if open { "🔓 changes allowed" } else { "🔒 asks before changes" }).size(z(12.5)).color(if open { WARNING() } else { TEXT_MUTED() })).fill(BG_MUTED()).stroke(Stroke::NONE).corner_radius(CornerRadius::same(6)));
                        if r.on_hover_text("The same lock as everywhere in Kubedog. In the shell it's a reminder for the tools Kubedog knows (kubectl, oc, helm, argocd, flux...): scripts, k9s and other programs don't ask.").clicked() {
                            lock = Some(c.clone());
                        }
                    } else {
                        ui.label(RichText::new("this kind of shell doesn't ask before changes").size(z(12.0)).color(WARNING()));
                    }
                    ui.add_space(6.0);
                    ui.label(RichText::new(if ns.is_empty() { ctx_label(&c) } else { format!("{} · {ns}", ctx_label(&c)) }).size(z(13.0)).color(TEXT_MUTED()));
                    let (d, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), Sense::hover());
                    ui.painter().circle_filled(d.center(), 3.5, context_color(&c));
                }
            });
        });
        if let Some(i) = show {
            self.shells.dock.show_tab(i);
        }
        if let Some(i) = close {
            self.shells.dock.close_tab(i);
            self.shells.closed = !self.shells.dock.has_sessions();
        }
        if let Some((c, k)) = open {
            self.open_shell_room(&c, &k);
        }
        if let Some(c) = lock {
            if !self.unlocked.remove(&c) {
                self.unlocked.insert(c);
            }
            self.shells.dock.focused = true;
        }
    }

    /// Nothing open yet.
    fn shell_start(&mut self, ui: &mut Ui) {
        let mut open = None;
        ui.add_space(30.0);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new("A shell for a cluster").size(z(19.0)).color(TEXT_DEFAULT()));
            ui.label(RichText::new("kubectl, helm, argocd and the others all use that cluster, and your own kubeconfig stays as it is").size(z(13.0)).color(TEXT_SUBTLE()));
            ui.add_space(14.0);
            let kinds = self.shell_kinds();
            if kinds.len() > 1 {
                let was = self.shell_kind();
                let mut now = was.clone();
                let name = |k: &str| kinds.iter().find(|x| x.0 == k).map(|x| x.1.clone()).unwrap_or_default();
                egui::ComboBox::from_id_salt("shell-kind").selected_text(name(&was)).width(u(220.0)).show_ui(ui, |ui| {
                    for (k, n) in &kinds {
                        ui.selectable_value(&mut now, k.clone(), n);
                    }
                });
                if now != was {
                    self.prefs.shell = now;
                    self.save();
                }
                ui.add_space(10.0);
            }
            for c in self.active.clone() {
                if button(ui, &format!("Open a shell on {}", ctx_label(&c)), true, false) {
                    open = Some(c);
                }
                ui.add_space(6.0);
            }
        });
        if let Some(c) = open {
            let k = self.shell_kind();
            self.open_shell_room(&c, &k);
        }
    }

    /// Ready commands for the tools this computer has. A click types one; it isn't run.
    fn shell_tools(&mut self, ui: &mut Ui) {
        let found = self.shells.found.get_or_insert_with(|| TOOLS.iter().map(|t| kube::find_program(t.program).is_some()).collect()).clone();
        // In WSL they're that Linux's; all of them until it has looked.
        let there = self.shell_seen().map(|s| s.1).filter(|s| s.linux);
        let found = match &there {
            Some(s) => s.tools.clone().unwrap_or(vec![true; TOOLS.len()]),
            None => found,
        };
        let mut type_it: Option<&'static str> = None;
        let w = ui.available_width();
        filter_box(ui, &mut self.shells.find, "Find a command", w);
        ui.label(RichText::new("A click types it; you press Enter.").size(z(11.5)).color(TEXT_PLACEHOLDER()));
        ui.add_space(4.0);
        let q = self.shells.find.to_lowercase();
        egui::ScrollArea::vertical().id_salt("shell-tools").auto_shrink([false, false]).show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 1.0;
            for (t, _) in TOOLS.iter().zip(&found).filter(|x| *x.1) {
                let l: Vec<_> = t.ready.iter().filter(|r| q.is_empty() || t.label.to_lowercase().contains(&q) || r.0.contains(&q) || r.1.to_lowercase().contains(&q)).collect();
                if l.is_empty() {
                    continue;
                }
                ui.add_space(8.0);
                ui.label(RichText::new(t.label).size(z(13.0)).strong().color(TEXT_DEFAULT()));
                for (cmd, what, changes) in l {
                    let (r, resp) = dash::line(ui, u(36.0), true);
                    let y = r.top() + u(11.0);
                    let cw = ui.painter().layout_no_wrap("M".into(), FontId::monospace(z(12.0)), PRIMARY_TEXT()).size().x.max(1.0);
                    let n = (((r.width() - 22.0) / cw) as usize).max(8);
                    let g = ui.painter().layout_no_wrap(truncate(cmd.trim_end(), n), FontId::monospace(z(12.0)), PRIMARY_TEXT());
                    let h = g.size().y / 2.0;
                    ui.painter().galley(egui::pos2(r.left(), y - h), g, PRIMARY_TEXT());
                    pg::label_at(ui, ui.painter(), egui::pos2(r.left(), r.top() + u(26.0)), what, 11.5, TEXT_SUBTLE(), r.width() - 18.0);
                    if *changes {
                        ui.painter().circle_filled(egui::pos2(r.right() - 8.0, r.center().y), u(3.5), WARNING());
                    }
                    if resp.on_hover_text(format!("{}\n{what}{}", cmd.trim_end(), if *changes { "\nchanges something" } else { "" })).clicked() {
                        type_it = Some(cmd);
                    }
                }
            }
            let gone: Vec<&str> = TOOLS.iter().zip(&found).filter(|x| !*x.1).map(|x| x.0.program).collect();
            if !gone.is_empty() && q.is_empty() {
                ui.add_space(12.0);
                let (place, more) = if there.is_some() { ("in this Linux", " Kubedog doesn't install them: install the ones you need there.") } else { ("on this computer", "") };
                said(ui, &format!("Not {place}: {}.{more}", gone.join(", ")), TEXT_PLACEHOLDER());
            }
            ui.add_space(12.0);
        });
        if let Some(t) = type_it {
            self.shells.dock.type_text(t);
        }
    }

    /// Settings > Terminal: which shell the Shell opens, where there's a choice.
    pub(super) fn settings_shell(&mut self, ui: &mut Ui) {
        let kinds = self.shell_kinds();
        if kinds.len() < 2 {
            return;
        }
        ui.add_space(16.0);
        let mut now = self.shell_kind();
        let was = now.clone();
        let mut whole = self.prefs.wsl_app;
        card(ui, |ui| {
            ui.label(RichText::new("Shell (superpower)").size(z(15.0)).strong().color(TEXT_DEFAULT()));
            ui.add_space(4.0);
            for (k, n) in &kinds {
                ui.radio_value(&mut now, k.clone(), n);
            }
            ui.add_space(4.0);
            settings::hint(ui, "With WSL, the tools are the ones installed in that Linux: Kubedog doesn't install them, so kubectl has to be there, and helm, argocd and the others if you want them. It uses the clusters you opened in Kubedog. A cluster that signs in with a Windows program, or whose certificate is a file given by its Windows path, can't be reached from there.");
            if let Some(linux) = now.strip_prefix("wsl:") {
                ui.add_space(8.0);
                ui.checkbox(&mut whole, format!("Use {linux} for the whole app, not only for the Shell"));
                settings::hint(ui, "Kubedog then runs kubectl and helm in that Linux and lists the clusters of its kubeconfig (~/.kube/config there, or what KUBECONFIG says in its shell): logins made there work here. The kubeconfig files added in Kubedog aren't used meanwhile, and the clusters that are open are closed when this changes. A file on Windows can't be handed to kubectl there, and a port forward is reached the way WSL lets localhost through.");
                if let Some(w) = &self.kubectl.wsl {
                    said(ui, &format!("In use: {} in {}.", w.kubectl, w.linux), SUCCESS());
                }
            }
        });
        if now != was || whole != self.prefs.wsl_app {
            self.prefs.shell = now;
            self.prefs.wsl_app = whole;
            self.save();
            if self.wsl_app_linux().is_some() || self.kubectl.wsl.is_some() {
                self.wsl_app_start();
            }
        }
    }

    /// The Linux the whole app goes through, when that's asked for (Windows only).
    fn wsl_app_linux(&self) -> Option<String> {
        self.prefs.shell.strip_prefix("wsl:").filter(|_| cfg!(windows) && self.prefs.wsl_app && self.screenshot.is_none()).map(String::from)
    }

    /// Follows the setting: asks the Linux where its things are (in a thread), or goes back to this computer's own.
    pub(super) fn wsl_app_start(&mut self) {
        match self.wsl_app_linux() {
            Some(linux) => {
                if self.kubectl.wsl.as_ref().is_some_and(|w| w.linux == linux) {
                    return;
                }
                self.spawn(move |_| Msg::Text { key: "wslapp".into(), result: kube::Wsl::ask(&linux).map(|w| w.json().to_string()) });
            }
            None if self.kubectl.wsl.is_some() => {
                if self.connected {
                    self.disconnect();
                }
                let found = Kubectl::detect();
                self.kubectl = Kubectl { kubeconfig: self.kubectl.kubeconfig.clone(), ..found };
                self.apply_kubeconfigs();
                self.load_contexts();
            }
            None => {}
        }
    }

    /// The Linux answered (or didn't).
    pub(super) fn on_wsl_app(&mut self, result: &Result<String, String>) {
        let got = result.clone().and_then(|t| serde_json::from_str::<Value>(&t).ok().and_then(|v| kube::Wsl::from_json(&v)).ok_or("The Linux's answer couldn't be read.".to_string()));
        match got {
            // Not asked for anymore in the meantime.
            Ok(w) if self.wsl_app_linux().as_deref() != Some(w.linux.as_str()) => {}
            Ok(w) => {
                if self.connected {
                    self.disconnect();
                }
                if self.demo {
                    self.leave_demo();
                }
                self.toast(format!("Kubedog works through {} now: its kubectl and its kubeconfig.", w.linux), false);
                self.kubectl.bin = Some(kube::system32("wsl.exe"));
                self.kubectl.helm = (!w.helm.is_empty()).then(|| PathBuf::from(&w.helm));
                self.kubectl.cnpg = (!w.cnpg.is_empty()).then(|| PathBuf::from(&w.cnpg));
                self.kubectl.wsl = Some(w);
                self.load_contexts();
            }
            Err(e) => {
                self.toast(format!("{e} Kubedog keeps using this computer's own kubectl."), true);
            }
        }
    }

    pub(super) fn close_shells(&mut self) {
        self.shells.dock.close_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(name: &str, ns: &str) -> ContextInfo {
        ContextInfo { name: name.into(), cluster: format!("{name}-cluster"), user: format!("{name}-user"), namespace: ns.into(), server: String::new(), source: String::new() }
    }

    #[test]
    fn the_file_in_front() {
        let l = [ctx("one", "shop"), ctx("two: \"x\"", "")];
        let v = front_config(&l, "one", &|c| c.namespace.clone());
        assert_eq!(v["current-context"], "one");
        assert_eq!(v["contexts"][0]["context"]["namespace"], "shop");
        assert!(v["contexts"][1]["context"]["namespace"].is_null());
        // It only refers: no addresses, no logins.
        assert!(v["clusters"].as_array().unwrap().is_empty() && v["users"].as_array().unwrap().is_empty());
        assert_eq!(read_now("one\nshop\n"), Some(("one".into(), "shop".into())));
        assert_eq!(read_now("one\n"), Some(("one".into(), String::new())));
        assert_eq!(read_now("\n"), None);
    }

    #[test]
    fn shells_that_are_known() {
        for (p, f) in [("/bin/zsh", Flavour::Zsh), ("/opt/homebrew/bin/bash", Flavour::Bash), ("/usr/bin/fish", Flavour::Fish), ("C:\\x\\pwsh.exe", Flavour::Power), ("powershell.exe", Flavour::Power), ("/bin/dash", Flavour::Sh)] {
            assert_eq!(flavour(p), f);
        }
        assert!(TOOLS.iter().all(|t| t.ready.iter().all(|r| !r.0.contains('\n'))));
    }

    #[cfg(unix)]
    fn files(home: &Path) -> String {
        // The person's own files: two clusters that don't exist.
        let k = home.join("mine");
        std::fs::write(&k, r#"{"apiVersion":"v1","kind":"Config","current-context":"two","clusters":[{"name":"one-cluster","cluster":{"server":"https://127.0.0.1:1"}},{"name":"two-cluster","cluster":{"server":"https://127.0.0.1:2"}}],"users":[{"name":"one-user","user":{"token":"x"}},{"name":"two-user","user":{"token":"y"}}],"contexts":[{"name":"one","context":{"cluster":"one-cluster","user":"one-user"}},{"name":"two","context":{"cluster":"two-cluster","user":"two-user"}}]}"#).unwrap();
        k.to_string_lossy().to_string()
    }

    /// Stand-ins for the tools, so nothing real is ever called, and the real kubectl only for its own files.
    #[cfg(unix)]
    fn run_in(shell: &str, script: &str, unlocked: &str) -> Option<String> {
        use std::os::unix::fs::PermissionsExt;
        if !Path::new(shell).exists() {
            return None;
        }
        let home = own_dir().unwrap();
        let bin = home.join("bin");
        std::fs::create_dir(&bin).unwrap();
        for t in ["kubectl", "helm", "argocd", "oc"] {
            // kubectl config is answered from the file in front; all else only says what it was asked.
            let body = if t == "kubectl" { "#!/bin/sh\ncase \"$1 $2\" in 'config current-context') sed -n 's/.*\"current-context\":\"\\([^\"]*\\)\".*/\\1/p' \"${KUBECONFIG%%:*}\";; 'config view') echo one; echo shop;; *) echo \"RAN kubectl $*\";; esac\n".to_string() } else { format!("#!/bin/sh\necho \"RAN {t} $* KC=${{KUBECONFIG%%:*}}\"\n") };
            std::fs::write(bin.join(t), body).unwrap();
            std::fs::set_permissions(bin.join(t), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        // The person's own start-up file sets things of its own, and an alias in the way.
        std::fs::write(home.join(".zshrc"), format!("PATH={}:/usr/bin:/bin\nexport KUBECONFIG=/elsewhere\nalias kubectl='echo ALIAS'\nexport MINE=1\n", bin.display())).unwrap();
        std::fs::write(home.join(".bashrc"), "export KUBECONFIG=/elsewhere\nalias kubectl='echo ALIAS'\nexport MINE=1\n").unwrap();
        let rest = files(&home);
        let l = [ctx("one", "shop"), ctx("two", "")];
        let s = prepare(shell, &For { contexts: &l, ctx: "one", ns: Some("db"), argo: &|_| "gitops".into(), rest: &rest, kubectl: None }).unwrap();
        std::fs::write(s.dir.join("unlocked"), unlocked).unwrap();
        let mut args: Vec<String> = s.args.clone();
        args.push("-c".into());
        if flavour(shell) == Flavour::Bash {
            // An rcfile isn't read with -c: the same file by hand.
            args = vec!["-c".into(), format!(". {}/init.sh\n{script}", s.dir.display())];
        } else {
            args.push(script.into());
        }
        let mut c = std::process::Command::new(shell);
        c.args(&args).env_clear().envs(s.env.iter().map(|e| (e.0.clone(), e.1.clone()))).env("HOME", &home).env("PATH", format!("{}:/usr/bin:/bin", bin.display())).env("TERM", "dumb").stdin(std::process::Stdio::null());
        let o = c.output().unwrap();
        let t = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        let t = t.replace(&s.dir.to_string_lossy().to_string(), "DIR");
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&s.dir);
        Some(t)
    }

    #[cfg(unix)]
    #[test]
    fn set_up_for_the_cluster() {
        for shell in ["/bin/zsh", "/bin/bash"] {
            let Some(o) = run_in(shell, "echo \"MINE=$MINE\"; kubectl get pods; helm list -A; acd app list; echo \"KC=${KUBECONFIG%%:*}\"; k get nodes 2>&1 | head -1; cat \"$KUBEDOG_SHELL/now\"", "") else { continue };
            // The person's own files were read, and what they set doesn't take the cluster away.
            for want in ["MINE=1", "RAN kubectl get pods", "RAN helm list -A KC=DIR/config", "RAN argocd --core --kube-context one app list KC=DIR/argocd", "KC=DIR/config", "one\nshop"] {
                assert!(o.contains(want), "{shell}: {want}\n{o}");
            }
            assert!(!o.contains("ALIAS"), "{o}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn asks_before_changes() {
        // Without a terminal nobody can say yes: what changes something isn't run.
        let changing = ["kubectl delete pod x", "kubectl -n db apply -f x", "kubectl --context two scale --replicas=1 deploy/x", "kubectl rollout restart deployment/x", "kubectl cnpg promote x", "oc adm drain n", "helm upgrade x y", "argocd app sync x", "acd app delete x"];
        let reading = ["kubectl get pods", "kubectl rollout status deployment/x", "kubectl apply -f x --dry-run=client", "kubectl logs x", "kubectl cnpg status x", "kubectl auth can-i create pods", "helm list", "helm get values x", "argocd app get x", "acd app diff x", "oc get pods"];
        for shell in ["/bin/zsh", "/bin/bash"] {
            for c in changing {
                let Some(o) = run_in(shell, c, "") else { continue };
                assert!(!o.contains("RAN "), "{shell}: {c}\n{o}");
                // Unlocked in Kubedog: no question. (The cluster the command names counts.)
                let o = run_in(shell, c, if c.contains("two") { "two\n" } else { "one\n" }).unwrap();
                assert!(o.contains("RAN "), "{shell}: {c}\n{o}");
            }
            // Another cluster being open doesn't count.
            if let Some(o) = run_in(shell, "kubectl --context=two delete pod x", "one\n") {
                assert!(!o.contains("RAN "), "{o}");
            }
            for c in reading {
                let Some(o) = run_in(shell, c, "") else { continue };
                assert!(o.contains("RAN "), "{shell}: {c}\n{o}");
            }
        }
    }

    /// In a real terminal: it asks, and no means no.
    #[cfg(unix)]
    #[test]
    fn asks_in_a_terminal() {
        use std::os::unix::fs::PermissionsExt;
        for shell in ["/bin/zsh", "/bin/bash"] {
            if !Path::new(shell).exists() {
                continue;
            }
            let home = own_dir().unwrap();
            let bin = home.join("bin");
            std::fs::create_dir(&bin).unwrap();
            std::fs::write(bin.join("kubectl"), "#!/bin/sh\ncase \"$1 $2\" in 'config current-context') echo one;; 'config view') printf 'one\\nshop\\n';; *) echo \"RAN $*\";; esac\n").unwrap();
            std::fs::set_permissions(bin.join("kubectl"), std::fs::Permissions::from_mode(0o755)).unwrap();
            for f in [".zshrc", ".bashrc"] {
                std::fs::write(home.join(f), format!("PATH={}:/usr/bin:/bin\nPS1='$ '\n", bin.display())).unwrap();
            }
            let l = [ctx("one", "shop")];
            let s = prepare(shell, &For { contexts: &l, ctx: "one", ns: None, argo: &|_| "argocd".into(), rest: &files(&home), kubectl: None }).unwrap();
            let mut env = s.env.clone();
            env.push(("HOME".into(), home.to_string_lossy().to_string()));
            let mut d = terminal::Dock::default();
            d.spawn_for("one".into(), &s.program, &s.args, &env, None, &egui::Context::default(), "one".into(), Some(s.dir.clone())).unwrap();
            let wait = |d: &terminal::Dock, t: &str| {
                for _ in 0..150 {
                    if d.shown().contains(t) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                panic!("{shell}: no {t:?} in\n{}", d.shown());
            };
            wait(&d, "$ ");
            d.enter("kubectl delete pod x");
            wait(&d, "[y/N]");
            d.enter("n");
            wait(&d, "Not done.");
            assert!(!d.shown().contains("RAN"), "{}", d.shown());
            d.enter("kubectl delete pod x");
            std::thread::sleep(Duration::from_millis(300));
            d.enter("y");
            wait(&d, "RAN delete pod x");
            d.close_all();
            assert!(!s.dir.exists());
            let _ = std::fs::remove_dir_all(&home);
        }
    }

    #[test]
    fn linuxes_on_windows() {
        let reg = "\r\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss\r\n    DefaultDistribution    REG_SZ    {bb}\r\n    NatIpAddress    REG_SZ    192.0.2.1\r\n\r\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss\\{aa}\r\n    State    REG_DWORD    0x1\r\n    DistributionName    REG_SZ    Debian\r\n\r\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss\\{cc}\r\n    DistributionName    REG_SZ    docker-desktop\r\n\r\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss\\{bb}\r\n    DistributionName    REG_SZ    Ubuntu 24.04\r\n";
        assert_eq!(linuxes_in(reg, &[]), ["Ubuntu 24.04", "Debian"]);
        assert!(linuxes_in("ERROR: The system was unable to find the specified registry key or value.\r\n", &[]).is_empty());
        // The one that runs comes first, whatever it's called; also one the registry doesn't name.
        let wide = |t: &str| t.encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<Vec<u8>>();
        assert_eq!(running_in(&wide("Debian\r\ndocker-desktop\r\n")), ["Debian", "docker-desktop"]);
        assert_eq!(running_in(b"shop-linux\n"), ["shop-linux"]);
        assert!(running_in(&wide("There are no running distributions.\r\n")).is_empty());
        assert_eq!(linuxes_in(reg, &["Debian".into()]), ["Debian", "Ubuntu 24.04"]);
        assert_eq!(linuxes_in(reg, &["docker-desktop".into(), "shop-linux".into()]), ["docker-desktop", "shop-linux", "Ubuntu 24.04", "Debian"]);
        // Nothing on its command line needs more than a pair of quotes around it.
        let l = [ctx("one", "shop")];
        let s = prepare_wsl("Ubuntu 24.04", &For { contexts: &l, ctx: "one", ns: None, argo: &|_| "argocd".into(), rest: "", kubectl: None }).unwrap();
        assert_eq!(s.args[..3], ["-d", "Ubuntu 24.04", "--cd"]);
        assert_eq!(s.args[4..], ["--exec", "sh", "./start.sh"]);
        assert!(!s.args.iter().any(|a| a.contains(['"', '$', '\'', '%'])));
        for e in std::fs::read_dir(&s.dir).unwrap().flatten() {
            assert!(!std::fs::read(e.path()).unwrap().contains(&b'\r'), "{e:?}");
        }
        assert!(look(&s.dir).linux && look(&s.dir).kind.is_empty() && look(&s.dir).tools.is_none());
        let _ = std::fs::remove_dir_all(&s.dir);
    }

    /// The Linux side, with a stand-in for what only WSL has.
    #[cfg(unix)]
    #[test]
    fn the_linux_side() {
        use std::os::unix::fs::PermissionsExt;
        for shell in ["/bin/zsh", "/bin/bash"] {
            if !Path::new(shell).exists() {
                continue;
            }
            let home = own_dir().unwrap();
            let bin = home.join("bin");
            std::fs::create_dir(&bin).unwrap();
            for (n, t) in [
                ("kubectl", "#!/bin/sh\ncase \"$1 $2\" in 'config current-context') echo one;; 'config view') printf 'one\\nshop\\n';; *) echo \"RAN $*\";; esac\n"),
                ("helm", "#!/bin/sh\necho helm\n"),
                // Windows' path in, Linux' out; one that can't be turned is left out.
                ("wslpath", "#!/bin/sh\ncase \"$2\" in C?*) printf '/mnt/c%s\\n' \"$(printf %s \"${2#C}\" | tr '\\\\' /)\";; *) exit 1;; esac\n"),
            ] {
                std::fs::write(bin.join(n), t).unwrap();
                std::fs::set_permissions(bin.join(n), std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            for f in [".zshrc", ".bash_profile"] {
                std::fs::write(home.join(f), format!("PATH={}:/usr/bin:/bin\nPS1='$ '\nalias kubectl='echo ALIAS'\nMINE=yes\n", bin.display())).unwrap();
            }
            let l = [ctx("one", "shop")];
            let sep = kube::LIST_SEP;
            let rest = format!("C\\Users\\A B\\config{sep}D\\gone{sep}C\\two{sep}/home/dev/.kube/own one");
            let s = prepare_wsl("Any", &For { contexts: &l, ctx: "one", ns: None, argo: &|_| "argocd".into(), rest: &rest, kubectl: None }).unwrap();
            let env = [("HOME", home.to_string_lossy().to_string()), ("SHELL", shell.into()), ("PATH", format!("{}:/usr/bin:/bin", bin.display()))].map(|e| (e.0.to_string(), e.1));
            let mut d = terminal::Dock::default();
            let args = ["-c".to_string(), format!("cd {} && exec sh ./start.sh", sh_quote(&s.dir.to_string_lossy()))];
            d.spawn_for("one".into(), "/bin/sh", &args, &env, None, &egui::Context::default(), "one".into(), Some(s.dir.clone())).unwrap();
            let wait = |d: &terminal::Dock, t: &str| {
                for _ in 0..150 {
                    if d.shown().replace('\n', "").contains(t) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                panic!("{shell}: no {t:?} in\n{}", d.shown());
            };
            wait(&d, "$ ");
            d.enter("echo \"<${KUBECONFIG#*/config:}> $MINE\"");
            wait(&d, "</mnt/c/Users/A B/config:/mnt/c/two:/home/dev/.kube/own one> yes");
            d.enter("kubectl delete pod x");
            wait(&d, "[y/N]");
            d.enter("n");
            wait(&d, "Not done.");
            assert!(!d.shown().contains("RAN") && !d.shown().contains("ALIAS"), "{}", d.shown());
            for _ in 0..50 {
                if look(&s.dir).tools.is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let seen = look(&s.dir);
            assert_eq!(seen.now, Some(("one".into(), "shop".into())));
            assert!(asks(&seen.kind), "{}", seen.kind);
            let has = |p: &str| seen.tools.as_ref().unwrap()[TOOLS.iter().position(|t| t.program == p).unwrap()];
            assert!(has("kubectl") && has("helm") && !has("argocd") && !has("velero"));
            d.close_all();
            let _ = std::fs::remove_dir_all(&home);
        }
    }

    /// The real kubectl, with files that lead nowhere: switching stays in the shell's own file.
    #[cfg(unix)]
    #[test]
    fn own_files_stay() {
        let Some(kubectl) = kube::find_program("kubectl") else { return };
        let home = own_dir().unwrap();
        let rest = files(&home);
        let before = std::fs::read(&rest).unwrap();
        let l = [ctx("one", "shop"), ctx("two", "")];
        let s = prepare("/bin/zsh", &For { contexts: &l, ctx: "one", ns: None, argo: &|_| "argocd".into(), rest: &rest, kubectl: None }).unwrap();
        let kc = s.env.iter().find(|e| e.0 == "KUBECONFIG").unwrap().1.clone();
        let run = |a: &[&str]| String::from_utf8_lossy(&std::process::Command::new(&kubectl).args(a).env("KUBECONFIG", &kc).env("HOME", &home).output().unwrap().stdout).trim().to_string();
        let now = || run(&["config", "view", "--minify", "-o", "jsonpath={.current-context}/{..namespace}/{.clusters[0].cluster.server}"]);
        assert_eq!(now(), "one/shop/https://127.0.0.1:1");
        run(&["config", "set-context", "--current", "--namespace=db"]);
        assert_eq!(now(), "one/db/https://127.0.0.1:1");
        run(&["config", "use-context", "two"]);
        run(&["config", "set-context", "--current", "--namespace=tools"]);
        assert_eq!(now(), "two/tools/https://127.0.0.1:2");
        assert_eq!(std::fs::read(&rest).unwrap(), before);
        // Nobody else can look in.
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&s.dir).unwrap().permissions().mode() & 0o777, 0o700);
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&s.dir);
    }
}
