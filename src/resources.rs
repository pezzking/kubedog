//! Resource kinds shown in the sidebar and how each one's table is built
//! from the JSON kubectl returns.

use crate::kube::{age, age_secs};
use serde_json::Value;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Kind {
    Pods,
    Deployments,
    StatefulSets,
    DaemonSets,
    ReplicaSets,
    Jobs,
    CronJobs,
    Services,
    Ingresses,
    EndpointSlices,
    NetworkPolicies,
    ConfigMaps,
    Secrets,
    HorizontalPodAutoscalers,
    PersistentVolumeClaims,
    PersistentVolumes,
    StorageClasses,
    Nodes,
    Namespaces,
    Events,
    ServiceAccounts,
    Roles,
    RoleBindings,
    ClusterRoles,
    ClusterRoleBindings,
    CustomResourceDefinitions,
    Leases,
    IngressClasses,
    LimitRanges,
    ResourceQuotas,
    PodDisruptionBudgets,
    VolumeAttachments,
    CSINodes,
    CSIDrivers,
    PriorityClasses,
    RuntimeClasses,
    MutatingWebhooks,
    ValidatingWebhooks,
    CertificateSigningRequests,
}

use Kind::*;

/// Sidebar groups, in order. Helm sits between
/// Cluster and Workloads and is drawn by the sidebar itself.
pub const GROUPS: &[(&str, &[Kind])] = &[
    ("Cluster", &[Nodes, Events, Namespaces, Leases]),
    (
        "Workloads",
        &[Deployments, Pods, ReplicaSets, DaemonSets, StatefulSets, Jobs, CronJobs],
    ),
    (
        "Configuration",
        &[Secrets, ConfigMaps, HorizontalPodAutoscalers, LimitRanges, ResourceQuotas, PodDisruptionBudgets],
    ),
    ("Networking", &[Services, Ingresses, EndpointSlices, NetworkPolicies, IngressClasses]),
    (
        "Storage",
        &[PersistentVolumes, PersistentVolumeClaims, VolumeAttachments, CSINodes, CSIDrivers, StorageClasses],
    ),
    (
        "Access Control",
        &[ServiceAccounts, Roles, RoleBindings, ClusterRoles, ClusterRoleBindings, CertificateSigningRequests],
    ),
    ("Administration", &[CustomResourceDefinitions, PriorityClasses, RuntimeClasses, MutatingWebhooks, ValidatingWebhooks]),
];

/// A table cell: what is shown, plus a key for sorting.
#[derive(Clone, Debug)]
pub struct Cell {
    pub text: String,
    pub sort: SortKey,
    pub tone: Tone,
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub enum SortKey {
    Num(f64),
    Text(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Normal,
    Muted,
    Success,
    /// Only just begun: a brighter green.
    Fresh,
    Warning,
    Danger,
    Info,
    Link,
}

fn t(s: impl Into<String>) -> Cell {
    let s = s.into();
    Cell {
        sort: SortKey::Text(s.to_lowercase()),
        text: s,
        tone: Tone::Normal,
    }
}
fn n(v: i64) -> Cell {
    Cell {
        text: v.to_string(),
        sort: SortKey::Num(v as f64),
        tone: Tone::Normal,
    }
}
fn toned(mut c: Cell, tone: Tone) -> Cell {
    c.tone = tone;
    c
}
/// The Ready column: green when everything that should be ready is, red when something isn't,
/// grey when nothing is meant to run (scaled to zero, or a finished pod).
pub fn ready_tone(ready: i64, wanted: i64) -> Tone {
    if wanted <= 0 {
        Tone::Muted
    } else if ready >= wanted {
        Tone::Success
    } else {
        Tone::Danger
    }
}

fn usage() -> Cell {
    Cell { text: String::new(), sort: SortKey::Num(0.0), tone: Tone::Normal }
}

fn age_cell(ts: &Value) -> Cell {
    let s = ts.as_str().unwrap_or("");
    Cell {
        text: age(s),
        sort: SortKey::Num(age_secs(s) as f64),
        tone: Tone::Normal,
    }
}
/// A pod's age: bright green while it's written in seconds, green in minutes, plain once it's written in hours.
fn pod_age_cell(ts: &Value) -> Cell {
    let mut c = age_cell(ts);
    c.tone = young(ts.as_str().and_then(crate::kube::parse_time).map(|t| crate::kube::now_secs() - t));
    c
}

/// The tone for an age in seconds; not known (or a clock that's off) is plain.
pub fn young(secs: Option<i64>) -> Tone {
    match secs {
        // As the age is written: in seconds up to two minutes, in minutes up to three hours.
        Some(0..=119) => Tone::Fresh,
        Some(120..=10_799) => Tone::Success,
        _ => Tone::Normal,
    }
}

fn s(v: &Value) -> String {
    match v {
        Value::String(x) => x.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}
fn i(v: &Value) -> i64 {
    v.as_i64().unwrap_or(0)
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Pods => "Pods",
            Deployments => "Deployments",
            StatefulSets => "StatefulSets",
            DaemonSets => "DaemonSets",
            ReplicaSets => "ReplicaSets",
            Jobs => "Jobs",
            CronJobs => "CronJobs",
            Services => "Services",
            Ingresses => "Ingresses",
            EndpointSlices => "Endpoint Slices",
            NetworkPolicies => "Network Policies",
            ConfigMaps => "ConfigMaps",
            Secrets => "Secrets",
            HorizontalPodAutoscalers => "HPA",
            PersistentVolumeClaims => "Persistent Volume Claims",
            PersistentVolumes => "Persistent Volume",
            StorageClasses => "Storage Classes",
            Nodes => "Nodes",
            Namespaces => "Namespaces",
            Events => "Events",
            ServiceAccounts => "Service Accounts",
            Roles => "Roles",
            RoleBindings => "Role Bindings",
            ClusterRoles => "Cluster Roles",
            ClusterRoleBindings => "Cluster Role Bindings",
            CustomResourceDefinitions => "CRDs",
            Leases => "Lease",
            PriorityClasses => "Priority Classes",
            RuntimeClasses => "Runtime Classes",
            MutatingWebhooks => "Mutating Webhooks",
            ValidatingWebhooks => "Validating Webhooks",
            CertificateSigningRequests => "Certificate Requests",
            IngressClasses => "Ingress Classes",
            LimitRanges => "Limit Ranges",
            ResourceQuotas => "Resource Quotas",
            PodDisruptionBudgets => "Pod Disruption Budgets",
            VolumeAttachments => "Volume Attachments",
            CSINodes => "CSI Nodes",
            CSIDrivers => "CSI Drivers",
        }
    }

    /// Singular, for buttons and dialogs.
    pub fn singular(self) -> &'static str {
        match self {
            Pods => "pod",
            Deployments => "deployment",
            StatefulSets => "stateful set",
            DaemonSets => "daemon set",
            ReplicaSets => "replica set",
            Jobs => "job",
            CronJobs => "cron job",
            Services => "service",
            Ingresses => "ingress",
            EndpointSlices => "endpoint slice",
            NetworkPolicies => "network policy",
            ConfigMaps => "config map",
            Secrets => "secret",
            HorizontalPodAutoscalers => "autoscaler",
            PersistentVolumeClaims => "volume claim",
            PersistentVolumes => "volume",
            StorageClasses => "storage class",
            Nodes => "node",
            Namespaces => "namespace",
            Events => "event",
            ServiceAccounts => "service account",
            Roles => "role",
            RoleBindings => "role binding",
            ClusterRoles => "cluster role",
            ClusterRoleBindings => "cluster role binding",
            CustomResourceDefinitions => "definition",
            Leases => "lease",
            PriorityClasses => "priority class",
            RuntimeClasses => "runtime class",
            MutatingWebhooks => "mutating webhook configuration",
            ValidatingWebhooks => "validating webhook configuration",
            CertificateSigningRequests => "certificate signing request",
            IngressClasses => "ingress class",
            LimitRanges => "limit range",
            ResourceQuotas => "resource quota",
            PodDisruptionBudgets => "pod disruption budget",
            VolumeAttachments => "volume attachment",
            CSINodes => "CSI node",
            CSIDrivers => "CSI driver",
        }
    }

    /// The resource name kubectl understands.
    pub fn resource(self) -> &'static str {
        match self {
            Pods => "pods",
            Deployments => "deployments.apps",
            StatefulSets => "statefulsets.apps",
            DaemonSets => "daemonsets.apps",
            ReplicaSets => "replicasets.apps",
            Jobs => "jobs.batch",
            CronJobs => "cronjobs.batch",
            Services => "services",
            Ingresses => "ingresses.networking.k8s.io",
            EndpointSlices => "endpointslices.discovery.k8s.io",
            NetworkPolicies => "networkpolicies.networking.k8s.io",
            ConfigMaps => "configmaps",
            Secrets => "secrets",
            HorizontalPodAutoscalers => "horizontalpodautoscalers.autoscaling",
            PersistentVolumeClaims => "persistentvolumeclaims",
            PersistentVolumes => "persistentvolumes",
            StorageClasses => "storageclasses.storage.k8s.io",
            Nodes => "nodes",
            Namespaces => "namespaces",
            Events => "events",
            ServiceAccounts => "serviceaccounts",
            Roles => "roles.rbac.authorization.k8s.io",
            RoleBindings => "rolebindings.rbac.authorization.k8s.io",
            ClusterRoles => "clusterroles.rbac.authorization.k8s.io",
            ClusterRoleBindings => "clusterrolebindings.rbac.authorization.k8s.io",
            CustomResourceDefinitions => "customresourcedefinitions.apiextensions.k8s.io",
            Leases => "leases.coordination.k8s.io",
            PriorityClasses => "priorityclasses.scheduling.k8s.io",
            RuntimeClasses => "runtimeclasses.node.k8s.io",
            MutatingWebhooks => "mutatingwebhookconfigurations.admissionregistration.k8s.io",
            ValidatingWebhooks => "validatingwebhookconfigurations.admissionregistration.k8s.io",
            CertificateSigningRequests => "certificatesigningrequests.certificates.k8s.io",
            IngressClasses => "ingressclasses.networking.k8s.io",
            LimitRanges => "limitranges",
            ResourceQuotas => "resourcequotas",
            PodDisruptionBudgets => "poddisruptionbudgets.policy",
            VolumeAttachments => "volumeattachments.storage.k8s.io",
            CSINodes => "csinodes.storage.k8s.io",
            CSIDrivers => "csidrivers.storage.k8s.io",
        }
    }

    pub fn namespaced(self) -> bool {
        !matches!(
            self,
            Nodes
                | Namespaces
                | PersistentVolumes
                | StorageClasses
                | ClusterRoles
                | ClusterRoleBindings
                | CustomResourceDefinitions
                | IngressClasses
                | VolumeAttachments
                | CSINodes
                | CSIDrivers
                | PriorityClasses
                | RuntimeClasses
                | MutatingWebhooks
                | ValidatingWebhooks
                | CertificateSigningRequests
        )
    }

    /// Whether Kubernetes normally records events for this kind. Plain data and policy
    /// objects (config maps, secrets, RBAC, classes, quotas...) don't, so their pages
    /// leave the Events tab out (unless events turn up for one anyway).
    pub fn has_events(self) -> bool {
        !matches!(
            self,
            ConfigMaps
                | Secrets
                | ServiceAccounts
                | Roles
                | RoleBindings
                | ClusterRoles
                | ClusterRoleBindings
                | CustomResourceDefinitions
                | StorageClasses
                | IngressClasses
                | LimitRanges
                | Leases
                | Events
                | EndpointSlices
                | NetworkPolicies
                | CSIDrivers
                | CSINodes
                | PriorityClasses
                | RuntimeClasses
                | MutatingWebhooks
                | ValidatingWebhooks
        )
    }

    /// Kinds whose logs can be read: a pod's own, or every pod a workload runs (by its selector).
    pub fn has_logs(self) -> bool {
        matches!(self, Pods | Deployments | StatefulSets | DaemonSets | ReplicaSets | Jobs)
    }
    pub fn can_scale(self) -> bool {
        matches!(self, Deployments | StatefulSets | ReplicaSets)
    }
    pub fn can_restart(self) -> bool {
        matches!(self, Deployments | StatefulSets | DaemonSets)
    }
    pub fn can_port_forward(self) -> bool {
        matches!(self, Pods | Services)
    }

    /// Column headers after Name (and Namespace / Context, added by the table).
    /// Column headers after Name (Context and Namespace are added by the table).
    /// "CPU Usage" / "Memory Usage" cells are drawn by the table from live metrics.
    pub fn columns(self) -> &'static [&'static str] {
        match self {
            Pods => &["Ready", "Status", "CPU Usage", "Memory Usage", "Restarts", "Last Restart", "Last Restart Reason", "Node", "Controller", "Pod IP", "Age"],
            Deployments | StatefulSets => &["Ready", "Desired", "Up-to-date", "Available", "CPU Usage", "Memory Usage", "Age"],
            DaemonSets => &["Current", "Ready", "Desired", "Up-to-date", "Available", "CPU Usage", "Memory Usage", "Age"],
            ReplicaSets => &["Desired", "Current", "Ready", "Age"],
            Jobs => &["Status", "Succeeded", "Failures", "Duration", "Age"],
            CronJobs => &["Schedule", "Active Jobs", "Last Schedule", "Suspended", "Age"],
            Services => &["Type", "Cluster IP", "External IP", "Ports", "Age"],
            Ingresses => &["Class", "Hosts", "TLS", "Address", "Age"],
            EndpointSlices => &["Address Type", "Ports", "Endpoints", "Age"],
            NetworkPolicies => &["Pod Selector", "Age"],
            IngressClasses => &["Controller", "Default", "Age"],
            ConfigMaps => &["Count", "Keys", "Age"],
            Secrets => &["Type", "Count", "Keys", "Age"],
            HorizontalPodAutoscalers => &["Target", "Min", "Max", "Replicas", "Age"],
            LimitRanges => &["Limits", "Age"],
            ResourceQuotas => &["Hard", "Age"],
            PodDisruptionBudgets => &["Min Available", "Max Unavailable", "Allowed Disruptions", "Age"],
            PersistentVolumeClaims => &["Capacity", "Status", "Usage", "Volume", "Access Modes", "Storage Class", "Age"],
            PersistentVolumes => &["Capacity", "Access", "Reclaim", "Status", "Claim", "Storage Class", "Age"],
            VolumeAttachments => &["Attacher", "Volume", "Node", "Attached", "Age"],
            CSINodes => &["Drivers", "Age"],
            CSIDrivers => &["Attach Required", "Pod Info On Mount", "Modes", "Age"],
            StorageClasses => &["Provisioner", "Reclaim", "Binding Mode", "Age"],
            Nodes => &["Status", "CPU Usage", "Memory Usage", "Roles", "kubelet", "Operating System", "Kernel Version", "Container Runtime", "Internal IP", "Age"],
            Namespaces => &["Phase", "Age"],
            Events => &["Object", "Reason", "Message", "Type", "Interval", "Last Seen"],
            ServiceAccounts => &["Secrets", "Age"],
            Roles | ClusterRoles => &["Rules", "Age"],
            RoleBindings | ClusterRoleBindings => &["Role", "Subjects", "Age"],
            CustomResourceDefinitions => &["Group", "Kind", "Scope", "Versions", "Age"],
            Leases => &["Holder", "Last Renew", "Age"],
            PriorityClasses => &["Value", "Global Default", "Preemption", "Age"],
            RuntimeClasses => &["Handler", "Age"],
            MutatingWebhooks | ValidatingWebhooks => &["Webhooks", "Services", "Failure Policy", "Age"],
            CertificateSigningRequests => &["Signer", "Requestor", "Condition", "Age"],
        }
    }

    /// More columns that can be switched on from the column picker (hidden until then).
    /// Their cells follow the usual ones in `Row::cells`.
    pub fn extra_columns(self) -> &'static [&'static str] {
        match self {
            Pods => &["CPU Requests", "CPU Limits", "Memory Requests", "Memory Limits", "Containers", "Images", "QoS Class", "Service Account", "Host IP", "Priority Class", "Labels", "Created"],
            Deployments => &["CPU Requests", "CPU Limits", "Memory Requests", "Memory Limits", "Images", "Strategy", "Selector", "Labels", "Created"],
            StatefulSets | DaemonSets => &["CPU Requests", "CPU Limits", "Memory Requests", "Memory Limits", "Images", "Selector", "Labels", "Created"],
            ReplicaSets => &["Images", "Selector", "Labels", "Created"],
            Jobs | CronJobs => &["Images", "Labels", "Created"],
            Services => &["Selector", "Labels", "Created"],
            Nodes => &["Pods", "CPU Capacity", "Memory Capacity", "Architecture", "Labels", "Created"],
            Events => &[],
            _ => &["Labels", "Created"],
        }
    }

    /// Every column a list can show: the usual ones, then the extra ones.
    pub fn all_columns(self) -> Vec<&'static str> {
        self.columns().iter().chain(self.extra_columns()).copied().collect()
    }

    pub fn extra_cells(self, o: &Value) -> Vec<Cell> {
        let md = &o["metadata"];
        let spec = &o["spec"];
        let st = &o["status"];
        let pod_spec = match self {
            Pods => spec,
            CronJobs => &spec["jobTemplate"]["spec"]["template"]["spec"],
            _ => &spec["template"]["spec"],
        };
        let containers = pod_spec["containers"].as_array().cloned().unwrap_or_default();
        let list = |f: &dyn Fn(&Value) -> String| -> Cell {
            let v: Vec<String> = containers.iter().map(f).filter(|x| !x.is_empty()).collect();
            t(if v.is_empty() { "-".to_string() } else { v.join(", ") })
        };
        self.extra_columns()
            .iter()
            .map(|c| match *c {
                "CPU Requests" | "CPU Limits" | "Memory Requests" | "Memory Limits" => {
                    let r = requests(self, o);
                    let v = match *c { "CPU Requests" => r[0], "CPU Limits" => r[1], "Memory Requests" => r[2], _ => r[3] };
                    let (a, b) = if c.starts_with("CPU") { fmt_cpu(v) } else { fmt_mem(v) };
                    // Nothing set (no request, no limit) is a dash, and sorts below zero.
                    if v > 0.0 { Cell { text: format!("{a}{b}"), sort: SortKey::Num(v), tone: Tone::Normal } } else { Cell { text: "-".into(), sort: SortKey::Num(-1.0), tone: Tone::Muted } }
                }
                "Containers" => list(&|c| s(&c["name"])),
                "Images" => list(&|c| s(&c["image"])),
                "QoS Class" => t(or_dash(s(&st["qosClass"]))),
                "Service Account" => t(or_dash(s(&spec["serviceAccountName"]))),
                "Host IP" => t(or_dash(s(&st["hostIP"]))),
                "Priority Class" => t(or_dash(s(&spec["priorityClassName"]))),
                "Strategy" => t(or_dash(s(&spec["strategy"]["type"]))),
                "Selector" => t(if self == Services { selector(&spec["selector"]) } else { selector(&spec["selector"]["matchLabels"]) }),
                "Pods" => n(st["capacity"]["pods"].as_str().and_then(|x| x.parse().ok()).unwrap_or(0)),
                "CPU Capacity" => {
                    let m = cpu_milli(st["capacity"]["cpu"].as_str().unwrap_or("0"));
                    let (a, b) = fmt_cpu(m);
                    Cell { text: format!("{a}{b}"), sort: SortKey::Num(m), tone: Tone::Normal }
                }
                "Memory Capacity" => {
                    let m = mem_bytes(st["capacity"]["memory"].as_str().unwrap_or("0"));
                    let (a, b) = fmt_mem(m);
                    Cell { text: format!("{a}{b}"), sort: SortKey::Num(m), tone: Tone::Normal }
                }
                "Architecture" => t(or_dash(s(&st["nodeInfo"]["architecture"]))),
                "Labels" => {
                    let l = md["labels"].as_object().map(|m| m.iter().map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or(""))).collect::<Vec<_>>().join(", ")).unwrap_or_default();
                    t(or_dash(l))
                }
                "Created" => {
                    let ts = s(&md["creationTimestamp"]);
                    let secs = crate::kube::parse_time(&ts).unwrap_or(0) as f64;
                    Cell { text: or_dash(ts.replace('T', " ").trim_end_matches('Z').to_string()), sort: SortKey::Num(secs), tone: Tone::Muted }
                }
                _ => t("-"),
            })
            .collect()
    }

    /// Events are listed by the object they are about, without a Name column.
    pub fn shows_name(self) -> bool {
        self != Events
    }

    pub fn cells(self, o: &Value) -> Vec<Cell> {
        let md = &o["metadata"];
        let spec = &o["spec"];
        let st = &o["status"];
        let created = &md["creationTimestamp"];
        match self {
            Pods => {
                let cs = st["containerStatuses"].as_array().cloned().unwrap_or_default();
                let total = spec["containers"].as_array().map(|a| a.len()).unwrap_or(0);
                let ready = cs.iter().filter(|c| c["ready"].as_bool() == Some(true)).count();
                let restarts: i64 = cs.iter().map(|c| i(&c["restartCount"])).sum();
                let last = cs
                    .iter()
                    .filter_map(|c| c["lastState"]["terminated"]["finishedAt"].as_str())
                    .filter_map(crate::kube::parse_time)
                    .max();
                let last_reason = last_restart(o).map(|x| x.0).unwrap_or_else(|| "-".into());
                let status = pod_status(o);
                let done = status == "Completed";
                let owner = md["ownerReferences"]
                    .as_array()
                    .and_then(|a| a.first())
                    // Just the kind; the pod's page links to the object itself.
                    .map(|r| s(&r["kind"]))
                    .unwrap_or_else(|| "-".into());
                // What matters is how fresh a restart is: red within the hour, amber within the day.
                // Many of them are amber however old.
                let fresh = match last.map(|t| crate::kube::now_secs() - t) {
                    Some(a) if a < 3600 => Tone::Danger,
                    Some(a) if a < 86_400 => Tone::Warning,
                    _ => Tone::Muted,
                };
                let rtone = match (restarts, fresh) {
                    (0, _) => Tone::Muted,
                    (n, Tone::Muted) => if n >= 20 { Tone::Warning } else { Tone::Normal },
                    (_, t) => t,
                };
                let (ltext, ltone, lsort) = match last {
                    Some(tm) => {
                        let ago = crate::kube::now_secs() - tm;
                        (crate::kube::human_duration(ago), fresh, ago as f64)
                    }
                    None => ("-".to_string(), Tone::Muted, f64::MAX),
                };
                vec![
                    toned(
                        t(format!("{ready}/{total}")),
                        if done { Tone::Muted } else { ready_tone(ready as i64, total as i64) },
                    ),
                    toned(t(status.clone()), status_tone(&status)),
                    usage(),
                    usage(),
                    toned(n(restarts), rtone),
                    Cell { text: ltext, sort: SortKey::Num(lsort), tone: ltone },
                    toned(t(last_reason), Tone::Normal),
                    toned(t(s(&spec["nodeName"])), Tone::Muted),
                    toned(t(owner), Tone::Muted),
                    toned(t(s(&st["podIP"])), Tone::Muted),
                    pod_age_cell(created),
                ]
            }
            Deployments | StatefulSets => {
                let want = spec["replicas"].as_i64().unwrap_or(1);
                let ready = i(&st["readyReplicas"]);
                vec![
                    toned(
                        t(format!("{ready}/{want}")),
                        ready_tone(ready, want),
                    ),
                    n(want),
                    n(i(&st["updatedReplicas"])),
                    n(i(&st["availableReplicas"])),
                    usage(),
                    usage(),
                    age_cell(created),
                ]
            }
            DaemonSets => vec![
                n(i(&st["currentNumberScheduled"])),
                toned(n(i(&st["numberReady"])), ready_tone(i(&st["numberReady"]), i(&st["desiredNumberScheduled"]))),
                n(i(&st["desiredNumberScheduled"])),
                n(i(&st["updatedNumberScheduled"])),
                n(i(&st["numberAvailable"])),
                usage(),
                usage(),
                age_cell(created),
            ],
            ReplicaSets => vec![
                n(spec["replicas"].as_i64().unwrap_or(0)),
                n(i(&st["replicas"])),
                toned(n(i(&st["readyReplicas"])), ready_tone(i(&st["readyReplicas"]), spec["replicas"].as_i64().unwrap_or(0))),
                age_cell(created),
            ],
            Jobs => {
                let succeeded = i(&st["succeeded"]);
                let failed = i(&st["failed"]);
                let want = spec["completions"].as_i64().unwrap_or(1);
                let status = if succeeded >= want {
                    "Complete"
                } else if failed > 0 && i(&st["active"]) == 0 {
                    "Failed"
                } else {
                    "Running"
                };
                let dur = match (
                    crate::kube::parse_time(st["startTime"].as_str().unwrap_or("")),
                    crate::kube::parse_time(st["completionTime"].as_str().unwrap_or("")),
                ) {
                    (Some(a), Some(b)) => crate::kube::human_duration(b - a),
                    (Some(a), None) => crate::kube::human_duration(crate::kube::now_secs() - a),
                    _ => "-".into(),
                };
                vec![
                    toned(t(status), status_tone(status)),
                    t(format!("{succeeded}/{want}")),
                    toned(n(failed), if failed > 0 { Tone::Danger } else { Tone::Muted }),
                    toned(t(dur), Tone::Muted),
                    age_cell(created),
                ]
            }
            CronJobs => vec![
                t(s(&spec["schedule"])),
                n(st["active"].as_array().map(|a| a.len() as i64).unwrap_or(0)),
                toned(
                    t(st["lastScheduleTime"]
                        .as_str()
                        .map(|x| format!("{} ago", age(x)))
                        .unwrap_or_else(|| "-".into())),
                    Tone::Muted,
                ),
                if spec["suspend"].as_bool() == Some(true) { toned(t("Yes"), Tone::Warning) } else { toned(t("No"), Tone::Muted) },
                age_cell(created),
            ],
            Services => {
                let ports = spec["ports"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|p| {
                                let np = p["nodePort"].as_i64();
                                match np {
                                    Some(np) => format!("{}:{}/{}", i(&p["port"]), np, s(&p["protocol"])),
                                    None => format!("{}/{}", i(&p["port"]), s(&p["protocol"])),
                                }
                            })
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                let ext = st["loadBalancer"]["ingress"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|x| {
                                x["ip"].as_str().or(x["hostname"].as_str()).unwrap_or("").to_string()
                            })
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .filter(|x| !x.is_empty())
                    .unwrap_or_else(|| "-".into());
                vec![
                    t(s(&spec["type"])),
                    toned(t(s(&spec["clusterIP"])), Tone::Muted),
                    toned(t(ext), Tone::Muted),
                    t(ports),
                    age_cell(created),
                ]
            }
            Ingresses => {
                let hosts = spec["rules"]
                    .as_array()
                    .map(|a| a.iter().map(|r| s(&r["host"])).collect::<Vec<_>>().join(", "))
                    .unwrap_or_default();
                let addr = st["loadBalancer"]["ingress"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|x| x["ip"].as_str().or(x["hostname"].as_str()).unwrap_or("").to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                // TLS: the certificate secrets the ingress uses (a Kubedog addition).
                let tls = spec["tls"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|x| x["secretName"].as_str().map(String::from).unwrap_or_else(|| "default certificate".into()))
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .filter(|x| !x.is_empty())
                    .unwrap_or_else(|| "-".into());
                vec![t(s(&spec["ingressClassName"])), t(hosts), toned(t(tls), Tone::Normal), toned(t(addr), Tone::Muted), age_cell(created)]
            }
            EndpointSlices => vec![
                t(s(&o["addressType"])),
                t(o["ports"]
                    .as_array()
                    .map(|a| a.iter().map(|p| i(&p["port"]).to_string()).collect::<Vec<_>>().join(", "))
                    .unwrap_or_default()),
                n(o["endpoints"].as_array().map(|a| a.len() as i64).unwrap_or(0)),
                age_cell(created),
            ],
            NetworkPolicies => vec![t(selector(&spec["podSelector"]["matchLabels"])), age_cell(created)],
            ConfigMaps => vec![n(count_keys(&o["data"]) + count_keys(&o["binaryData"])), toned(t(key_names(&o["data"])), Tone::Muted), age_cell(created)],
            Secrets => vec![toned(t(s(&o["type"])), Tone::Muted), n(count_keys(&o["data"])), toned(t(key_names(&o["data"])), Tone::Muted), age_cell(created)],
            HorizontalPodAutoscalers => vec![
                t(format!("{}/{}", s(&spec["scaleTargetRef"]["kind"]), s(&spec["scaleTargetRef"]["name"]))),
                n(spec["minReplicas"].as_i64().unwrap_or(1)),
                n(i(&spec["maxReplicas"])),
                n(i(&st["currentReplicas"])),
                age_cell(created),
            ],
            PersistentVolumeClaims => {
                let phase = s(&st["phase"]);
                vec![
                    t(s(&st["capacity"]["storage"])),
                    toned(t(phase.clone()), status_tone(&phase)),
                    usage(),
                    toned(t(s(&spec["volumeName"])), Tone::Muted),
                    t(access_modes(&spec["accessModes"])),
                    t(s(&spec["storageClassName"])),
                    age_cell(created),
                ]
            }
            PersistentVolumes => {
                let phase = s(&st["phase"]);
                let claim = if spec["claimRef"].is_object() {
                    format!("{}/{}", s(&spec["claimRef"]["namespace"]), s(&spec["claimRef"]["name"]))
                } else {
                    String::new()
                };
                vec![
                    t(s(&spec["capacity"]["storage"])),
                    t(access_modes(&spec["accessModes"])),
                    t(s(&spec["persistentVolumeReclaimPolicy"])),
                    toned(t(phase.clone()), status_tone(&phase)),
                    toned(t(claim), Tone::Muted),
                    t(s(&spec["storageClassName"])),
                    age_cell(created),
                ]
            }
            StorageClasses => vec![
                t(s(&o["provisioner"])),
                t(s(&o["reclaimPolicy"])),
                t(s(&o["volumeBindingMode"])),
                age_cell(created),
            ],
            Nodes => {
                let ready = st["conditions"]
                    .as_array()
                    .and_then(|a| a.iter().find(|c| c["type"] == "Ready"))
                    .map(|c| c["status"] == "True")
                    .unwrap_or(false);
                let mut status = if ready { "Ready".to_string() } else { "NotReady".to_string() };
                if spec["unschedulable"].as_bool() == Some(true) {
                    status.push_str(", SchedulingDisabled");
                }
                let roles = md["labels"]
                    .as_object()
                    .map(|m| {
                        m.keys()
                            .filter_map(|k| k.strip_prefix("node-role.kubernetes.io/"))
                            .map(|x| x.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .filter(|x| !x.is_empty())
                    .unwrap_or_else(|| "<none>".into());
                let ip = st["addresses"]
                    .as_array()
                    .and_then(|a| a.iter().find(|x| x["type"] == "InternalIP"))
                    .map(|x| s(&x["address"]))
                    .unwrap_or_default();
                vec![
                    toned(t(status.clone()), if ready && !status.contains(',') { Tone::Success } else { Tone::Warning }),
                    usage(),
                    usage(),
                    t(roles),
                    toned(t(s(&st["nodeInfo"]["kubeletVersion"])), Tone::Muted),
                    toned(t(s(&st["nodeInfo"]["osImage"])), Tone::Muted),
                    toned(t(s(&st["nodeInfo"]["kernelVersion"])), Tone::Muted),
                    toned(t(s(&st["nodeInfo"]["containerRuntimeVersion"])), Tone::Muted),
                    toned(t(ip), Tone::Muted),
                    age_cell(created),
                ]
            }
            Namespaces => {
                let phase = s(&st["phase"]);
                let tone = if phase == "Active" { Tone::Normal } else { status_tone(&phase) };
                vec![toned(t(phase.clone()), tone), age_cell(created)]
            }
            Events => {
                let ty = s(&o["type"]);
                let last = o["lastTimestamp"]
                    .as_str()
                    .or(o["eventTime"].as_str())
                    .or(md["creationTimestamp"].as_str())
                    .unwrap_or("")
                    .to_string();
                let count = o["count"].as_i64().or(o["series"]["count"].as_i64()).unwrap_or(1);
                let first = o["firstTimestamp"].as_str().or(md["creationTimestamp"].as_str()).unwrap_or("");
                let interval = if count > 1 { format!("x{count} over {}", age(first)) } else { "1".into() };
                vec![
                    toned(t(format!("{}: {}", s(&o["involvedObject"]["kind"]), s(&o["involvedObject"]["name"]))), Tone::Link),
                    t(s(&o["reason"])),
                    t(s(&o["message"]).replace('\n', " ")),
                    toned(t(ty.clone()), if ty == "Warning" { Tone::Warning } else { Tone::Normal }),
                    Cell { text: interval, sort: SortKey::Num(count as f64), tone: Tone::Normal },
                    {
                        let mut c = age_cell(&Value::String(last));
                        c.tone = Tone::Normal;
                        c
                    },
                ]
            }
            PriorityClasses => vec![
                n(o["value"].as_i64().unwrap_or(0)),
                t(if o["globalDefault"].as_bool() == Some(true) { "Yes" } else { "No" }),
                t(o["preemptionPolicy"].as_str().unwrap_or("PreemptLowerPriority")),
                age_cell(created),
            ],
            RuntimeClasses => vec![t(s(&o["handler"])), age_cell(created)],
            MutatingWebhooks | ValidatingWebhooks => {
                let hooks = o["webhooks"].as_array().cloned().unwrap_or_default();
                let svcs: Vec<String> = hooks
                    .iter()
                    .map(|h| {
                        let svc = &h["clientConfig"]["service"];
                        if svc.is_object() { format!("{}/{}", s(&svc["namespace"]), s(&svc["name"])) } else { s(&h["clientConfig"]["url"]) }
                    })
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect();
                let fp: Vec<String> = hooks.iter().map(|h| s(&h["failurePolicy"])).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
                vec![n(hooks.len() as i64), t(svcs.join(", ")), t(fp.join(", ")), age_cell(created)]
            }
            CertificateSigningRequests => {
                let cond = st["conditions"].as_array().and_then(|a| a.last()).map(|c| s(&c["type"])).unwrap_or_else(|| "Pending".into());
                let tone = if cond == "Approved" { Tone::Success } else if cond == "Denied" || cond == "Failed" { Tone::Danger } else { Tone::Warning };
                vec![t(s(&spec["signerName"])), t(s(&spec["username"])), toned(t(cond), tone), age_cell(created)]
            }
            Leases => vec![
                t(s(&spec["holderIdentity"])),
                t(spec["renewTime"].as_str().map(age).unwrap_or_else(|| "-".into())),
                age_cell(created),
            ],
            IngressClasses => vec![
                t(s(&spec["controller"])),
                t(if md["annotations"]["ingressclass.kubernetes.io/is-default-class"] == "true" { "Yes" } else { "No" }),
                age_cell(created),
            ],
            LimitRanges => vec![n(spec["limits"].as_array().map(|a| a.len() as i64).unwrap_or(0)), age_cell(created)],
            ResourceQuotas => vec![
                t(spec["hard"].as_object().map(|m| m.iter().map(|(k, v)| format!("{k}={}", s(v))).collect::<Vec<_>>().join(", ")).unwrap_or_default()),
                age_cell(created),
            ],
            PodDisruptionBudgets => vec![
                t(s(&spec["minAvailable"])),
                t(s(&spec["maxUnavailable"])),
                n(i(&st["disruptionsAllowed"])),
                age_cell(created),
            ],
            VolumeAttachments => vec![
                t(s(&spec["attacher"])),
                t(s(&spec["source"]["persistentVolumeName"])),
                t(s(&spec["nodeName"])),
                t(if st["attached"].as_bool() == Some(true) { "true" } else { "false" }),
                age_cell(created),
            ],
            CSINodes => vec![
                t(spec["drivers"].as_array().map(|a| a.iter().map(|d| s(&d["name"])).collect::<Vec<_>>().join(", ")).unwrap_or_default()),
                age_cell(created),
            ],
            CSIDrivers => vec![
                t(s(&spec["attachRequired"])),
                t(s(&spec["podInfoOnMount"])),
                t(spec["volumeLifecycleModes"].as_array().map(|a| a.iter().map(s).collect::<Vec<_>>().join(", ")).unwrap_or_default()),
                age_cell(created),
            ],
            ServiceAccounts => vec![n(o["secrets"].as_array().map(|a| a.len() as i64).unwrap_or(0)), age_cell(created)],
            Roles | ClusterRoles => vec![n(o["rules"].as_array().map(|a| a.len() as i64).unwrap_or(0)), age_cell(created)],
            RoleBindings | ClusterRoleBindings => vec![
                t(format!("{}/{}", s(&o["roleRef"]["kind"]), s(&o["roleRef"]["name"]))),
                t(o["subjects"]
                    .as_array()
                    .map(|a| a.iter().map(|x| s(&x["name"])).collect::<Vec<_>>().join(", "))
                    .unwrap_or_default()),
                age_cell(created),
            ],
            CustomResourceDefinitions => vec![
                t(s(&spec["group"])),
                t(s(&spec["names"]["kind"])),
                t(s(&spec["scope"])),
                t(spec["versions"]
                    .as_array()
                    .map(|a| a.iter().map(|v| s(&v["name"])).collect::<Vec<_>>().join(", "))
                    .unwrap_or_default()),
                age_cell(created),
            ],
        }
    }
}

fn or_dash(x: String) -> String {
    if x.is_empty() { "-".into() } else { x }
}

fn key_names(v: &Value) -> String {
    v.as_object().map(|m| m.keys().cloned().collect::<Vec<_>>().join(", ")).unwrap_or_default()
}

fn count_keys(v: &Value) -> i64 {
    v.as_object().map(|m| m.len() as i64).unwrap_or(0)
}

fn access_modes(v: &Value) -> String {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|m| match m.as_str().unwrap_or("") {
                    "ReadWriteOnce" => "RWO",
                    "ReadOnlyMany" => "ROX",
                    "ReadWriteMany" => "RWX",
                    "ReadWriteOncePod" => "RWOP",
                    x => x,
                }.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

pub fn selector(v: &Value) -> String {
    v.as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or("")))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|x| !x.is_empty())
        .unwrap_or_else(|| "(all pods)".into())
}

/// Did its node refuse it (instead of pushing it off later)?
pub fn rejected(o: &Value) -> bool {
    o["status"]["message"].as_str().unwrap_or("").trim_start().starts_with("Pod was rejected")
}

/// What the node was short of, from its message: "memory", "disk"...
fn short_of(msg: &str) -> String {
    let list = match (msg.split("low on resource: ").nth(1), msg.split("condition: [").nth(1)) {
        (Some(r), _) => r.split(['.', ',']).next().unwrap_or(""),
        (None, Some(r)) => r.split(']').next().unwrap_or(""),
        _ if msg.contains("ephemeral") || msg.contains("EmptyDir") => "disk",
        _ => "",
    };
    let mut v: Vec<&str> = vec![];
    for w in list.split_whitespace() {
        let w = match w {
            "MemoryPressure" => "memory",
            "DiskPressure" | "ephemeral-storage" | "inodes" => "disk",
            "PIDPressure" | "pids" => "processes",
            w => w,
        };
        if !v.contains(&w) && v.len() < 3 {
            v.push(w);
        }
    }
    v.join(", ")
}

/// Why a pod that failed is over, when it's about the pod and not about what one of its containers did:
/// (short, in full). Its containers then only say "ContainerStatusUnknown" or that they were killed.
pub fn pod_over(o: &Value) -> Option<(String, String)> {
    let st = &o["status"];
    if st["phase"] != "Failed" {
        return None;
    }
    let msg = st["message"].as_str().unwrap_or("").trim().to_string();
    let target = st["conditions"].as_array().into_iter().flatten().find(|c| c["type"] == "DisruptionTarget" && c["status"] == "True");
    let more = target.and_then(|c| c["message"].as_str()).unwrap_or("").trim().to_string();
    let full = |m: &str| if m.is_empty() { more.clone() } else { m.to_string() };
    let with = |word: &str, m: &str| {
        let s = short_of(m);
        if s.is_empty() { word.to_string() } else { format!("{word}: {s}") }
    };
    match st["reason"].as_str().filter(|r| !r.is_empty()) {
        Some("Evicted") => Some((with(if rejected(o) { "Rejected" } else { "Evicted" }, &full(&msg)), full(&msg))),
        Some("Terminated" | "NodeShutdown") if msg.contains("shutdown") => Some(("Node shutdown".into(), msg)),
        Some(r) => Some((r.to_string(), full(&msg))),
        None => {
            let word = match target?["reason"].as_str()? {
                "TerminationByKubelet" => with("Evicted", &more),
                "EvictionByEvictionAPI" => "Evicted".into(),
                "DeletionByTaintManager" => "Evicted: taint".into(),
                "PreemptionByScheduler" => "Preempted".into(),
                "DeletionByPodGC" => "Node gone".into(),
                r => r.to_string(),
            };
            Some((word, more))
        }
    }
}

/// How the last run of a pod's containers ended: (short, more about it when the short needs it). With several
/// containers, the one that ended last, like the time that's shown next to it.
pub fn last_restart(o: &Value) -> Option<(String, String)> {
    let cs = o["status"]["containerStatuses"].as_array()?;
    let ended = |c: &Value| c["lastState"]["terminated"]["finishedAt"].as_str().and_then(crate::kube::parse_time);
    let mut best: Option<&Value> = None;
    for c in cs.iter().filter(|c| c["lastState"]["terminated"]["reason"].is_string()) {
        if best.map(|b| ended(c) > ended(b)).unwrap_or(true) {
            best = Some(c);
        }
    }
    let c = best?;
    let tm = &c["lastState"]["terminated"];
    let reason = tm["reason"].as_str()?;
    let lost = "Nobody saw how the container ended: its node couldn't find it any more. Usually the node or what runs its containers was restarted.";
    // The node makes these up when a container is gone, exit code and all.
    if reason == "ContainerStatusUnknown" {
        // It never ran again because the whole pod was over: then that's why.
        if c["state"]["terminated"]["reason"] == "ContainerStatusUnknown" {
            if let Some(w) = pod_over(o) {
                return Some(w);
            }
        }
        return Some(("Container lost".into(), lost.into()));
    }
    let code = tm["exitCode"].as_i64();
    if reason == "Unknown" {
        return Some((code.map(|c| format!("Container lost (ExitCode: {c})")).unwrap_or("Container lost".into()), lost.into()));
    }
    Some((code.map(|c| format!("{reason} (ExitCode: {c})")).unwrap_or(reason.into()), String::new()))
}

/// A pod's STATUS, like kubectl's: waiting/terminated reasons win over the phase. Why the whole pod failed
/// (evicted, rejected...) wins over those.
pub fn pod_status(o: &Value) -> String {
    if o["metadata"]["deletionTimestamp"].is_string() {
        return "Terminating".into();
    }
    if let Some((word, _)) = pod_over(o) {
        return word;
    }
    let st = &o["status"];
    for key in ["initContainerStatuses", "containerStatuses"] {
        if let Some(cs) = st[key].as_array() {
            for c in cs {
                if let Some(r) = c["state"]["waiting"]["reason"].as_str() {
                    if key == "initContainerStatuses" {
                        return format!("Init:{r}");
                    }
                    return r.to_string();
                }
                if let Some(r) = c["state"]["terminated"]["reason"].as_str() {
                    if key == "containerStatuses" {
                        return r.to_string();
                    }
                }
            }
        }
    }
    if let Some(r) = st["reason"].as_str() {
        return r.to_string();
    }
    st["phase"].as_str().unwrap_or("Unknown").to_string()
}

/// Colours: Running green; Pending/PodInitializing amber;
/// Terminating/ContainerCreating violet (info); Completed grey; anything else red.
pub fn status_tone(status: &str) -> Tone {
    match status {
        "Running" | "Ready" | "Active" | "Bound" | "Available" | "Complete" | "Succeeded" => {
            Tone::Success
        }
        "Pending" | "PodInitializing" | "Released" => Tone::Warning,
        "Terminating" | "ContainerCreating" => Tone::Info,
        "Completed" => Tone::Muted,
        x if x.starts_with("Init:") => Tone::Warning,
        _ => Tone::Danger,
    }
}

// ---------- requests, limits and quantities ----------

/// CPU in millicores from a Kubernetes quantity ("250m", "2", "0.5").
pub fn cpu_milli(q: &str) -> f64 {
    let q = q.trim();
    if q.is_empty() {
        return 0.0;
    }
    if let Some(m) = q.strip_suffix('m') {
        return m.parse().unwrap_or(0.0);
    }
    if let Some(n) = q.strip_suffix('n') {
        return n.parse::<f64>().unwrap_or(0.0) / 1_000_000.0;
    }
    if let Some(u) = q.strip_suffix('u') {
        return u.parse::<f64>().unwrap_or(0.0) / 1_000.0;
    }
    q.parse::<f64>().unwrap_or(0.0) * 1000.0
}

/// Memory in bytes from a Kubernetes quantity ("128Mi", "1G", "512").
pub fn mem_bytes(q: &str) -> f64 {
    let q = q.trim();
    const UNITS: [(&str, f64); 12] = [
        ("Ki", 1024.0),
        ("Mi", 1048576.0),
        ("Gi", 1073741824.0),
        ("Ti", 1099511627776.0),
        ("Pi", 1125899906842624.0),
        ("Ei", 1152921504606846976.0),
        ("k", 1e3),
        ("K", 1e3),
        ("M", 1e6),
        ("G", 1e9),
        ("T", 1e12),
        ("m", 1e-3),
    ];
    for (u, f) in UNITS {
        if let Some(n) = q.strip_suffix(u) {
            return n.parse::<f64>().unwrap_or(0.0) * f;
        }
    }
    q.parse().unwrap_or(0.0)
}

pub fn fmt_cpu(m: f64) -> (String, &'static str) {
    if m >= 10_000.0 {
        (format!("{:.1}", m / 1000.0), "")
    } else {
        (format!("{}", m.round() as i64), "m")
    }
}

pub fn fmt_mem(b: f64) -> (String, &'static str) {
    let gi = b / 1073741824.0;
    if gi >= 1.0 {
        let s = if gi >= 100.0 { format!("{gi:.0}") } else if gi >= 10.0 { format!("{gi:.2}") } else { format!("{gi:.1}") };
        (s, "Gi")
    } else {
        (format!("{}", (b / 1048576.0).round() as i64), "Mi")
    }
}

/// Requests and limits: (cpu request m, cpu limit m, memory request B, memory limit B).
/// Pods sum their containers; workloads use their pod template times replicas;
/// nodes report allocatable as the "limit".
pub fn requests(kind: Kind, o: &Value) -> [f64; 4] {
    let sum = |cs: &Value, mult: f64| -> [f64; 4] {
        let mut r = [0.0; 4];
        for c in cs.as_array().cloned().unwrap_or_default() {
            let res = &c["resources"];
            r[0] += cpu_milli(res["requests"]["cpu"].as_str().unwrap_or(""));
            r[1] += cpu_milli(res["limits"]["cpu"].as_str().unwrap_or(""));
            r[2] += mem_bytes(res["requests"]["memory"].as_str().unwrap_or(""));
            r[3] += mem_bytes(res["limits"]["memory"].as_str().unwrap_or(""));
        }
        r.map(|x| x * mult)
    };
    match kind {
        Pods => sum(&o["spec"]["containers"], 1.0),
        Deployments | StatefulSets => {
            let reps = o["spec"]["replicas"].as_f64().unwrap_or(1.0);
            sum(&o["spec"]["template"]["spec"]["containers"], reps)
        }
        DaemonSets => {
            let reps = o["status"]["desiredNumberScheduled"].as_f64().unwrap_or(1.0);
            sum(&o["spec"]["template"]["spec"]["containers"], reps)
        }
        Nodes => {
            let a = &o["status"]["allocatable"];
            [0.0, cpu_milli(a["cpu"].as_str().unwrap_or("")), 0.0, mem_bytes(a["memory"].as_str().unwrap_or(""))]
        }
        _ => [0.0; 4],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn why_a_pod_is_over() {
        let gone = serde_json::json!([{"name": "web", "state": {"terminated": {"exitCode": 137, "reason": "ContainerStatusUnknown"}}}]);
        let pod = |reason: &str, msg: &str| serde_json::json!({"status": {"phase": "Failed", "reason": reason, "message": msg, "containerStatuses": gone}});
        for (reason, msg, want) in [
            ("Evicted", "Pod was rejected: The node had condition: [MemoryPressure]. ", "Rejected: memory"),
            ("Evicted", "Pod was rejected: The node had condition: [DiskPressure MemoryPressure]. ", "Rejected: disk, memory"),
            ("Evicted", "The node was low on resource: memory. Threshold quantity: 2839063389, available: 2161288Ki. ", "Evicted: memory"),
            ("Evicted", "The node was low on resource: ephemeral-storage. Container web was using 4Gi", "Evicted: disk"),
            ("Evicted", "Pod ephemeral local storage usage exceeds the total limit of containers 1Gi. ", "Evicted: disk"),
            ("Evicted", "", "Evicted"),
            ("DeadlineExceeded", "Pod was active on the node longer than the specified deadline", "DeadlineExceeded"),
            ("Terminated", "Pod was terminated in response to imminent node shutdown.", "Node shutdown"),
            ("NodeAffinity", "Pod was rejected: Predicate NodeAffinity failed", "NodeAffinity"),
        ] {
            let p = pod(reason, msg);
            assert_eq!(pod_status(&p), want);
            assert_eq!(status_tone(&pod_status(&p)), Tone::Danger);
        }
        assert!(pod_over(&pod("Evicted", "Pod was rejected: why")).unwrap().1.ends_with("why"));
        // Without a reason of its own: from the condition.
        let mut p = pod("", "");
        p["status"]["reason"] = Value::Null;
        assert_eq!(pod_status(&p), "ContainerStatusUnknown");
        p["status"]["conditions"] = serde_json::json!([{"type": "DisruptionTarget", "status": "True", "reason": "PreemptionByScheduler", "message": "made room"}]);
        assert_eq!((pod_status(&p).as_str(), pod_over(&p).unwrap().1.as_str()), ("Preempted", "made room"));
        // A container's own failure stays what it is, and so does a pod that runs.
        let p = serde_json::json!({"status": {"phase": "Failed", "containerStatuses": [{"state": {"terminated": {"reason": "OOMKilled", "exitCode": 137}}}]}});
        assert_eq!(pod_status(&p), "OOMKilled");
        let p = serde_json::json!({"status": {"phase": "Running", "containerStatuses": [{"state": {"waiting": {"reason": "CrashLoopBackOff"}}}]}});
        assert_eq!(pod_status(&p), "CrashLoopBackOff");
    }

    #[test]
    fn why_it_restarted() {
        let lost = serde_json::json!({"terminated": {"exitCode": 137, "finishedAt": null, "reason": "ContainerStatusUnknown"}});
        let pod = |st: Value| serde_json::json!({"status": st});
        let short = |p: &Value| last_restart(p).map(|x| x.0);
        // Its pod was evicted and it never ran again.
        let p = pod(serde_json::json!({"phase": "Failed", "reason": "Evicted", "message": "The node was low on resource: memory. Threshold", "containerStatuses": [{"state": lost, "lastState": lost}]}));
        assert_eq!(short(&p).as_deref(), Some("Evicted: memory"));
        assert!(last_restart(&p).unwrap().1.starts_with("The node was low"));
        // It runs again: the node lost sight of it, and that's all that's known.
        let p = pod(serde_json::json!({"phase": "Running", "containerStatuses": [{"state": {"running": {}}, "lastState": lost}]}));
        assert_eq!(short(&p).as_deref(), Some("Container lost"));
        // It ended in its own way before the pod was evicted.
        let oom = serde_json::json!({"terminated": {"exitCode": 137, "finishedAt": "2026-01-02T10:00:00Z", "reason": "OOMKilled"}});
        let p = pod(serde_json::json!({"phase": "Failed", "reason": "Evicted", "containerStatuses": [{"state": lost, "lastState": oom}]}));
        assert_eq!(last_restart(&p), Some(("OOMKilled (ExitCode: 137)".into(), String::new())));
        // Of several, the one that ended last.
        let err = serde_json::json!({"terminated": {"exitCode": 1, "finishedAt": "2026-01-03T10:00:00Z", "reason": "Error"}});
        let p = pod(serde_json::json!({"phase": "Running", "containerStatuses": [{"lastState": lost}, {"lastState": oom}, {"lastState": err}, {"lastState": {}}]}));
        assert_eq!(short(&p).as_deref(), Some("Error (ExitCode: 1)"));
        let p = pod(serde_json::json!({"containerStatuses": [{"lastState": {"terminated": {"reason": "Unknown", "exitCode": 255}}}]}));
        assert_eq!(short(&p).as_deref(), Some("Container lost (ExitCode: 255)"));
        assert_eq!(last_restart(&pod(serde_json::json!({"containerStatuses": [{"lastState": {}}]}))), None);
    }

    #[test]
    fn ready_colours() {
        let pod = |phase: &str, ready: &[bool]| {
            serde_json::json!({
                "metadata": {"name": "p"},
                "spec": {"containers": ready.iter().map(|_| serde_json::json!({"name": "c"})).collect::<Vec<_>>()},
                "status": {"phase": phase, "containerStatuses": ready.iter().map(|r| if phase == "Succeeded" {
                    serde_json::json!({"ready": r, "state": {"terminated": {"reason": "Completed", "exitCode": 0}}})
                } else {
                    serde_json::json!({"ready": r, "state": {"running": {}}})
                }).collect::<Vec<_>>()}
            })
        };
        let ready = |k: Kind, o: &Value, col: usize| { let c = &k.cells(o)[col]; (c.text.clone(), c.tone) };
        assert_eq!(ready(Kind::Pods, &pod("Running", &[true]), 0), ("1/1".into(), Tone::Success));
        assert_eq!(ready(Kind::Pods, &pod("Running", &[true, false]), 0), ("1/2".into(), Tone::Danger));
        assert_eq!(ready(Kind::Pods, &pod("Pending", &[false]), 0), ("0/1".into(), Tone::Danger));
        assert_eq!(ready(Kind::Pods, &pod("Succeeded", &[false]), 0), ("0/1".into(), Tone::Muted));
        let dep = |want: i64, ready: i64| serde_json::json!({"metadata": {}, "spec": {"replicas": want}, "status": {"readyReplicas": ready}});
        assert_eq!(ready(Kind::Deployments, &dep(2, 2), 0), ("2/2".into(), Tone::Success));
        assert_eq!(ready(Kind::StatefulSets, &dep(3, 1), 0), ("1/3".into(), Tone::Danger));
        assert_eq!(ready(Kind::Deployments, &dep(0, 0), 0), ("0/0".into(), Tone::Muted));
        assert_eq!(ready(Kind::ReplicaSets, &dep(2, 1), 2).1, Tone::Danger);
        let ds = serde_json::json!({"metadata": {}, "spec": {}, "status": {"numberReady": 4, "desiredNumberScheduled": 4}});
        assert_eq!(ready(Kind::DaemonSets, &ds, 1).1, Tone::Success);
    }

    #[test]
    fn a_young_pod_is_green() {
        use crate::kube::human_duration as h;
        for (secs, tone) in [(0, Tone::Fresh), (45, Tone::Fresh), (119, Tone::Fresh), (120, Tone::Success), (3600, Tone::Success), (10_799, Tone::Success), (10_800, Tone::Normal), (900_000, Tone::Normal)] {
            assert_eq!(young(Some(secs)), tone, "{secs}");
            // The colour follows what is written: seconds, then minutes, then hours.
            let (text, want) = (h(secs), match tone { Tone::Fresh => "s", Tone::Success => "m", _ => "" });
            assert!(tone == Tone::Normal && text.contains(['h', 'd', 'y']) || tone == Tone::Fresh && text.ends_with('s') && !text.contains('m') || tone == Tone::Success && text.contains('m') && !text.contains('h'), "{secs} {text} {want}");
        }
        assert_eq!(young(None), Tone::Normal);
        assert_eq!(young(Some(-5)), Tone::Normal);
    }
}
