// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use prometheus::{
    Gauge, GaugeVec, IntCounter, IntCounterVec, IntGauge, Registry,
    register_gauge_vec_with_registry, register_gauge_with_registry,
    register_int_counter_vec_with_registry, register_int_counter_with_registry,
    register_int_gauge_with_registry,
};
use reqwest::Client;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::{
    Components, Cpu, CpuRefreshKind, Disk, Disks, Networks, ProcessRefreshKind, ProcessesToUpdate,
    System, get_current_pid,
};
use tracing::warn;

const REFRESH_INTERVAL: Duration = Duration::from_secs(15);
const MAX_METADATA_VALUE_CHARS: usize = 128;
const INFO_LABELS: &[&str] = &[
    "version",
    "git_revision",
    "os",
    "os_version",
    "kernel_version",
    "architecture",
    "hostname",
    "deployment_environment",
    "cloud_provider",
    "region",
    "zone",
    "location",
    "instance_type",
    "cloud_instance_id",
    "cloud_image_id",
    "private_ip",
    "memory_type",
    "virtualization",
    "container",
    "container_runtime",
    "container_id",
    "container_image",
    "kubernetes_cluster",
    "kubernetes_namespace",
    "kubernetes_pod",
    "kubernetes_node",
];

/// Machine and process telemetry emitted only by validator nodes.
///
/// Metadata values come from an explicit allow-list. Arbitrary environment
/// variables are deliberately never exported because they commonly contain
/// credentials and can create unbounded Prometheus label cardinality.
pub(crate) struct ValidatorMetrics {
    up: GaugeVec,
    binary_info: GaugeVec,
    binary_size_bytes: IntGauge,
    collection_errors_total: IntCounterVec,
    cpu_frequency_mhz: Gauge,
    cpu_info: GaugeVec,
    cpu_logical_count: IntGauge,
    cpu_physical_count: IntGauge,
    cgroup_cpu_limit_cores: Gauge,
    cgroup_memory_available_bytes: IntGauge,
    cgroup_memory_limit_bytes: IntGauge,
    cgroup_memory_rss_bytes: IntGauge,
    cloud_metadata_available: GaugeVec,
    load_average_fifteen_minutes: Gauge,
    load_average_five_minutes: Gauge,
    load_average_one_minute: Gauge,
    memory_available_bytes: IntGauge,
    machine_info: GaugeVec,
    memory_total_bytes: IntGauge,
    memory_used_bytes: IntGauge,
    network_receive_bytes_total: IntCounter,
    network_receive_errors_total: IntCounter,
    network_transmit_bytes_total: IntCounter,
    network_transmit_errors_total: IntCounter,
    process_cpu_cores: Gauge,
    process_disk_read_bytes_total: IntCounter,
    process_disk_written_bytes_total: IntCounter,
    process_open_file_descriptors: IntGauge,
    process_resident_memory_bytes: IntGauge,
    process_thread_count: IntGauge,
    process_uptime_seconds: IntGauge,
    process_virtual_memory_bytes: IntGauge,
    storage_available_bytes: IntGauge,
    storage_info: GaugeVec,
    storage_total_bytes: IntGauge,
    swap_total_bytes: IntGauge,
    swap_used_bytes: IntGauge,
    system_cpu_usage_ratio: Gauge,
    system_boot_unixtime: IntGauge,
    system_uptime_seconds: IntGauge,
    telemetry_last_refresh_unixtime: IntGauge,
    temperature_celsius: GaugeVec,
    temperature_critical_celsius: GaugeVec,
    db_path: PathBuf,
    disks: Disks,
    networks: Networks,
    system: System,
    version: &'static str,
    git_revision: &'static str,
    metadata: ValidatorMetadata,
}

impl ValidatorMetrics {
    pub(crate) fn new(
        registry: &Registry,
        version: &'static str,
        git_revision: &'static str,
        db_path: &Path,
    ) -> Self {
        let up = register_gauge_vec_with_registry!(
            "ika_validator_up",
            "1 while the validator process is alive; machine and deployment facts are labels",
            INFO_LABELS,
            registry,
        )
        .unwrap();
        let metadata = ValidatorMetadata::collect(version, git_revision);
        up.with_label_values(&metadata.label_values()).set(1.0);

        let disks = Disks::new_with_refreshed_list();

        let mut metrics = Self {
            up,
            binary_info: register_gauge_vec_with_registry!(
                "ika_validator_binary_info",
                "Running validator binary identity",
                &["version", "git_revision", "sha256"],
                registry,
            )
            .unwrap(),
            binary_size_bytes: register_int_gauge_with_registry!(
                "ika_validator_binary_size_bytes",
                "Size of the running validator binary in bytes",
                registry,
            )
            .unwrap(),
            collection_errors_total: register_int_counter_vec_with_registry!(
                "ika_validator_telemetry_collection_errors_total",
                "Validator host telemetry collection errors",
                &["operation"],
                registry,
            )
            .unwrap(),
            cpu_frequency_mhz: register_gauge_with_registry!(
                "ika_validator_cpu_frequency_mhz",
                "Average current frequency of logical CPUs in MHz",
                registry,
            )
            .unwrap(),
            cpu_info: register_gauge_vec_with_registry!(
                "ika_validator_cpu_info",
                "CPU hardware identity",
                &["vendor", "brand"],
                registry,
            )
            .unwrap(),
            cpu_logical_count: register_int_gauge_with_registry!(
                "ika_validator_cpu_logical_count",
                "Logical CPUs visible to the validator",
                registry,
            )
            .unwrap(),
            cpu_physical_count: register_int_gauge_with_registry!(
                "ika_validator_cpu_physical_count",
                "Physical CPU cores visible to the validator, or 0 when unavailable",
                registry,
            )
            .unwrap(),
            cgroup_cpu_limit_cores: register_gauge_with_registry!(
                "ika_validator_cgroup_cpu_limit_cores",
                "Cgroup CPU quota in cores, or 0 when unlimited or unavailable",
                registry,
            )
            .unwrap(),
            cgroup_memory_available_bytes: register_int_gauge_with_registry!(
                "ika_validator_cgroup_memory_available_bytes",
                "Memory remaining in the validator cgroup, or 0 when unavailable",
                registry,
            )
            .unwrap(),
            cgroup_memory_limit_bytes: register_int_gauge_with_registry!(
                "ika_validator_cgroup_memory_limit_bytes",
                "Validator cgroup memory limit, or 0 when unavailable",
                registry,
            )
            .unwrap(),
            cgroup_memory_rss_bytes: register_int_gauge_with_registry!(
                "ika_validator_cgroup_memory_rss_bytes",
                "Resident memory used by the validator cgroup, or 0 when unavailable",
                registry,
            )
            .unwrap(),
            cloud_metadata_available: register_gauge_vec_with_registry!(
                "ika_validator_cloud_metadata_available",
                "1 when the cloud identity endpoint returned metadata",
                &["provider"],
                registry,
            )
            .unwrap(),
            load_average_fifteen_minutes: register_gauge_with_registry!(
                "ika_validator_load_average_fifteen_minutes",
                "System load average over fifteen minutes",
                registry,
            )
            .unwrap(),
            load_average_five_minutes: register_gauge_with_registry!(
                "ika_validator_load_average_five_minutes",
                "System load average over five minutes",
                registry,
            )
            .unwrap(),
            load_average_one_minute: register_gauge_with_registry!(
                "ika_validator_load_average_one_minute",
                "System load average over one minute",
                registry,
            )
            .unwrap(),
            memory_available_bytes: register_int_gauge_with_registry!(
                "ika_validator_memory_available_bytes",
                "System memory available to the validator",
                registry,
            )
            .unwrap(),
            machine_info: register_gauge_vec_with_registry!(
                "ika_validator_machine_info",
                "Machine, board, and BIOS identity reported by DMI",
                &[
                    "manufacturer",
                    "product_name",
                    "product_version",
                    "board_vendor",
                    "board_name",
                    "bios_vendor",
                    "bios_version",
                    "machine_id_sha256",
                ],
                registry,
            )
            .unwrap(),
            memory_total_bytes: register_int_gauge_with_registry!(
                "ika_validator_memory_total_bytes",
                "System memory visible to the validator",
                registry,
            )
            .unwrap(),
            memory_used_bytes: register_int_gauge_with_registry!(
                "ika_validator_memory_used_bytes",
                "System memory currently used",
                registry,
            )
            .unwrap(),
            network_receive_bytes_total: register_int_counter_with_registry!(
                "ika_validator_network_receive_bytes_total",
                "Network bytes received by all interfaces since validator telemetry started",
                registry,
            )
            .unwrap(),
            network_receive_errors_total: register_int_counter_with_registry!(
                "ika_validator_network_receive_errors_total",
                "Network receive errors since validator telemetry started",
                registry,
            )
            .unwrap(),
            network_transmit_bytes_total: register_int_counter_with_registry!(
                "ika_validator_network_transmit_bytes_total",
                "Network bytes transmitted by all interfaces since validator telemetry started",
                registry,
            )
            .unwrap(),
            network_transmit_errors_total: register_int_counter_with_registry!(
                "ika_validator_network_transmit_errors_total",
                "Network transmit errors since validator telemetry started",
                registry,
            )
            .unwrap(),
            process_cpu_cores: register_gauge_with_registry!(
                "ika_validator_process_cpu_cores",
                "CPU used by the validator process, measured in logical cores",
                registry,
            )
            .unwrap(),
            process_disk_read_bytes_total: register_int_counter_with_registry!(
                "ika_validator_process_disk_read_bytes_total",
                "Bytes read from storage by the validator since telemetry started",
                registry,
            )
            .unwrap(),
            process_disk_written_bytes_total: register_int_counter_with_registry!(
                "ika_validator_process_disk_written_bytes_total",
                "Bytes written to storage by the validator since telemetry started",
                registry,
            )
            .unwrap(),
            process_open_file_descriptors: register_int_gauge_with_registry!(
                "ika_validator_process_open_file_descriptors",
                "Open file descriptors held by the validator, or 0 when unavailable",
                registry,
            )
            .unwrap(),
            process_resident_memory_bytes: register_int_gauge_with_registry!(
                "ika_validator_process_resident_memory_bytes",
                "Validator process resident memory",
                registry,
            )
            .unwrap(),
            process_thread_count: register_int_gauge_with_registry!(
                "ika_validator_process_thread_count",
                "Operating-system threads in the validator process, or 0 when unavailable",
                registry,
            )
            .unwrap(),
            process_uptime_seconds: register_int_gauge_with_registry!(
                "ika_validator_process_uptime_seconds",
                "Validator process uptime in seconds",
                registry,
            )
            .unwrap(),
            process_virtual_memory_bytes: register_int_gauge_with_registry!(
                "ika_validator_process_virtual_memory_bytes",
                "Validator process virtual memory",
                registry,
            )
            .unwrap(),
            storage_available_bytes: register_int_gauge_with_registry!(
                "ika_validator_storage_available_bytes",
                "Available bytes on the volume containing the validator database",
                registry,
            )
            .unwrap(),
            storage_info: register_gauge_vec_with_registry!(
                "ika_validator_storage_info",
                "Database volume identity",
                &["mount_point", "file_system", "disk_kind"],
                registry,
            )
            .unwrap(),
            storage_total_bytes: register_int_gauge_with_registry!(
                "ika_validator_storage_total_bytes",
                "Total bytes on the volume containing the validator database",
                registry,
            )
            .unwrap(),
            swap_total_bytes: register_int_gauge_with_registry!(
                "ika_validator_swap_total_bytes",
                "System swap visible to the validator",
                registry,
            )
            .unwrap(),
            swap_used_bytes: register_int_gauge_with_registry!(
                "ika_validator_swap_used_bytes",
                "System swap currently used",
                registry,
            )
            .unwrap(),
            system_cpu_usage_ratio: register_gauge_with_registry!(
                "ika_validator_system_cpu_usage_ratio",
                "System CPU usage from 0 to 1",
                registry,
            )
            .unwrap(),
            system_boot_unixtime: register_int_gauge_with_registry!(
                "ika_validator_system_boot_unixtime",
                "Host boot time as a Unix timestamp",
                registry,
            )
            .unwrap(),
            system_uptime_seconds: register_int_gauge_with_registry!(
                "ika_validator_system_uptime_seconds",
                "Host operating-system uptime in seconds",
                registry,
            )
            .unwrap(),
            telemetry_last_refresh_unixtime: register_int_gauge_with_registry!(
                "ika_validator_telemetry_last_refresh_unixtime",
                "Unix timestamp of the last completed host telemetry refresh",
                registry,
            )
            .unwrap(),
            temperature_celsius: register_gauge_vec_with_registry!(
                "ika_validator_temperature_celsius",
                "Current hardware temperature by sensor component",
                &["component"],
                registry,
            )
            .unwrap(),
            temperature_critical_celsius: register_gauge_vec_with_registry!(
                "ika_validator_temperature_critical_celsius",
                "Critical hardware temperature by sensor component",
                &["component"],
                registry,
            )
            .unwrap(),
            db_path: db_path.to_path_buf(),
            disks,
            networks: Networks::new_with_refreshed_list(),
            system: System::new(),
            version,
            git_revision,
            metadata,
        };
        metrics.initialize_static_metrics();
        metrics
    }

    pub(crate) async fn run(mut self) {
        let binary_identity = tokio::task::spawn_blocking(binary_identity).await;
        match binary_identity {
            Ok(Ok((sha256, size))) => {
                self.binary_info
                    .with_label_values(&[self.version, self.git_revision, &sha256])
                    .set(1.0);
                self.binary_size_bytes.set(to_i64(size));
            }
            Ok(Err(error)) => {
                warn!(?error, "failed to hash running validator binary");
                self.collection_errors_total
                    .with_label_values(&["binary_hash"])
                    .inc();
            }
            Err(error) => {
                warn!(?error, "validator binary hash task failed");
                self.collection_errors_total
                    .with_label_values(&["binary_hash_task"])
                    .inc();
            }
        }

        if env::var("IKA_DISABLE_CLOUD_METADATA").as_deref() != Ok("1") {
            let old_labels = self
                .metadata
                .label_values()
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let cloud_metadata = discover_cloud_metadata(&self.metadata.cloud_provider).await;
            let provider = if cloud_metadata.provider.is_empty() {
                &self.metadata.cloud_provider
            } else {
                &cloud_metadata.provider
            };
            if !provider.is_empty() {
                self.cloud_metadata_available
                    .with_label_values(&[provider])
                    .set(if cloud_metadata.has_values() {
                        1.0
                    } else {
                        0.0
                    });
            }
            if cloud_metadata.has_values() {
                let old_labels = old_labels.iter().map(String::as_str).collect::<Vec<_>>();
                self.up.remove_label_values(&old_labels).ok();
                self.metadata.merge_cloud_metadata(cloud_metadata);
                self.up
                    .with_label_values(&self.metadata.label_values())
                    .set(1.0);
            }
        }

        let mut interval = tokio::time::interval(REFRESH_INTERVAL);
        loop {
            interval.tick().await;
            self.refresh();
        }
    }

    fn initialize_static_metrics(&mut self) {
        self.system.refresh_cpu_list(CpuRefreshKind::everything());
        self.cpu_logical_count
            .set(to_i64(self.system.cpus().len() as u64));
        self.cpu_physical_count
            .set(to_i64(System::physical_core_count().unwrap_or(0) as u64));
        if let Some(cpu) = self.system.cpus().first() {
            self.cpu_info
                .with_label_values(&[&bounded(cpu.vendor_id()), &bounded(cpu.brand())])
                .set(1.0);
        }
        self.refresh_cpu_frequency();
        self.cgroup_cpu_limit_cores.set(cgroup_cpu_limit_cores());
        self.system_boot_unixtime.set(to_i64(System::boot_time()));
        let machine_info = MachineInfo::collect();
        self.machine_info
            .with_label_values(&machine_info.label_values())
            .set(1.0);
        self.refresh_storage_metrics();
    }

    fn refresh(&mut self) {
        self.system.refresh_memory();
        self.system.refresh_cpu_usage();
        self.system.refresh_cpu_frequency();
        self.refresh_cpu_frequency();

        let Ok(pid) = get_current_pid() else {
            self.collection_errors_total
                .with_label_values(&["current_pid"])
                .inc();
            return;
        };
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            true,
            ProcessRefreshKind::nothing()
                .with_cpu()
                .with_memory()
                .with_disk_usage(),
        );

        self.system_cpu_usage_ratio
            .set(f64::from(self.system.global_cpu_usage()) / 100.0);
        let load = System::load_average();
        self.load_average_one_minute.set(load.one);
        self.load_average_five_minutes.set(load.five);
        self.load_average_fifteen_minutes.set(load.fifteen);
        self.memory_total_bytes
            .set(to_i64(self.system.total_memory()));
        self.memory_available_bytes
            .set(to_i64(self.system.available_memory()));
        self.memory_used_bytes
            .set(to_i64(self.system.used_memory()));
        self.swap_total_bytes.set(to_i64(self.system.total_swap()));
        self.swap_used_bytes.set(to_i64(self.system.used_swap()));
        self.system_uptime_seconds.set(to_i64(System::uptime()));
        self.cgroup_cpu_limit_cores.set(cgroup_cpu_limit_cores());

        if let Some(limits) = self.system.cgroup_limits() {
            self.cgroup_memory_limit_bytes
                .set(to_i64(limits.total_memory));
            self.cgroup_memory_available_bytes
                .set(to_i64(limits.free_memory));
            self.cgroup_memory_rss_bytes.set(to_i64(limits.rss));
        }

        if let Some(process) = self.system.process(pid) {
            self.process_cpu_cores
                .set(f64::from(process.cpu_usage()) / 100.0);
            self.process_resident_memory_bytes
                .set(to_i64(process.memory()));
            self.process_virtual_memory_bytes
                .set(to_i64(process.virtual_memory()));
            self.process_uptime_seconds.set(to_i64(process.run_time()));
            let disk_usage = process.disk_usage();
            self.process_disk_read_bytes_total
                .inc_by(disk_usage.read_bytes);
            self.process_disk_written_bytes_total
                .inc_by(disk_usage.written_bytes);
        } else {
            self.collection_errors_total
                .with_label_values(&["process"])
                .inc();
        }

        if let Some(count) = directory_entry_count("/proc/self/fd") {
            self.process_open_file_descriptors.set(to_i64(count));
        }
        if let Some(count) = directory_entry_count("/proc/self/task") {
            self.process_thread_count.set(to_i64(count));
        }

        self.networks.refresh(true);
        self.network_receive_bytes_total.inc_by(
            self.networks
                .values()
                .map(|network| network.received())
                .sum(),
        );
        self.network_transmit_bytes_total.inc_by(
            self.networks
                .values()
                .map(|network| network.transmitted())
                .sum(),
        );
        self.network_receive_errors_total.inc_by(
            self.networks
                .values()
                .map(|network| network.errors_on_received())
                .sum(),
        );
        self.network_transmit_errors_total.inc_by(
            self.networks
                .values()
                .map(|network| network.errors_on_transmitted())
                .sum(),
        );

        self.refresh_storage_metrics();
        self.refresh_temperature_metrics();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.telemetry_last_refresh_unixtime.set(to_i64(now));
    }

    fn refresh_cpu_frequency(&self) {
        let cpus = self.system.cpus();
        if !cpus.is_empty() {
            self.cpu_frequency_mhz
                .set(cpus.iter().map(Cpu::frequency).sum::<u64>() as f64 / cpus.len() as f64);
        }
    }

    fn refresh_storage_metrics(&mut self) {
        self.disks.refresh(false);
        if let Some(disk) = database_disk(&self.disks, &self.db_path) {
            self.storage_info
                .with_label_values(&[
                    &bounded(disk.mount_point().to_string_lossy()),
                    &bounded(disk.file_system().to_string_lossy()),
                    &disk.kind().to_string(),
                ])
                .set(1.0);
            self.storage_total_bytes.set(to_i64(disk.total_space()));
            self.storage_available_bytes
                .set(to_i64(disk.available_space()));
        } else {
            self.collection_errors_total
                .with_label_values(&["database_volume"])
                .inc();
        }
    }

    fn refresh_temperature_metrics(&self) {
        Components::new_with_refreshed_list()
            .iter()
            .for_each(|component| {
                let label = bounded(component.label());
                if let Some(temperature) = component.temperature() {
                    self.temperature_celsius
                        .with_label_values(&[&label])
                        .set(f64::from(temperature));
                }
                if let Some(critical) = component.critical() {
                    self.temperature_critical_celsius
                        .with_label_values(&[&label])
                        .set(f64::from(critical));
                }
            });
    }
}

struct ValidatorMetadata {
    version: String,
    git_revision: String,
    os: String,
    os_version: String,
    kernel_version: String,
    architecture: String,
    hostname: String,
    deployment_environment: String,
    cloud_provider: String,
    region: String,
    zone: String,
    location: String,
    instance_type: String,
    cloud_instance_id: String,
    cloud_image_id: String,
    private_ip: String,
    memory_type: String,
    virtualization: String,
    container: String,
    container_runtime: String,
    container_id: String,
    container_image: String,
    kubernetes_cluster: String,
    kubernetes_namespace: String,
    kubernetes_pod: String,
    kubernetes_node: String,
}

impl ValidatorMetadata {
    fn collect(version: &str, git_revision: &str) -> Self {
        let cgroup = read_cgroup();
        let kubernetes = env::var_os("KUBERNETES_SERVICE_HOST").is_some()
            || cgroup
                .as_deref()
                .is_some_and(|value| value.contains("kubepods"));
        let container = kubernetes
            || Path::new("/.dockerenv").exists()
            || env::var_os("container").is_some()
            || cgroup.as_deref().is_some_and(|value| {
                ["docker", "containerd", "libpod", "crio"]
                    .iter()
                    .any(|runtime| value.contains(runtime))
            });
        let container_runtime = first_env(&["IKA_METRICS_CONTAINER_RUNTIME"])
            .unwrap_or_else(|| detect_container_runtime(cgroup.as_deref()));
        let container_id = first_env(&["IKA_METRICS_CONTAINER_ID"])
            .or_else(|| cgroup.as_deref().and_then(container_id_from_cgroup))
            .unwrap_or_default();
        let machine_info = MachineInfo::collect();
        let cloud_provider = first_env(&["IKA_METRICS_CLOUD_PROVIDER"])
            .unwrap_or_else(|| detect_cloud_provider(&machine_info));
        let kubernetes_pod = first_env(&["IKA_METRICS_K8S_POD", "POD_NAME"])
            .or_else(|| kubernetes.then(|| first_env(&["HOSTNAME"])).flatten())
            .unwrap_or_default();

        Self {
            version: bounded(version),
            git_revision: bounded(git_revision),
            os: bounded(System::name().unwrap_or_default()),
            os_version: bounded(System::long_os_version().unwrap_or_default()),
            kernel_version: bounded(System::kernel_version().unwrap_or_default()),
            architecture: env::consts::ARCH.to_owned(),
            hostname: bounded(System::host_name().unwrap_or_default()),
            deployment_environment: first_env(&["IKA_METRICS_ENVIRONMENT"]).unwrap_or_default(),
            cloud_provider: cloud_provider.clone(),
            region: first_env(&[
                "IKA_METRICS_REGION",
                "AWS_REGION",
                "AWS_DEFAULT_REGION",
                "REGION",
            ])
            .unwrap_or_default(),
            zone: first_env(&["IKA_METRICS_ZONE", "AVAILABILITY_ZONE", "ZONE"]).unwrap_or_default(),
            location: first_env(&["IKA_METRICS_LOCATION"]).unwrap_or_default(),
            instance_type: first_env(&["IKA_METRICS_INSTANCE_TYPE", "INSTANCE_TYPE"])
                .or_else(|| dmi_instance_type(&cloud_provider, &machine_info))
                .unwrap_or_default(),
            cloud_instance_id: first_env(&["IKA_METRICS_CLOUD_INSTANCE_ID", "INSTANCE_ID"])
                .unwrap_or_default(),
            cloud_image_id: first_env(&["IKA_METRICS_CLOUD_IMAGE_ID", "IMAGE_ID"])
                .unwrap_or_default(),
            private_ip: first_env(&["IKA_METRICS_PRIVATE_IP", "POD_IP"]).unwrap_or_default(),
            memory_type: first_env(&["IKA_METRICS_MEMORY_TYPE"]).unwrap_or_else(dmi_memory_type),
            virtualization: detect_virtualization(&machine_info),
            container: container.to_string(),
            container_runtime,
            container_id,
            container_image: first_env(&["IKA_METRICS_CONTAINER_IMAGE", "CONTAINER_IMAGE"])
                .unwrap_or_default(),
            kubernetes_cluster: first_env(&["IKA_METRICS_K8S_CLUSTER", "KUBERNETES_CLUSTER_NAME"])
                .unwrap_or_default(),
            kubernetes_namespace: first_env(&["IKA_METRICS_K8S_NAMESPACE", "POD_NAMESPACE"])
                .unwrap_or_default(),
            kubernetes_pod,
            kubernetes_node: first_env(&["IKA_METRICS_K8S_NODE", "NODE_NAME"]).unwrap_or_default(),
        }
    }

    fn label_values(&self) -> Vec<&str> {
        vec![
            &self.version,
            &self.git_revision,
            &self.os,
            &self.os_version,
            &self.kernel_version,
            &self.architecture,
            &self.hostname,
            &self.deployment_environment,
            &self.cloud_provider,
            &self.region,
            &self.zone,
            &self.location,
            &self.instance_type,
            &self.cloud_instance_id,
            &self.cloud_image_id,
            &self.private_ip,
            &self.memory_type,
            &self.virtualization,
            &self.container,
            &self.container_runtime,
            &self.container_id,
            &self.container_image,
            &self.kubernetes_cluster,
            &self.kubernetes_namespace,
            &self.kubernetes_pod,
            &self.kubernetes_node,
        ]
        .into_iter()
        .map(String::as_str)
        .collect()
    }

    fn merge_cloud_metadata(&mut self, metadata: CloudMetadata) {
        fill_empty(&mut self.cloud_provider, metadata.provider);
        fill_empty(&mut self.region, metadata.region);
        fill_empty(&mut self.zone, metadata.zone);
        fill_empty(&mut self.location, metadata.location);
        fill_empty(&mut self.instance_type, metadata.instance_type);
        fill_empty(&mut self.cloud_instance_id, metadata.instance_id);
        fill_empty(&mut self.cloud_image_id, metadata.image_id);
        fill_empty(&mut self.private_ip, metadata.private_ip);
    }
}

struct MachineInfo {
    manufacturer: String,
    product_name: String,
    product_version: String,
    board_vendor: String,
    board_name: String,
    bios_vendor: String,
    bios_version: String,
    machine_id_sha256: String,
}

impl MachineInfo {
    fn collect() -> Self {
        Self {
            manufacturer: dmi_value("sys_vendor"),
            product_name: dmi_value("product_name"),
            product_version: dmi_value("product_version"),
            board_vendor: dmi_value("board_vendor"),
            board_name: dmi_value("board_name"),
            bios_vendor: dmi_value("bios_vendor"),
            bios_version: dmi_value("bios_version"),
            machine_id_sha256: machine_id_sha256(),
        }
    }

    fn label_values(&self) -> Vec<&str> {
        vec![
            &self.manufacturer,
            &self.product_name,
            &self.product_version,
            &self.board_vendor,
            &self.board_name,
            &self.bios_vendor,
            &self.bios_version,
            &self.machine_id_sha256,
        ]
        .into_iter()
        .map(String::as_str)
        .collect()
    }
}

#[derive(Default)]
struct CloudMetadata {
    provider: String,
    region: String,
    zone: String,
    location: String,
    instance_type: String,
    instance_id: String,
    image_id: String,
    private_ip: String,
}

impl CloudMetadata {
    fn has_values(&self) -> bool {
        self.label_values().iter().any(|value| !value.is_empty())
    }

    fn label_values(&self) -> [&str; 7] {
        [
            &self.region,
            &self.zone,
            &self.location,
            &self.instance_type,
            &self.instance_id,
            &self.image_id,
            &self.private_ip,
        ]
    }
}

async fn discover_cloud_metadata(provider: &str) -> CloudMetadata {
    let Ok(client) = Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_millis(300))
        .timeout(Duration::from_secs(1))
        .build()
    else {
        return CloudMetadata::default();
    };

    let mut metadata = match provider {
        "aws" => aws_cloud_metadata(&client).await,
        "gcp" => gcp_cloud_metadata(&client).await,
        "azure" => azure_cloud_metadata(&client).await,
        "" => {
            let (aws, gcp, azure) = tokio::join!(
                aws_cloud_metadata(&client),
                gcp_cloud_metadata(&client),
                azure_cloud_metadata(&client),
            );
            [aws, gcp, azure]
                .into_iter()
                .find(CloudMetadata::has_values)
                .unwrap_or_default()
        }
        _ => CloudMetadata::default(),
    };
    if metadata.has_values() && metadata.provider.is_empty() {
        metadata.provider = provider.to_owned();
    }
    metadata
}

async fn aws_cloud_metadata(client: &Client) -> CloudMetadata {
    let Ok(token) = client
        .put("http://169.254.169.254/latest/api/token")
        .header("X-aws-ec2-metadata-token-ttl-seconds", "60")
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
    else {
        return CloudMetadata::default();
    };
    let Ok(token) = token.text().await else {
        return CloudMetadata::default();
    };
    let Ok(document) = client
        .get("http://169.254.169.254/latest/dynamic/instance-identity/document")
        .header("X-aws-ec2-metadata-token", token)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
    else {
        return CloudMetadata::default();
    };
    let Ok(document) = document.json::<Value>().await else {
        return CloudMetadata::default();
    };

    CloudMetadata {
        provider: "aws".to_owned(),
        region: json_string(&document, "/region"),
        zone: json_string(&document, "/availabilityZone"),
        location: json_string(&document, "/region"),
        instance_type: json_string(&document, "/instanceType"),
        instance_id: json_string(&document, "/instanceId"),
        image_id: json_string(&document, "/imageId"),
        private_ip: json_string(&document, "/privateIp"),
    }
}

async fn gcp_cloud_metadata(client: &Client) -> CloudMetadata {
    const ROOT: &str = "http://metadata.google.internal/computeMetadata/v1/instance";
    let instance_id_url = format!("{ROOT}/id");
    let machine_type_url = format!("{ROOT}/machine-type");
    let zone_url = format!("{ROOT}/zone");
    let image_id_url = format!("{ROOT}/image");
    let private_ip_url = format!("{ROOT}/network-interfaces/0/ip");
    let (instance_id, machine_type, zone, image_id, private_ip) = tokio::join!(
        google_metadata_value(client, &instance_id_url),
        google_metadata_value(client, &machine_type_url),
        google_metadata_value(client, &zone_url),
        google_metadata_value(client, &image_id_url),
        google_metadata_value(client, &private_ip_url),
    );
    let zone = metadata_path_tail(&zone);
    let region = zone
        .rsplit_once('-')
        .map(|(region, _)| region.to_owned())
        .unwrap_or_default();

    CloudMetadata {
        provider: "gcp".to_owned(),
        region: region.clone(),
        zone,
        location: region,
        instance_type: metadata_path_tail(&machine_type),
        instance_id,
        image_id: metadata_path_tail(&image_id),
        private_ip,
    }
}

async fn google_metadata_value(client: &Client, url: &str) -> String {
    let Ok(response) = client
        .get(url)
        .header("Metadata-Flavor", "Google")
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
    else {
        return String::new();
    };
    response.text().await.map(bounded).unwrap_or_default()
}

async fn azure_cloud_metadata(client: &Client) -> CloudMetadata {
    let Ok(response) = client
        .get("http://169.254.169.254/metadata/instance?api-version=2025-04-07")
        .header("Metadata", "true")
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
    else {
        return CloudMetadata::default();
    };
    let Ok(document) = response.json::<Value>().await else {
        return CloudMetadata::default();
    };

    CloudMetadata {
        provider: "azure".to_owned(),
        region: json_string(&document, "/compute/location"),
        zone: json_string(&document, "/compute/zone"),
        location: json_string(&document, "/compute/location"),
        instance_type: json_string(&document, "/compute/vmSize"),
        instance_id: json_string(&document, "/compute/vmId"),
        image_id: azure_image_id(&document),
        private_ip: json_string(
            &document,
            "/network/interface/0/ipv4/ipAddress/0/privateIpAddress",
        ),
    }
}

fn azure_image_id(document: &Value) -> String {
    let values = [
        json_string(document, "/compute/storageProfile/imageReference/publisher"),
        json_string(document, "/compute/storageProfile/imageReference/offer"),
        json_string(document, "/compute/storageProfile/imageReference/sku"),
        json_string(document, "/compute/storageProfile/imageReference/version"),
    ];
    bounded(
        values
            .iter()
            .filter(|value| !value.is_empty())
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn json_string(value: &Value, pointer: &str) -> String {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(bounded)
        .unwrap_or_default()
}

fn metadata_path_tail(value: &str) -> String {
    bounded(value.rsplit('/').next().unwrap_or_default())
}

fn dmi_value(name: &str) -> String {
    ["/sys/class/dmi/id", "/sys/devices/virtual/dmi/id"]
        .into_iter()
        .find_map(|directory| fs::read_to_string(Path::new(directory).join(name)).ok())
        .map(bounded)
        .unwrap_or_default()
}

fn dmi_memory_type() -> String {
    let Some(entries) = fs::read_dir("/sys/firmware/dmi/entries").ok() else {
        return String::new();
    };
    let mut memory_types = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("17-"))
        .filter_map(|entry| fs::read(entry.path().join("raw")).ok())
        .filter_map(|raw| raw.get(18).copied())
        .filter_map(memory_type_name)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    memory_types.sort();
    memory_types.dedup();
    bounded(memory_types.join(","))
}

fn memory_type_name(memory_type: u8) -> Option<&'static str> {
    match memory_type {
        0x12 => Some("DDR"),
        0x13 => Some("DDR2"),
        0x18 => Some("DDR3"),
        0x1A => Some("DDR4"),
        0x1B => Some("LPDDR"),
        0x1C => Some("LPDDR2"),
        0x1D => Some("LPDDR3"),
        0x1E => Some("LPDDR4"),
        0x20 => Some("HBM"),
        0x21 => Some("HBM2"),
        0x22 => Some("DDR5"),
        0x23 => Some("LPDDR5"),
        0x24 => Some("HBM3"),
        _ => None,
    }
}

fn machine_id_sha256() -> String {
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .into_iter()
        .find_map(|path| fs::read(path).ok())
        .filter(|value| !value.is_empty())
        .map(|value| format!("{:x}", Sha256::digest(value)))
        .unwrap_or_default()
}

fn detect_cloud_provider(machine_info: &MachineInfo) -> String {
    if env::var_os("AWS_REGION").is_some() || env::var_os("AWS_DEFAULT_REGION").is_some() {
        return "aws".to_owned();
    }
    if env::var_os("GOOGLE_CLOUD_PROJECT").is_some() {
        return "gcp".to_owned();
    }
    if env::var_os("AZURE_HTTP_USER_AGENT").is_some() {
        return "azure".to_owned();
    }

    let identity = format!(
        "{} {} {} {}",
        machine_info.manufacturer,
        machine_info.product_name,
        machine_info.bios_vendor,
        machine_info.bios_version
    )
    .to_ascii_lowercase();
    if identity.contains("amazon ec2") || identity.contains("amazon.com") {
        "aws"
    } else if identity.contains("google compute engine") || identity.contains("google") {
        "gcp"
    } else if identity.contains("microsoft corporation") && identity.contains("azure") {
        "azure"
    } else if identity.contains("digitalocean") || identity.contains("droplet") {
        "digitalocean"
    } else {
        ""
    }
    .to_owned()
}

fn detect_virtualization(machine_info: &MachineInfo) -> String {
    let identity = format!(
        "{} {} {}",
        machine_info.manufacturer, machine_info.product_name, machine_info.bios_vendor
    )
    .to_ascii_lowercase();
    [
        ("vmware", "vmware"),
        ("virtualbox", "virtualbox"),
        ("kvm", "kvm"),
        ("qemu", "qemu"),
        ("xen", "xen"),
        ("amazon ec2", "amazon-ec2"),
        ("google compute engine", "google-compute-engine"),
        ("microsoft corporation", "hyper-v"),
        ("parallels", "parallels"),
    ]
    .into_iter()
    .find_map(|(needle, value)| identity.contains(needle).then_some(value))
    .unwrap_or_default()
    .to_owned()
}

fn dmi_instance_type(provider: &str, machine_info: &MachineInfo) -> Option<String> {
    (provider == "aws"
        && !machine_info.product_name.is_empty()
        && machine_info.product_name != "HVM domU"
        && machine_info.product_name != "Amazon EC2")
        .then(|| machine_info.product_name.clone())
}

fn fill_empty(target: &mut String, value: String) {
    if target.is_empty() {
        *target = value;
    }
}

fn database_disk<'a>(disks: &'a Disks, db_path: &Path) -> Option<&'a Disk> {
    let db_path = db_path.canonicalize().unwrap_or_else(|_| {
        if db_path.is_absolute() {
            db_path.to_path_buf()
        } else {
            env::current_dir()
                .map(|current_dir| current_dir.join(db_path))
                .unwrap_or_else(|_| db_path.to_path_buf())
        }
    });
    disks
        .iter()
        .filter(|disk| db_path.starts_with(disk.mount_point()))
        .max_by_key(|disk| disk.mount_point().components().count())
}

fn binary_identity() -> io::Result<(String, u64)> {
    let path = env::current_exe()?;
    let size = path.metadata()?.len();
    let sha256 = sha256_reader(BufReader::new(File::open(path)?))?;
    Ok((sha256, size))
}

fn sha256_reader(mut reader: impl Read) -> io::Result<String> {
    let mut hasher = Sha256::new();
    io::copy(&mut reader, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn read_cgroup() -> Option<String> {
    fs::read_to_string("/proc/self/cgroup").ok()
}

fn detect_container_runtime(cgroup: Option<&str>) -> String {
    let Some(cgroup) = cgroup else {
        return if Path::new("/.dockerenv").exists() {
            "docker".to_owned()
        } else {
            String::new()
        };
    };
    ["containerd", "docker", "crio", "libpod"]
        .into_iter()
        .find(|runtime| cgroup.contains(runtime))
        .unwrap_or_default()
        .to_owned()
}

fn container_id_from_cgroup(cgroup: &str) -> Option<String> {
    cgroup
        .split(['/', '\n', ':'])
        .rev()
        .map(|part| {
            part.trim()
                .trim_end_matches(".scope")
                .trim_start_matches("docker-")
                .trim_start_matches("cri-containerd-")
                .trim_start_matches("crio-")
        })
        .find(|part| {
            (32..=64).contains(&part.len())
                && part.chars().all(|character| character.is_ascii_hexdigit())
        })
        .map(bounded)
}

fn cgroup_cpu_limit_cores() -> f64 {
    fs::read_to_string("/sys/fs/cgroup/cpu.max")
        .ok()
        .and_then(|value| {
            let mut fields = value.split_whitespace();
            let quota = fields.next()?;
            let period = fields.next()?.parse::<f64>().ok()?;
            (quota != "max")
                .then(|| quota.parse::<f64>().ok().map(|quota| quota / period))
                .flatten()
        })
        .or_else(|| {
            let quota = fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
                .ok()?
                .trim()
                .parse::<f64>()
                .ok()?;
            let period = fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
                .ok()?
                .trim()
                .parse::<f64>()
                .ok()?;
            (quota > 0.0).then_some(quota / period)
        })
        .unwrap_or(0.0)
}

fn first_env(keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| env::var(key).ok().filter(|value| !value.trim().is_empty()))
        .map(bounded)
}

fn directory_entry_count(path: impl AsRef<Path>) -> Option<u64> {
    Some(fs::read_dir(path).ok()?.filter_map(Result::ok).count() as u64)
}

fn bounded(value: impl AsRef<str>) -> String {
    value
        .as_ref()
        .trim()
        .chars()
        .take(MAX_METADATA_VALUE_CHARS)
        .collect()
}

fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn sha256_reader_hashes_binary_content() {
        assert_eq!(
            sha256_reader(Cursor::new(b"abc")).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn container_id_parser_handles_systemd_cgroup_paths() {
        let id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let cgroup = format!("0::/system.slice/docker-{id}.scope\n");
        assert_eq!(container_id_from_cgroup(&cgroup).as_deref(), Some(id));
    }

    #[test]
    fn metadata_values_are_bounded() {
        assert_eq!(bounded(format!("  {}  ", "x".repeat(200))).len(), 128);
    }

    #[test]
    fn smbios_memory_types_include_current_ddr_generations() {
        assert_eq!(memory_type_name(0x18), Some("DDR3"));
        assert_eq!(memory_type_name(0x1A), Some("DDR4"));
        assert_eq!(memory_type_name(0x22), Some("DDR5"));
        assert_eq!(memory_type_name(0), None);
    }

    #[test]
    fn azure_image_identity_is_bounded_and_composed() {
        let document: Value = serde_json::from_str(
            r#"{"compute":{"storageProfile":{"imageReference":{"publisher":"Canonical","offer":"ubuntu","sku":"24_04-lts","version":"latest"}}}}"#,
        )
        .unwrap();

        assert_eq!(
            azure_image_id(&document),
            "Canonical:ubuntu:24_04-lts:latest"
        );
    }

    #[test]
    fn validator_up_is_registered_with_machine_metadata() {
        let registry = Registry::new();
        let _metrics = ValidatorMetrics::new(&registry, "1.2.3", "abc123", Path::new("."));
        let up = registry
            .gather()
            .into_iter()
            .find(|family| family.name() == "ika_validator_up")
            .unwrap();

        assert_eq!(up.get_metric().len(), 1);
        assert_eq!(up.get_metric()[0].get_gauge().value(), 1.0);
        assert!(
            up.get_metric()[0]
                .get_label()
                .iter()
                .any(|label| label.name() == "version" && label.value() == "1.2.3")
        );
    }
}
