//! 관리 경계에서만 실행하는 인증서 발급·폐기·원자적 권한 저장.
use anyhow::{Context, Result, ensure};
use mtp_relay::config::{
    Config, Device, Limits, Policy, Registry, ResolverConfig, UserPolicy, valid_id,
};
use mtp_test_peer::{SecuritySettings, ServerSettings};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    net::SocketAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub outer_sni: String,
    pub server_name: String,
}
pub fn atomic(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().context("상위 디렉터리 필요")?;
    let mut rand = [0; 8];
    mtp_transport::random(&mut rand)?;
    let tmp = parent.join(format!(".tmp-{}", hex::encode(rand)));
    let metadata = fs::metadata(path).ok();
    let mode = metadata
        .as_ref()
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0o600);
    let r = (|| {
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(mode)
            .open(&tmp)?;
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        if let Some(meta) = &metadata {
            std::os::unix::fs::fchown(&f, Some(meta.uid()), Some(meta.gid()))?;
        }
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if r.is_err() {
        let _ = fs::remove_file(tmp);
    }
    r
}
pub fn save<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    atomic(path, &serde_json::to_vec_pretty(value)?)
}
fn directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn lock(root: &Path) -> Result<File> {
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(root.join("registry.lock"))?;
    f.lock()?;
    Ok(f)
}
fn params(name: &str, days: i64) -> Result<CertificateParams> {
    let mut p = CertificateParams::new(vec![])?;
    p.distinguished_name.push(DnType::CommonName, name);
    p.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
    p.not_after = OffsetDateTime::now_utc() + Duration::days(days);
    let mut serial = [0; 16];
    mtp_transport::random(&mut serial)?;
    serial[0] &= 0x7f;
    p.serial_number = Some(serial.to_vec().into());
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    Ok(p)
}
fn ca(root: &Path, name: &str) -> Result<()> {
    let key = KeyPair::generate()?;
    let mut p = params(name, 3650)?;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages
        .extend([KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]);
    let c = p.self_signed(&key)?;
    atomic(&root.join(format!("{name}.pem")), c.pem().as_bytes())?;
    atomic(
        &root.join(format!("{name}-key.pem")),
        key.serialize_pem().as_bytes(),
    )
}
fn issuer(root: &Path, name: &str) -> Result<Issuer<'static, KeyPair>> {
    Ok(Issuer::from_ca_cert_pem(
        &fs::read_to_string(root.join(format!("{name}.pem")))?,
        KeyPair::from_pem(&fs::read_to_string(root.join(format!("{name}-key.pem")))?)?,
    )?)
}
pub fn init(
    root: &Path,
    mut endpoint: Endpoint,
    listen: Vec<SocketAddr>,
    resolver: SocketAddr,
) -> Result<Config> {
    ensure!(
        root.is_absolute() && !root.exists(),
        "초기 경로는 아직 없는 절대 경로여야 합니다"
    );
    ensure!(
        endpoint.port != 0 && !endpoint.host.is_empty() && endpoint.host.len() <= 253,
        "접속 주소 필요"
    );
    endpoint.outer_sni = mtp_protocol::domain(&endpoint.outer_sni)?;
    endpoint.server_name = mtp_protocol::domain(&endpoint.server_name)?;
    directory(root)?;
    for d in ["pki", "state", "devices", "run"] {
        directory(&root.join(d))?;
    }
    let keys = root.join("pki");
    ca(&keys, "server-ca")?;
    ca(&keys, "client-ca")?;
    let mut p = params("mtp-gateway", 365)?;
    p.subject_alt_names =
        CertificateParams::new(vec![endpoint.server_name.clone()])?.subject_alt_names;
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate()?;
    let cert = p.signed_by(&key, &issuer(&keys, "server-ca")?)?;
    atomic(&keys.join("server.pem"), cert.pem().as_bytes())?;
    atomic(&keys.join("server-key.pem"), key.serialize_pem().as_bytes())?;
    let mut secret = [0; 16];
    mtp_transport::random(&mut secret)?;
    atomic(
        &root.join("secret.ee"),
        mtp_transport::Secret {
            key: secret,
            domain: endpoint.outer_sni.clone(),
        }
        .expose_hex()
        .as_bytes(),
    )?;
    save(&root.join("endpoint.json"), &endpoint)?;
    let config = Config {
        listen,
        secret_file: root.join("secret.ee"),
        server_cert: keys.join("server.pem"),
        server_key: keys.join("server-key.pem"),
        client_ca: keys.join("client-ca.pem"),
        registry_file: root.join("state/registry.json"),
        metrics_socket: root.join("run/status.sock"),
        resolver: ResolverConfig {
            address: resolver,
            mode: "udp".into(),
            server_name: None,
            ca_file: None,
            timeout_seconds: 3,
            cache_entries: 1024,
        },
        policy: Policy::default(),
        limits: Limits::default(),
        log_domains: false,
    };
    config.validate()?;
    save(
        &config.registry_file,
        &Registry {
            revision: 1,
            enabled: true,
            ..Default::default()
        },
    )?;
    atomic(
        &root.join("gateway.toml"),
        toml::to_string_pretty(&config)?.as_bytes(),
    )?;
    Ok(config)
}
pub fn issue(root: &Path, id: &str, owner: &str, days: i64) -> Result<Device> {
    ensure!(
        valid_id(id) && valid_id(owner) && (1..=730).contains(&days),
        "장치/소유자 식별자 또는 유효 기간 오류"
    );
    let _lock = lock(root)?;
    let config = Config::load(&root.join("gateway.toml"))?;
    let mut registry = Registry::load(&config.registry_file)?;
    ensure!(
        !registry.certificates.values().any(|d| d.id == id),
        "장치 식별자가 이미 존재합니다"
    );
    ensure!(
        registry.users.len() < 4096 && registry.certificates.len() < 16384,
        "발급 개수 한도"
    );
    let device_dir = root.join("devices").join(id);
    ensure!(!device_dir.exists(), "장치 파일이 이미 존재합니다");
    directory(&device_dir)?;
    let key = KeyPair::generate()?;
    let mut p = params(id, days)?;
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let expiration = p.not_after.format(&Rfc3339)?;
    let cert = p.signed_by(&key, &issuer(&root.join("pki"), "client-ca")?)?;
    atomic(
        &device_dir.join("client-key.pem"),
        key.serialize_pem().as_bytes(),
    )?;
    atomic(&device_dir.join("client.pem"), cert.pem().as_bytes())?;
    let device = Device {
        id: id.into(),
        owner: owner.into(),
        enabled: true,
        issued_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
        not_after: expiration,
    };
    registry.users.entry(owner.into()).or_default();
    registry
        .certificates
        .insert(mtp_transport::fingerprint(cert.der()), device.clone());
    registry.revision = registry.revision.checked_add(1).context("revision 소진")?;
    registry.validate()?;
    save(&config.registry_file, &registry)?;
    Ok(device)
}
pub fn revoke(root: &Path, id: &str) -> Result<()> {
    ensure!(valid_id(id), "장치 식별자 오류");
    let _lock = lock(root)?;
    let c = Config::load(&root.join("gateway.toml"))?;
    let mut r = Registry::load(&c.registry_file)?;
    let device = r
        .certificates
        .values_mut()
        .find(|d| d.id == id)
        .context("장치를 찾을 수 없습니다")?;
    device.enabled = false;
    r.revision = r.revision.checked_add(1).context("revision 소진")?;
    save(&c.registry_file, &r)
}
pub fn user_policy(root: &Path, owner: &str, policy: UserPolicy) -> Result<()> {
    ensure!(valid_id(owner), "소유자 식별자 오류");
    let _lock = lock(root)?;
    let c = Config::load(&root.join("gateway.toml"))?;
    let mut r = Registry::load(&c.registry_file)?;
    ensure!(r.users.contains_key(owner), "등록된 소유자가 아닙니다");
    r.users.insert(owner.into(), policy);
    r.revision = r.revision.checked_add(1).context("revision 소진")?;
    r.validate()?;
    save(&c.registry_file, &r)
}
pub fn set_enabled(root: &Path, enabled: bool) -> Result<()> {
    let _lock = lock(root)?;
    let c = Config::load(&root.join("gateway.toml"))?;
    let mut r = Registry::load(&c.registry_file)?;
    r.enabled = enabled;
    r.revision = r.revision.checked_add(1).context("revision 소진")?;
    save(&c.registry_file, &r)
}
pub fn bundle(root: &Path, id: &str) -> Result<std::collections::BTreeMap<String, String>> {
    ensure!(valid_id(id), "장치 식별자 오류");
    let c = Config::load(&root.join("gateway.toml"))?;
    let r = Registry::load(&c.registry_file)?;
    ensure!(
        r.certificates.values().any(|d| d.id == id && d.enabled),
        "유효한 장치가 아닙니다"
    );
    let e: Endpoint = serde_json::from_slice(&fs::read(root.join("endpoint.json"))?)?;
    let server = ServerSettings {
        host: e.host,
        port: e.port,
        secret_hex: fs::read_to_string(&c.secret_file)?.trim().into(),
        tls_domain: e.outer_sni,
        tunnel_mode: "extended_socks_over_mtproto".into(),
    };
    let security = SecuritySettings {
        transport: "mtp_tcp_v1".into(),
        server_name: e.server_name,
        ca_file: "config/gateway-ca.pem".into(),
        certificate_file: "config/client.pem".into(),
        private_key_file: "config/client-key.pem".into(),
        mux_version: 1,
        zero_rtt: false,
    };
    let mut b = std::collections::BTreeMap::new();
    b.insert(
        "config/server.json".into(),
        serde_json::to_string_pretty(&server)?,
    );
    b.insert(
        "config/security.json".into(),
        serde_json::to_string_pretty(&security)?,
    );
    for (file, path) in [
        ("gateway-ca.pem", root.join("pki/server-ca.pem")),
        (
            "client.pem",
            root.join("devices").join(id).join("client.pem"),
        ),
        (
            "client-key.pem",
            root.join("devices").join(id).join("client-key.pem"),
        ),
    ] {
        b.insert(format!("config/{file}"), fs::read_to_string(path)?);
    }
    Ok(b)
}
pub fn export(root: &Path, id: &str, out: &Path) -> Result<PathBuf> {
    let b = bundle(root, id)?;
    let target = out.join(format!("client-{id}"));
    ensure!(!target.exists(), "기존 내보내기 경로를 덮지 않습니다");
    directory(&target.join("config"))?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;
    for (file, data) in b {
        atomic(&target.join(file), data.as_bytes())?;
    }
    Ok(target)
}
pub fn validate(path: &Path) -> Result<Config> {
    let c = Config::load(path)?;
    mtp_transport::Secret::parse(&fs::read_to_string(&c.secret_file)?)?;
    let _ = mtp_transport::server_tls(&c.server_cert, &c.server_key, &c.client_ca)?;
    Registry::load(&c.registry_file)?;
    Ok(c)
}
