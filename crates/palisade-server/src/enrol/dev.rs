//! The development server path (#223, #334): a throwaway CA, files for the
//! server's TLS identity and agent CA bundle, an in-memory store with one
//! registration code, and the enrolment routes, ready to start.
//!
//! `palisade-server dev-pki <dir>` and the end-to-end tests use it. Nothing
//! here is fit for production: the root key lives in process memory and
//! every device is forgotten on restart.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use palisade_proto::comms::code::{self, Code, Pepper};
use palisade_proto::events::{DnsName, TenantId, Timestamp, Uuid7};
use palisade_proto::pki::{Clock, SystemClock};

use super::authority::{Authority, AuthorityError};
use super::store::{CodeRecord, MemoryStore, Published};
use super::{EnrolService, EnrolSettings};

/// A development tenant: fixed IDs so runs are easy to read.
pub const DEV_TENANT: &str = "019a0000-0000-7000-8000-0000000000aa";
/// The development group.
pub const DEV_GROUP: &str = "019a0000-0000-7000-8000-0000000000bb";

/// What [`DevServer::create`] wrote and holds.
pub struct DevServer {
    /// The enrolment service, for [`EnrolService::admin_routes`] and
    /// [`EnrolService::agent_routes`].
    pub service: Arc<EnrolService>,
    /// The store, to publish policy or revoke devices.
    pub store: Arc<MemoryStore>,
    /// The authority, to sign policy bundles.
    pub authority: Arc<Authority>,
    /// The registration code, to give the agent.
    pub code: Code,
    /// The CA pin agents are installed with: `sha256/<hex>` of the root key.
    pub ca_pin: String,
    /// The server certificate chain file (PEM).
    pub cert_file: PathBuf,
    /// The server key file (PEM, mode 0600 on Unix).
    pub key_file: PathBuf,
    /// The agent listener's client CA bundle (PEM).
    pub agent_ca_file: PathBuf,
    /// The root certificate (PEM), for clients that want it.
    pub root_file: PathBuf,
}

impl std::fmt::Debug for DevServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DevServer")
            .field("ca_pin", &self.ca_pin)
            .field("cert_file", &self.cert_file)
            .finish_non_exhaustive()
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn write(path: &Path, contents: &str, secret: bool) -> Result<(), AuthorityError> {
    std::fs::write(path, contents)
        .map_err(|e| AuthorityError(format!("cannot write {}: {e}", path.display())))?;
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| AuthorityError(format!("cannot restrict {}: {e}", path.display())))?;
    }
    #[cfg(not(unix))]
    let _ = secret;
    Ok(())
}

impl DevServer {
    /// Generates a hierarchy for `server_names`, writes the TLS files into
    /// `dir`, and builds the service with one registration code for the
    /// development tenant and group.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] if generation or a write fails.
    pub fn create(
        dir: &Path,
        server_names: &[DnsName],
        settings: EnrolSettings,
    ) -> Result<Self, AuthorityError> {
        Self::create_with_clock(dir, server_names, settings, Arc::new(SystemClock))
    }

    /// As [`Self::create`], with a clock.
    ///
    /// # Errors
    ///
    /// As [`Self::create`].
    pub fn create_with_clock(
        dir: &Path,
        server_names: &[DnsName],
        settings: EnrolSettings,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Result<Self, AuthorityError> {
        let now: Timestamp = clock.now();
        let dev = Authority::generate(now, server_names)?;
        std::fs::create_dir_all(dir)
            .map_err(|e| AuthorityError(format!("cannot create {}: {e}", dir.display())))?;
        let cert_file = dir.join("server.crt");
        let key_file = dir.join("server.key");
        let agent_ca_file = dir.join("agent-ca.crt");
        let root_file = dir.join("root.crt");
        let chain: String = dev
            .server_chain
            .iter()
            .map(|c| pem("CERTIFICATE", c))
            .collect();
        write(&cert_file, &chain, false)?;
        write(
            &key_file,
            &pem("PRIVATE KEY", dev.server_key.expose()),
            true,
        )?;
        write(
            &agent_ca_file,
            &pem("CERTIFICATE", dev.authority.issuing_der()),
            false,
        )?;
        write(
            &root_file,
            &pem("CERTIFICATE", dev.authority.root_der()),
            false,
        )?;

        let mut pepper_key = [0u8; 32];
        crate::tls::fill_random(&mut pepper_key).map_err(AuthorityError)?;
        let pepper = Pepper::new(&pepper_key);
        let code = code::generate(code::DEFAULT_LEN).map_err(|e| AuthorityError(e.to_string()))?;
        let tenant: Uuid7 = DEV_TENANT
            .parse()
            .map_err(|_| AuthorityError("bad development tenant".to_owned()))?;
        let group: Uuid7 = DEV_GROUP
            .parse()
            .map_err(|_| AuthorityError("bad development group".to_owned()))?;
        let store = Arc::new(MemoryStore::default());
        store.add_code(
            pepper.hash(&code),
            CodeRecord {
                tenant: TenantId(tenant),
                group,
                expires_at: None,
                max_uses: None,
                uses: 0,
                revoked: false,
                allowed_sources: Vec::new(),
                require_hardware_key: false,
            },
        );
        let ca_pin = format!("sha256/{}", dev.authority.root_key().spki_sha256());
        let authority = Arc::new(dev.authority);
        let service = EnrolService::new(store.clone(), authority.clone(), pepper, clock, settings);
        Ok(Self {
            service,
            store,
            authority,
            code,
            ca_pin,
            cert_file,
            key_file,
            agent_ca_file,
            root_file,
        })
    }

    /// Signs `bundle` and publishes it for the development group.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] if the bundle is not canonical.
    pub fn publish(&self, bundle: &[u8], version: u64) -> Result<(), AuthorityError> {
        let envelope = self.authority.sign_policy(bundle)?;
        let tenant: Uuid7 = DEV_TENANT
            .parse()
            .map_err(|_| AuthorityError("bad development tenant".to_owned()))?;
        let group: Uuid7 = DEV_GROUP
            .parse()
            .map_err(|_| AuthorityError("bad development group".to_owned()))?;
        self.store.publish(
            TenantId(tenant),
            group,
            Published {
                version,
                bundle_hash: palisade_proto::policy_bundle::content_hash(bundle),
                envelope: Arc::from(envelope),
            },
        );
        Ok(())
    }
}
