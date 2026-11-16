//! Opening a client session against an endpoint.

use crate::endpoint::{check_trusted, choose, thumbprint, Offer, Token};
use crate::error::{Error, Result};
use opcua::client::prelude::*;
use opcua::sync::RwLock;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Message security applied to a session.
///
/// [`Security::None`] leaves traffic in plaintext. The other two sign, and in
/// the encrypting case also encrypt, using the named policy.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum Security {
    /// No signing and no encryption. Anyone on the network can read the traffic.
    None,
    /// Messages are signed but sent in the clear.
    Sign(SecurityPolicy),
    /// Messages are signed and encrypted.
    SignAndEncrypt(SecurityPolicy),
    /// Whatever the server offers: its plain endpoint while it has one, otherwise
    /// its strongest one. Follows the server when its security is changed.
    Auto,
    /// The strongest signed and encrypted endpoint the server offers.
    Encrypted,
}

impl Security {
    /// Returns the security policy this mode uses.
    ///
    /// [`Auto`](Security::Auto) and [`Encrypted`](Security::Encrypted) have none
    /// until they are matched against the server's endpoints, and return
    /// [`SecurityPolicy::Unknown`].
    pub fn policy(&self) -> SecurityPolicy {
        match self {
            Security::None => SecurityPolicy::None,
            Security::Sign(policy) | Security::SignAndEncrypt(policy) => *policy,
            Security::Auto | Security::Encrypted => SecurityPolicy::Unknown,
        }
    }

    /// Returns the message security mode this maps to on the wire.
    ///
    /// [`Auto`](Security::Auto) has none until it is matched against the
    /// server's endpoints, and returns [`MessageSecurityMode::Invalid`].
    pub fn mode(&self) -> MessageSecurityMode {
        match self {
            Security::None => MessageSecurityMode::None,
            Security::Sign(_) => MessageSecurityMode::Sign,
            Security::SignAndEncrypt(_) | Security::Encrypted => {
                MessageSecurityMode::SignAndEncrypt
            }
            Security::Auto => MessageSecurityMode::Invalid,
        }
    }

    /// Whether traffic is sure to be encrypted, and so safe to carry a password.
    ///
    /// [`Auto`](Security::Auto) is not: it depends on what the server offers.
    pub fn is_encrypted(&self) -> bool {
        matches!(self, Security::SignAndEncrypt(_) | Security::Encrypted)
    }
}

/// What a session was opened with, for showing next to the server's own diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConnectionInfo {
    /// The id the server gave the session, once it is known.
    pub session_id: Option<String>,
    /// The security in use, for example `None` or `SignAndEncrypt Basic256Sha256`.
    pub security: String,
    /// Thumbprint of the server's certificate, as TIA Portal shows it.
    pub server_certificate: Option<String>,
    /// The user logged in, or `None` for a guest.
    pub user: Option<String>,
}

/// This client's own certificate, as the server sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClientCertificate {
    /// The certificate in DER form, for importing into a server's trusted clients.
    pub der: Vec<u8>,
    /// Its thumbprint, as TIA Portal shows it.
    pub thumbprint: String,
}

/// Reads the client certificate kept in `pki_dir`, if one was made already.
///
/// The first connection makes it when [`ConnectOptions::create_sample_keypair`] is on.
pub fn client_certificate(pki_dir: &Path) -> Option<ClientCertificate> {
    let der = std::fs::read(pki_dir.join("own").join("cert.der")).ok()?;
    let thumbprint = crate::endpoint::thumbprint(&der)?;
    Some(ClientCertificate { der, thumbprint })
}

/// How the client identifies itself to the server.
///
/// The `Debug` implementation redacts the password so it cannot reach a log by
/// accident.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Credentials {
    /// No user identity; the server decides what an anonymous client may do.
    Anonymous,
    /// A user name and password, sent only over an encrypted channel.
    UserName {
        /// The user name.
        user: String,
        /// The password. Never appears in `Debug` output.
        password: String,
        /// The server's identifier for its user-name token policy.
        ///
        /// Servers advertise this in their endpoint description and reject a
        /// value they do not recognise. The default suits most servers; the
        /// `opcua` crate's own server uses `userpass_rsa_15` under encryption.
        policy_id: String,
    },
}

impl Credentials {
    /// Default policy identifier used for user-name authentication.
    pub const DEFAULT_USER_NAME_POLICY_ID: &'static str = "username";

    /// Creates user-name credentials with the default policy identifier.
    pub fn user_name(user: impl Into<String>, password: impl Into<String>) -> Self {
        Credentials::UserName {
            user: user.into(),
            password: password.into(),
            policy_id: Self::DEFAULT_USER_NAME_POLICY_ID.to_string(),
        }
    }

    /// Overrides the policy identifier sent with user-name credentials.
    ///
    /// A no-op on [`Credentials::Anonymous`].
    pub fn policy_id(mut self, id: impl Into<String>) -> Self {
        if let Credentials::UserName { policy_id, .. } = &mut self {
            *policy_id = id.into();
        }
        self
    }

    /// Converts to the `opcua` identity token.
    fn identity_token(&self) -> IdentityToken {
        match self {
            Credentials::Anonymous => IdentityToken::Anonymous,
            Credentials::UserName { user, password, .. } => {
                IdentityToken::UserName(user.clone(), password.clone())
            }
        }
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Credentials::Anonymous => f.write_str("Anonymous"),
            Credentials::UserName {
                user, policy_id, ..
            } => f
                .debug_struct("UserName")
                .field("user", user)
                .field("password", &"<redacted>")
                .field("policy_id", policy_id)
                .finish(),
        }
    }
}

/// Options for opening a client session.
///
/// [`Default`] signs and encrypts with `Basic256Sha256` and rejects untrusted
/// server certificates. Use [`insecure`](Self::insecure) for a plaintext server
/// on an isolated network; naming it keeps the choice visible in your source.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConnectOptions {
    /// Application name presented to the server during the handshake.
    pub application_name: String,
    /// Application URI presented to the server. Must match the certificate's URI.
    pub application_uri: String,
    /// Session name the server shows in its session diagnostics, for example in
    /// TIA Portal's list of OPC UA sessions of an S7-1500.
    pub session_name: String,
    /// Session keep-alive timeout in milliseconds.
    ///
    /// Bounds how long the server holds an abandoned session, and with it any
    /// monitored items that still count against the server's budget.
    pub session_timeout_ms: u32,
    /// Whether to generate a self-signed keypair if none exists on disk.
    pub create_sample_keypair: bool,
    /// Whether to accept any server certificate without validation.
    pub trust_server_certs: bool,
    /// Whether to verify server certificates against the trust store.
    pub verify_server_certs: bool,
    /// Thumbprint of the only server certificate to accept on a secure endpoint,
    /// for example the one seen at an earlier connection.
    ///
    /// When set, any other certificate fails with [`Error::ServerCertificateChanged`]
    /// and this one is trusted without the trust store.
    pub server_certificate: Option<String>,
    /// Folder for this client's own certificate and key and its trust store.
    ///
    /// `None` uses `pki` under the current directory.
    pub pki_dir: Option<PathBuf>,
    /// Message security applied to the session.
    pub security: Security,
    /// How the client identifies itself.
    pub credentials: Credentials,
    /// How many times the underlying `opcua` session retries a dropped
    /// connection before giving up, or `-1` for no limit.
    ///
    /// This governs the built-in reconnect loop `Collector::run` relies on:
    /// when the connection drops, `opcua` reconnects and re-attaches existing
    /// subscriptions on its own, without this crate's involvement. A finite
    /// limit bounds how long `CollectorHandle::stop` can take to take effect
    /// while a reconnect is in progress, at the cost of eventually giving up
    /// on a long outage (`Collector`'s own restart loop then takes over).
    pub session_retry_limit: i32,
    /// Delay between reconnect attempts.
    ///
    /// Floored at 500ms by the underlying `opcua` crate.
    pub session_retry_interval: std::time::Duration,
    /// How long [`connect`] waits for the server to accept a TCP connection.
    ///
    /// The `opcua` client connects without a time limit: where the network
    /// silently drops the attempt, one connect can block for about two
    /// minutes. A plain TCP check with this limit comes first.
    pub reach_timeout: std::time::Duration,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            application_name: "opcua-tag-browser".to_string(),
            application_uri: "urn:opcua-tag-browser".to_string(),
            session_name: "opcua-tag-browser".to_string(),
            session_timeout_ms: 30_000,
            create_sample_keypair: true,
            trust_server_certs: false,
            verify_server_certs: true,
            server_certificate: None,
            pki_dir: None,
            security: Security::SignAndEncrypt(SecurityPolicy::Basic256Sha256),
            credentials: Credentials::Anonymous,
            session_retry_limit: 20,
            session_retry_interval: std::time::Duration::from_secs(2),
            reach_timeout: std::time::Duration::from_secs(3),
        }
    }
}

impl ConnectOptions {
    /// Connects with no encryption or authentication, trusting any certificate.
    ///
    /// Appropriate on an isolated machine network with no PKI. Anyone able to
    /// see the traffic can read and forge it.
    ///
    /// ```
    /// use opcua_tag_browser::{ConnectOptions, Security};
    ///
    /// assert_eq!(ConnectOptions::insecure().security, Security::None);
    /// ```
    pub fn insecure() -> Self {
        Self {
            trust_server_certs: true,
            verify_server_certs: false,
            security: Security::None,
            credentials: Credentials::Anonymous,
            ..Self::default()
        }
    }

    /// Sets the application name.
    pub fn application_name(mut self, name: impl Into<String>) -> Self {
        self.application_name = name.into();
        self
    }

    /// Sets the application URI.
    pub fn application_uri(mut self, uri: impl Into<String>) -> Self {
        self.application_uri = uri.into();
        self
    }

    /// Sets the session name the server shows in its session diagnostics.
    pub fn session_name(mut self, name: impl Into<String>) -> Self {
        self.session_name = name.into();
        self
    }

    /// Accepts only this server certificate on a secure endpoint, by thumbprint.
    pub fn server_certificate(mut self, thumbprint: Option<String>) -> Self {
        self.server_certificate = thumbprint;
        self
    }

    /// Sets the folder for this client's own certificate, key and trust store.
    pub fn pki_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.pki_dir = Some(dir.into());
        self
    }

    /// Whether the library may trust the server certificate it is shown.
    ///
    /// A trusted thumbprint is checked here before connecting, so it then may.
    pub(crate) fn trusts_server(&self) -> (bool, bool) {
        if self.server_certificate.is_some() {
            (true, false)
        } else {
            (self.trust_server_certs, self.verify_server_certs)
        }
    }

    /// Sets the session keep-alive timeout in milliseconds.
    pub fn session_timeout_ms(mut self, ms: u32) -> Self {
        self.session_timeout_ms = ms;
        self
    }

    /// Sets the message security applied to the session.
    pub fn security(mut self, security: Security) -> Self {
        self.security = security;
        self
    }

    /// Authenticates with a user name and password.
    ///
    /// The password is only ever sent over an encrypted channel: with any other
    /// [`Security`], [`connect`] fails with [`Error::InsecureCredentials`]
    /// rather than transmitting it.
    pub fn user_name(mut self, user: impl Into<String>, password: impl Into<String>) -> Self {
        self.credentials = Credentials::user_name(user, password);
        self
    }

    /// Sets the credentials directly.
    pub fn credentials(mut self, credentials: Credentials) -> Self {
        self.credentials = credentials;
        self
    }

    /// Accepts any server certificate without validating it.
    pub fn trust_server_certs(mut self, yes: bool) -> Self {
        self.trust_server_certs = yes;
        self
    }

    /// Sets how many times a dropped connection is retried before giving up,
    /// or `-1` for no limit.
    ///
    /// Values below `-1` are clamped to `-1`: the underlying `opcua` crate
    /// panics on them rather than erroring, so this crate does not forward an
    /// invalid value.
    pub fn session_retry_limit(mut self, limit: i32) -> Self {
        self.session_retry_limit = limit.max(-1);
        self
    }

    /// Sets the delay between reconnect attempts. Floored at 500ms by the
    /// underlying `opcua` crate.
    pub fn session_retry_interval(mut self, interval: std::time::Duration) -> Self {
        self.session_retry_interval = interval;
        self
    }

    /// Sets how long [`connect`] waits for the server to accept a TCP connection.
    pub fn reach_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.reach_timeout = timeout;
        self
    }
}

pub(crate) const DEFAULT_PKI_DIR: &str = "pki";

pub(crate) fn own_certificate_for(pki_dir: &Path, application_uri: &str) {
    let cert = pki_dir.join("own").join("cert.der");
    let Ok(der) = std::fs::read(&cert) else {
        return;
    };
    let fits = opcua::crypto::X509::from_der(&der)
        .map(|certificate| {
            certificate
                .is_application_uri_valid(application_uri)
                .is_good()
        })
        .unwrap_or(false);
    if fits {
        return;
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let key = pki_dir.join("private").join("private.pem");
    for path in [cert, key] {
        let Some(name) = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
        else {
            continue;
        };
        let aside = path.with_file_name(format!("{name}.before-{stamp}"));
        if let Err(e) = std::fs::rename(&path, &aside) {
            if path.exists() {
                log::warn!("{}: not set aside ({e})", path.display());
            }
        }
    }
    log::warn!(
        "{}: the client certificate was made for another application URI; a new one is made for {application_uri} and the old one is kept beside it",
        pki_dir.display()
    );
}

pub(crate) fn key_readable_by_both_clients(pki_dir: &Path) {
    let key = pki_dir.join("private").join("private.pem");
    let Ok(bytes) = std::fs::read(&key) else {
        return;
    };
    if !bytes.contains(&b'\r') {
        return;
    }
    let fixed = String::from_utf8_lossy(&bytes)
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    if let Err(e) = std::fs::write(&key, fixed) {
        log::warn!(
            "{}: line ends not fixed ({e}); encrypted connections may fail",
            key.display()
        );
    }
}

/// Connects to an endpoint using the supplied options.
///
/// ```no_run
/// use opcua_tag_browser::{connect, ConnectOptions};
///
/// # fn main() -> opcua_tag_browser::Result<()> {
/// let session = connect("opc.tcp://192.168.201.0:8080", &ConnectOptions::insecure())?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns [`Error::InsecureCredentials`] if credentials were configured
/// without encryption, [`Error::ClientBuild`] if the options do not produce a
/// usable client, and [`Error::Connect`] if the handshake fails.
pub fn connect(endpoint_url: &str, options: &ConnectOptions) -> Result<Arc<RwLock<Session>>> {
    if !matches!(options.credentials, Credentials::Anonymous)
        && options.security != Security::Auto
        && !options.security.is_encrypted()
    {
        return Err(Error::InsecureCredentials);
    }

    let failed = |status: StatusCode| Error::Connect {
        endpoint: endpoint_url.to_string(),
        status,
    };
    if !reachable(endpoint_url, options.reach_timeout) {
        return Err(failed(StatusCode::BadNotConnected));
    }

    let pki_dir = options
        .pki_dir
        .as_deref()
        .unwrap_or(Path::new(DEFAULT_PKI_DIR));
    own_certificate_for(pki_dir, &options.application_uri);
    key_readable_by_both_clients(pki_dir);
    let (trust, verify) = options.trusts_server();
    let mut builder = ClientBuilder::new()
        .application_name(options.application_name.clone())
        .application_uri(options.application_uri.clone())
        .session_name(options.session_name.clone())
        .create_sample_keypair(options.create_sample_keypair)
        .trust_server_certs(trust)
        .verify_server_certs(verify)
        .session_timeout(options.session_timeout_ms)
        .session_retry_limit(options.session_retry_limit)
        .session_retry_interval(options.session_retry_interval.as_millis() as u32);
    if let Some(dir) = &options.pki_dir {
        builder = builder.pki_dir(dir.clone());
    }
    let mut client = builder
        .client()
        .ok_or_else(|| Error::ClientBuild("ClientBuilder returned no client".to_string()))?;

    let endpoints = client
        .get_server_endpoints_from_url(endpoint_url)
        .map_err(failed)?;
    let offers: Vec<Offer> = endpoints.iter().map(offer).collect();
    let index = choose(
        endpoint_url,
        &offers,
        options.security,
        &options.credentials,
    )?;
    let mut chosen = endpoints[index].clone();
    let seen = thumbprint(chosen.server_certificate.as_ref());
    check_trusted(
        endpoint_url,
        options.server_certificate.as_deref(),
        seen.as_deref(),
        offers[index].policy != SecurityPolicy::None,
    )?;
    chosen.endpoint_url = UAString::from(endpoint_url);

    log::debug!(
        "connecting to {} with {} as {:?}",
        endpoint_url,
        offers[index].label(),
        options.credentials
    );

    let session = client
        .connect_to_endpoint(chosen, options.credentials.identity_token())
        .map_err(failed)?;

    log::info!("connected to {}", endpoint_url);
    Ok(session)
}

fn offer(endpoint: &EndpointDescription) -> Offer {
    let tokens = endpoint.user_identity_tokens.as_deref().unwrap_or(&[]);
    Offer::new(
        endpoint.security_policy_uri.as_ref(),
        endpoint.security_mode,
        tokens.iter().map(|token| {
            let kind = match token.token_type {
                UserTokenType::Anonymous => Token::Anonymous,
                UserTokenType::UserName => Token::UserName,
                _ => Token::Other,
            };
            (kind, token.security_policy_uri.as_ref())
        }),
    )
}

/// Whether some address of the endpoint accepts a TCP connection in time.
///
/// An endpoint this cannot read is left to the `opcua` client to judge.
pub(crate) fn reachable(endpoint_url: &str, timeout: std::time::Duration) -> bool {
    use std::net::{TcpStream, ToSocketAddrs};

    let Some(rest) = endpoint_url.strip_prefix("opc.tcp://") else {
        return true;
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    let with_port = if authority
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        authority.to_string()
    } else {
        format!("{authority}:4840")
    };
    match with_port.to_socket_addrs() {
        Ok(addresses) => addresses
            .into_iter()
            .any(|address| TcpStream::connect_timeout(&address, timeout).is_ok()),
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_encrypted_and_verifies_certs() {
        let options = ConnectOptions::default();
        assert!(options.security.is_encrypted());
        assert!(!options.trust_server_certs);
        assert!(options.verify_server_certs);
    }

    #[test]
    fn insecure_is_plaintext_and_anonymous() {
        let options = ConnectOptions::insecure();
        assert_eq!(options.security, Security::None);
        assert_eq!(options.credentials, Credentials::Anonymous);
        assert!(!options.security.is_encrypted());
    }

    #[test]
    fn the_session_name_shown_by_the_server_can_be_set() {
        assert_eq!(ConnectOptions::insecure().session_name, "opcua-tag-browser");
        let named = ConnectOptions::insecure().session_name("SRT HMI machine-fano-0010 panel 1");
        assert_eq!(named.session_name, "SRT HMI machine-fano-0010 panel 1");
    }

    #[test]
    fn a_key_written_with_bare_carriage_returns_gets_plain_line_ends() {
        let pki = std::env::temp_dir().join(format!("otb-key-ends-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&pki);
        std::fs::create_dir_all(pki.join("private")).unwrap();
        let key = pki.join("private").join("private.pem");

        std::fs::write(
            &key,
            "-----BEGIN PRIVATE KEY-----\rAAAA\rBBBB\r-----END PRIVATE KEY-----\r",
        )
        .unwrap();
        key_readable_by_both_clients(&pki);
        assert_eq!(
            std::fs::read_to_string(&key).unwrap(),
            "-----BEGIN PRIVATE KEY-----\nAAAA\nBBBB\n-----END PRIVATE KEY-----\n"
        );

        std::fs::write(&key, "-----BEGIN PRIVATE KEY-----\r\nAAAA\r\n").unwrap();
        key_readable_by_both_clients(&pki);
        assert_eq!(
            std::fs::read_to_string(&key).unwrap(),
            "-----BEGIN PRIVATE KEY-----\nAAAA\n"
        );

        key_readable_by_both_clients(&pki.join("missing"));
        std::fs::remove_dir_all(&pki).unwrap();
    }

    #[test]
    fn a_certificate_made_for_another_application_uri_is_set_aside_once() {
        let pki = std::env::temp_dir().join(format!("otb-own-uri-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&pki);
        std::fs::create_dir_all(pki.join("own")).unwrap();
        std::fs::create_dir_all(pki.join("private")).unwrap();
        let made = |uri: &str| {
            let data = opcua::crypto::X509Data {
                key_size: 2048,
                common_name: "test".into(),
                organization: "test".into(),
                organizational_unit: "test".into(),
                country: "IT".into(),
                state: "MC".into(),
                alt_host_names: vec![uri.into(), "localhost".into()],
                certificate_duration_days: 30,
            };
            let (cert, _) = opcua::crypto::X509::cert_and_pkey(&data).unwrap();
            std::fs::write(pki.join("own").join("cert.der"), cert.to_der().unwrap()).unwrap();
            std::fs::write(pki.join("private").join("private.pem"), "key").unwrap();
        };

        made("urn:srt:hmi:machine-fano-0012:panel-1");
        own_certificate_for(&pki, "urn:srt:hmi:machine-fano-0012:panel-1");
        assert!(
            pki.join("own").join("cert.der").exists(),
            "a matching certificate stays"
        );
        assert!(pki.join("private").join("private.pem").exists());

        own_certificate_for(&pki, "urn:srt:hmi:machine-fano-0012:panel-2");
        assert!(
            !pki.join("own").join("cert.der").exists(),
            "the old one is set aside"
        );
        assert!(!pki.join("private").join("private.pem").exists());
        let kept = |dir: &str| {
            std::fs::read_dir(pki.join(dir))
                .unwrap()
                .flatten()
                .any(|entry| entry.file_name().to_string_lossy().contains(".before-"))
        };
        assert!(kept("own") && kept("private"), "and kept beside");

        own_certificate_for(&pki, "urn:anything");
        std::fs::remove_dir_all(&pki).unwrap();
    }

    #[test]
    fn debug_redacts_the_password() {
        let rendered = format!("{:?}", Credentials::user_name("collector", "hunter2"));
        assert!(rendered.contains("collector"));
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn credentials_without_encryption_are_refused() {
        let options = ConnectOptions::default()
            .security(Security::Sign(SecurityPolicy::Basic256Sha256))
            .user_name("collector", "hunter2");

        assert!(matches!(
            connect("opc.tcp://127.0.0.1:1", &options),
            Err(Error::InsecureCredentials)
        ));
    }

    #[test]
    fn security_maps_to_wire_modes() {
        assert_eq!(Security::None.mode(), MessageSecurityMode::None);
        assert_eq!(
            Security::Sign(SecurityPolicy::Basic256Sha256).mode(),
            MessageSecurityMode::Sign
        );
        assert_eq!(
            Security::SignAndEncrypt(SecurityPolicy::Basic256Sha256).policy(),
            SecurityPolicy::Basic256Sha256
        );
    }

    #[test]
    fn an_endpoint_that_never_answers_fails_within_the_reach_timeout() {
        let options =
            ConnectOptions::insecure().reach_timeout(std::time::Duration::from_millis(500));
        let started = std::time::Instant::now();
        let refused = connect("opc.tcp://192.0.2.1:4840/", &options);
        assert!(matches!(refused, Err(Error::Connect { .. })));
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
    }

    #[test]
    fn a_listening_endpoint_is_reachable() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(reachable(
            &format!("opc.tcp://127.0.0.1:{port}/"),
            std::time::Duration::from_secs(1)
        ));
        assert!(reachable(
            "http://not-opc",
            std::time::Duration::from_secs(1)
        ));
    }
}
