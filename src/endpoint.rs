//! Choosing which of a server's endpoints to open a session on.

use crate::connection::{Credentials, Security};
use crate::error::Error;
use opcua::client::prelude::{MessageSecurityMode, SecurityPolicy};

/// One endpoint as the server offers it, in the terms the choice needs.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Offer {
    pub(crate) policy: SecurityPolicy,
    pub(crate) mode: MessageSecurityMode,
    pub(crate) anonymous: bool,
    pub(crate) user_name: bool,
    pub(crate) password_protected: bool,
}

impl Offer {
    /// Builds an offer from the endpoint's policy and its user token policies,
    /// each given as its kind and the security policy URI that protects it.
    pub(crate) fn new<'a>(
        policy_uri: &str,
        mode: MessageSecurityMode,
        tokens: impl Iterator<Item = (Token, &'a str)>,
    ) -> Self {
        let policy = SecurityPolicy::from_uri(policy_uri);
        let mut offer = Offer {
            policy,
            mode,
            anonymous: false,
            user_name: false,
            password_protected: false,
        };
        for (token, token_policy_uri) in tokens {
            match token {
                Token::Anonymous => offer.anonymous = true,
                Token::UserName => {
                    offer.user_name = true;
                    let protecting = if token_policy_uri.is_empty() {
                        policy
                    } else {
                        SecurityPolicy::from_uri(token_policy_uri)
                    };
                    offer.password_protected |= strength(protecting) > 0;
                }
                Token::Other => {}
            }
        }
        offer
    }

    /// How the endpoint reads in a message, for example `SignAndEncrypt Basic256Sha256`.
    pub(crate) fn label(&self) -> String {
        label(self.policy, self.mode)
    }

    fn plain(&self) -> bool {
        self.mode == MessageSecurityMode::None && self.policy == SecurityPolicy::None
    }

    fn secure(&self) -> bool {
        self.mode != MessageSecurityMode::None && strength(self.policy) > 0
    }
}

/// The kind of a user token policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Token {
    Anonymous,
    UserName,
    Other,
}

/// How a policy and mode read in a message.
pub(crate) fn label(policy: SecurityPolicy, mode: MessageSecurityMode) -> String {
    match mode {
        MessageSecurityMode::Sign => format!("Sign {}", policy.to_str()),
        MessageSecurityMode::SignAndEncrypt => format!("SignAndEncrypt {}", policy.to_str()),
        _ => "None".to_string(),
    }
}

fn strength(policy: SecurityPolicy) -> u8 {
    match policy {
        SecurityPolicy::Aes256Sha256RsaPss => 5,
        SecurityPolicy::Aes128Sha256RsaOaep => 4,
        SecurityPolicy::Basic256Sha256 => 3,
        SecurityPolicy::Basic256 => 2,
        SecurityPolicy::Basic128Rsa15 => 1,
        _ => 0,
    }
}

fn mode_rank(mode: MessageSecurityMode) -> u8 {
    match mode {
        MessageSecurityMode::SignAndEncrypt => 2,
        MessageSecurityMode::Sign => 1,
        _ => 0,
    }
}

/// Picks the offer to connect to, or says in plain words why none fits.
pub(crate) fn choose(
    endpoint: &str,
    offers: &[Offer],
    wanted: Security,
    credentials: &Credentials,
) -> Result<usize, Error> {
    let asked: Vec<usize> = offers
        .iter()
        .enumerate()
        .filter(|(_, offer)| match wanted {
            Security::None => offer.plain(),
            Security::Sign(policy) => {
                offer.mode == MessageSecurityMode::Sign && offer.policy == policy
            }
            Security::SignAndEncrypt(policy) => {
                offer.mode == MessageSecurityMode::SignAndEncrypt && offer.policy == policy
            }
            Security::Encrypted => {
                offer.mode == MessageSecurityMode::SignAndEncrypt && offer.secure()
            }
            Security::Auto => offer.plain() || offer.secure(),
        })
        .map(|(index, _)| index)
        .collect();

    if asked.is_empty() {
        return Err(Error::NoMatchingSecurity {
            endpoint: endpoint.to_string(),
            offered: offered(offers),
        });
    }

    let fits = |offer: &Offer| match credentials {
        Credentials::Anonymous => offer.anonymous,
        Credentials::UserName { .. } => {
            offer.user_name
                && (offer.mode == MessageSecurityMode::SignAndEncrypt || offer.password_protected)
        }
    };
    let preference = |offer: &Offer| {
        let plain_first = wanted == Security::Auto && offer.plain();
        (plain_first, mode_rank(offer.mode), strength(offer.policy))
    };

    let chosen = asked
        .iter()
        .copied()
        .filter(|&index| fits(&offers[index]))
        .max_by_key(|&index| preference(&offers[index]));

    chosen.ok_or_else(|| match credentials {
        Credentials::Anonymous => Error::UserRequired {
            endpoint: endpoint.to_string(),
        },
        Credentials::UserName { .. } if asked.iter().any(|&index| offers[index].user_name) => {
            Error::InsecureCredentials
        }
        Credentials::UserName { .. } => Error::UserNotAccepted {
            endpoint: endpoint.to_string(),
        },
    })
}

fn offered(offers: &[Offer]) -> String {
    let mut labels: Vec<String> = offers.iter().map(Offer::label).collect();
    labels.dedup();
    if labels.is_empty() {
        "nothing".to_string()
    } else {
        labels.join(", ")
    }
}

/// The certificate's thumbprint as servers and TIA Portal show it, in upper-case hex.
pub(crate) fn thumbprint(der: &[u8]) -> Option<String> {
    if der.is_empty() {
        return None;
    }
    opcua::crypto::X509::from_der(der).ok().map(|certificate| {
        certificate
            .thumbprint()
            .as_hex_string()
            .to_ascii_uppercase()
    })
}

/// Refuses a server certificate that is not the one trusted before.
///
/// Only a secure endpoint is checked: without security the certificate plays no part.
pub(crate) fn check_trusted(
    endpoint: &str,
    trusted: Option<&str>,
    seen: Option<&str>,
    secure: bool,
) -> Result<(), Error> {
    let Some(trusted) = trusted.filter(|_| secure) else {
        return Ok(());
    };
    match seen {
        Some(seen) if seen.eq_ignore_ascii_case(trusted) => Ok(()),
        _ => Err(Error::ServerCertificateChanged {
            endpoint: endpoint.to_string(),
            seen: seen.unwrap_or("none").to_string(),
            trusted: trusted.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "opc.tcp://192.168.201.2:4840";

    fn offer(policy: SecurityPolicy, mode: MessageSecurityMode, tokens: &[Token]) -> Offer {
        Offer::new(
            policy.to_uri(),
            mode,
            tokens.iter().map(|token| (*token, "")),
        )
    }

    fn plain(tokens: &[Token]) -> Offer {
        offer(SecurityPolicy::None, MessageSecurityMode::None, tokens)
    }

    fn encrypted(policy: SecurityPolicy, tokens: &[Token]) -> Offer {
        offer(policy, MessageSecurityMode::SignAndEncrypt, tokens)
    }

    fn user() -> Credentials {
        Credentials::user_name("operator", "secret")
    }

    #[test]
    fn auto_keeps_the_plain_endpoint_while_the_server_offers_one() {
        let offers = [
            encrypted(SecurityPolicy::Basic256Sha256, &[Token::Anonymous]),
            plain(&[Token::Anonymous]),
        ];
        assert_eq!(
            choose(URL, &offers, Security::Auto, &Credentials::Anonymous).unwrap(),
            1
        );
    }

    #[test]
    fn auto_takes_the_strongest_encryption_once_the_plain_endpoint_is_gone() {
        let offers = [
            offer(
                SecurityPolicy::Basic256Sha256,
                MessageSecurityMode::Sign,
                &[Token::Anonymous],
            ),
            encrypted(SecurityPolicy::Basic256Sha256, &[Token::Anonymous]),
            encrypted(SecurityPolicy::Aes256Sha256RsaPss, &[Token::Anonymous]),
        ];
        assert_eq!(
            choose(URL, &offers, Security::Auto, &Credentials::Anonymous).unwrap(),
            2
        );
        assert_eq!(
            choose(URL, &offers, Security::Encrypted, &Credentials::Anonymous).unwrap(),
            2
        );
    }

    #[test]
    fn a_mode_the_server_does_not_offer_lists_what_it_offers() {
        let offers = [encrypted(
            SecurityPolicy::Basic256Sha256,
            &[Token::Anonymous],
        )];
        match choose(URL, &offers, Security::None, &Credentials::Anonymous) {
            Err(Error::NoMatchingSecurity { offered, .. }) => {
                assert_eq!(offered, "SignAndEncrypt Basic256Sha256")
            }
            other => panic!("expected NoMatchingSecurity, got {other:?}"),
        }
    }

    #[test]
    fn a_server_without_guests_asks_for_a_user() {
        let offers = [plain(&[Token::UserName])];
        assert!(matches!(
            choose(URL, &offers, Security::Auto, &Credentials::Anonymous),
            Err(Error::UserRequired { .. })
        ));
    }

    #[test]
    fn a_password_is_sent_only_encrypted() {
        let clear = [plain(&[Token::UserName])];
        assert!(matches!(
            choose(URL, &clear, Security::Auto, &user()),
            Err(Error::InsecureCredentials)
        ));

        let protected_token = Offer::new(
            SecurityPolicy::None.to_uri(),
            MessageSecurityMode::None,
            [(Token::UserName, SecurityPolicy::Basic256Sha256.to_uri())].into_iter(),
        );
        assert_eq!(
            choose(URL, &[protected_token], Security::Auto, &user()).unwrap(),
            0
        );

        let channel = [encrypted(
            SecurityPolicy::Basic256Sha256,
            &[Token::UserName],
        )];
        assert_eq!(choose(URL, &channel, Security::Auto, &user()).unwrap(), 0);
    }

    #[test]
    fn a_server_that_takes_only_guests_refuses_a_user() {
        let offers = [encrypted(
            SecurityPolicy::Basic256Sha256,
            &[Token::Anonymous],
        )];
        assert!(matches!(
            choose(URL, &offers, Security::Auto, &user()),
            Err(Error::UserNotAccepted { .. })
        ));
    }

    #[test]
    fn only_a_secure_endpoint_checks_the_trusted_certificate() {
        assert!(check_trusted(URL, Some("AB"), Some("ab"), true).is_ok());
        assert!(check_trusted(URL, None, Some("CD"), true).is_ok());
        assert!(check_trusted(URL, Some("AB"), Some("CD"), false).is_ok());
        assert!(matches!(
            check_trusted(URL, Some("AB"), Some("CD"), true),
            Err(Error::ServerCertificateChanged { .. })
        ));
    }
}
