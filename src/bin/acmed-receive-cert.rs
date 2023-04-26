use std::{
    collections::HashMap,
    fs::{remove_file, File},
    io::{stdin, BufReader, Write},
    net::IpAddr,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
};

use acmed_hook_ssh::Payload;
use anyhow::{bail, Context, Result};
use openssl::{
    asn1::{Asn1Time, Asn1TimeRef},
    pkey::{PKey, Private},
    stack::{Stack, StackRef},
    string::{OpensslString, OpensslStringRef},
    x509::{store::X509StoreBuilder, X509Ref, X509StoreContext, X509},
};
use serde::Deserialize;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Deserialize)]
struct Config {
    #[serde(with = "serde_yaml::with::singleton_map_recursive")]
    certificates: HashMap<String, CertificateConfig>,
    target: PathBuf,
}

#[derive(Deserialize, Default, Clone)]
struct CertificateConfig {
    sans: Vec<SubjectAlternativeName>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
enum SubjectAlternativeName {
    Email(String),
    DnsName(String),
    Uri(String),
    IpAddr(IpAddr),
}

fn main() -> Result<()> {
    let config_file =
        File::open("/etc/acmed-receive-cert.yaml").context("Couldn't open config file!")?;
    let config: Config =
        serde_yaml::from_reader(config_file).context("Couldn't parse config file!")?;

    let datetime = OffsetDateTime::now_utc();

    let (payload, certificate, chain) = load_payload().context("Couldn't load payload!")?;

    let name = extract_cert_name(&certificate).context("Couldn't load certificate name!")?;

    let certificate_config = config
        .certificates
        .get(&name.to_string())
        .cloned()
        .unwrap_or_default();

    check_system_trust(&certificate, &chain)
        .context("Error verifying certificate against system store!")?;

    check_sans(&certificate, &name, &certificate_config).context("Error verifying SANs!")?;

    check_validity_period(
        &certificate,
        Asn1Time::from_unix(datetime.unix_timestamp())
            .context("Couldn't generate ASN.1 timestamp from current unix timestamp!")?
            .as_ref(),
    )
    .context("Certificate is not valid right now!")?;

    store_payload(payload, &config, name, datetime).context("Failed to store payload!")?;

    Ok(())
}

fn load_payload() -> Result<(Payload, X509, Stack<X509>)> {
    let reader = BufReader::new(stdin());
    let payload: Payload =
        serde_json::from_reader(reader).context("Failed to load and parse payload from stdin!")?;

    let privkey = PKey::private_key_from_pem(payload.key.as_bytes())
        .context("Failed to parse private key from PEM!")?;

    let chain = X509::stack_from_pem(payload.certificate.as_bytes())
        .context("Failed to load certificate chain!")?;

    let mut chain_stack = Stack::new().context("Failed to initialize stack!")?;

    for cert in chain {
        chain_stack
            .push(cert)
            .context("Failed to push certificate onto stack!")?;
    }

    let certificate = select_cert_from_chain_using_privkey(privkey, &chain_stack)
        .context("Failed to select cert from chain using private key!")?;

    Ok((payload, certificate, chain_stack))
}

fn select_cert_from_chain_using_privkey(
    key: PKey<Private>,
    chain: &StackRef<X509>,
) -> Result<X509> {
    let mut certificate = None;
    for certificate_candidate in chain {
        let pubkey = certificate_candidate
            .public_key()
            .context("Couldn't find public key for a certificate in the chain!")?;
        if key.public_eq(&pubkey) {
            certificate = Some(certificate_candidate.to_owned());
        }
    }

    let certificate =
        certificate.context("Couldn't find certificate matching private key in fullchain")?;
    Ok(certificate)
}

fn extract_cert_name(certificate: &X509Ref) -> Result<OpensslString> {
    certificate
        .subject_name()
        .entries()
        .next()
        .context("Couldn't get subject name from certificate")?
        .data()
        .as_utf8()
        .context("Failed to get utf-8 representation of certificate name")
}

fn check_system_trust(certificate: &X509Ref, chain: &StackRef<X509>) -> Result<()> {
    if !openssl_probe::try_init_ssl_cert_env_vars() {
        bail!("Couldn't find CA certificates on the system!");
    }

    let mut store_builder =
        X509StoreBuilder::new().context("Failed to create new X509StoreBuilder!")?;
    store_builder
        .set_default_paths()
        .context("Failed to seed X509Store with system certificates!")?;
    let store = store_builder.build();

    let mut store_context =
        X509StoreContext::new().context("Failed to create new X509StoreContext!")?;
    if !store_context
        .init(&store, certificate, chain, |context| context.verify_cert())
        .context("Error during verification of certificate against local trust store!")?
    {
        bail!("Certificate isn't valid under the local trust store!");
    }

    Ok(())
}

fn check_sans(
    certificate: &X509Ref,
    name: &OpensslStringRef,
    config: &CertificateConfig,
) -> Result<()> {
    for wanted_san in &config.sans {
        if !certificate
            .subject_alt_names()
            .context("Certificate does not contain alt names!")?
            .iter()
            .any(|contained_san| match &wanted_san {
                SubjectAlternativeName::Email(wanted_email) => contained_san
                    .email()
                    .filter(|contained_email| contained_email.eq(wanted_email))
                    .is_some(),
                SubjectAlternativeName::DnsName(wanted_dns_name) => contained_san
                    .dnsname()
                    .filter(|contained_dns_name| contained_dns_name.eq(wanted_dns_name))
                    .is_some(),
                SubjectAlternativeName::Uri(wanted_uri) => contained_san
                    .uri()
                    .filter(|contained_uri| contained_uri.eq(wanted_uri))
                    .is_some(),
                SubjectAlternativeName::IpAddr(wanted_ip) => contained_san
                    .ipaddress()
                    .filter(|contained_ip| match wanted_ip {
                        IpAddr::V4(wanted_ip) => contained_ip.eq(&wanted_ip.octets()),
                        IpAddr::V6(wanted_ip) => contained_ip.eq(&wanted_ip.octets()),
                    })
                    .is_some(),
            })
        {
            bail!(
                "Couldn't find wanted SAN {:?} in certificate for name {}",
                wanted_san,
                name
            );
        }
    }

    Ok(())
}

fn check_validity_period(certificate: &X509Ref, time: &Asn1TimeRef) -> Result<()> {
    if certificate.not_before() > time {
        bail!("Certificate isn't valid yet!");
    }

    if certificate.not_after() < time {
        bail!("Certificate has expired!");
    }

    Ok(())
}

fn store_payload(
    payload: Payload,
    config: &Config,
    name: OpensslString,
    datetime: OffsetDateTime,
) -> Result<()> {
    let datetime_formatted = datetime
        .format(&Rfc3339)
        .context("Failed to format current time according to RFC3339!")?;

    store_file(
        payload.certificate,
        "crt",
        &name,
        &datetime_formatted,
        &config.target,
    )
    .context("Failed to store certificate!")?;
    store_file(
        payload.key,
        "pk",
        &name,
        &datetime_formatted,
        &config.target,
    )
    .context("Failed to store pirvate key!")?;

    Ok(())
}

fn store_file(
    content: String,
    kind: &str,
    name: &OpensslStringRef,
    datetime: &str,
    base: &Path,
) -> Result<()> {
    let mut file_path = PathBuf::from(base);
    file_path.push(format!("{name}_{datetime}.{kind}.pem"));
    let mut link_path = PathBuf::from(base);
    link_path.push(format!("{name}.{kind}.pem"));
    if let Ok(true) = link_path.try_exists() {
        remove_file(&link_path).context("Failed to remove old symlink!")?;
    }
    let mut file = File::create(&file_path).context("Failed to create new file!")?;
    file.write_all(content.as_bytes())
        .context("Failed to write payload to file!")?;
    symlink(file_path, link_path).context("Failed to link to newest payload!")?;
    Ok(())
}
