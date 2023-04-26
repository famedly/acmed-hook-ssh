use std::{io::Write, path::PathBuf, sync::Arc};

use acmed_hook_ssh::Payload;
use anyhow::{bail, Context};
use async_trait::async_trait;
use base64::Engine;
use clap::Parser;
use once_cell::sync::Lazy;
use russh::client::{connect_stream, Config, Handler};
use russh_keys::key::PublicKey;
use tokio::fs::read_to_string;
use trust_dns_client::rr::rdata::sshfp::{Algorithm, FingerprintType};
use trust_dns_resolver::{AsyncResolver, TokioAsyncResolver};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to full certificate chain
    #[arg(long)]
    certificate: PathBuf,
    /// Path to private key
    #[arg(long)]
    key: PathBuf,
    /// User to connect as for SSH
    #[arg(long)]
    user: String,
    /// DNS name of host to connect to with SSH
    #[arg(long)]
    host: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let payload = Payload {
        certificate: read_to_string(cli.certificate)
            .await
            .context("Failed to read certificate file.")?,
        key: read_to_string(&cli.key)
            .await
            .context("Failed to read private key file.")?,
    };

    send_payload_via_ssh(payload, cli.user, cli.host)
        .await
        .context("Failed to send certificate and key via ssh.")?;

    std::fs::remove_file(cli.key).context("Failed to delete private key file.")?;

    Ok(())
}

async fn send_payload_via_ssh(payload: Payload, user: String, host: String) -> anyhow::Result<()> {
    let config = Arc::new(Config::default());

    let handler = SshfpDnssecHandler {
        hostname: host.clone(),
    };

    let mut agent = russh_keys::agent::client::AgentClient::connect_env()
        .await
        .context("Couldn't connect to SSH agent.")?;
    let stream = Box::pin(
        happy_eyeballs::tokio::connect(format!("{host}:22"))
            .await
            .context("Couldn't connect TCP socket via happy_eyeballs")?,
    );

    let mut session = connect_stream(config, stream, handler)
        .await
        .context("Couldn't connect to ssh via established TCP stream")?;
    let mut authenticated = false;
    for key in agent
        .request_identities()
        .await
        .context("Couldn't list identities available on ssh agent")?
    {
        let (returned_agent, did_authenticate) =
            session.authenticate_future(&user, key, agent).await;
        agent = returned_agent;
        if did_authenticate.context("Couldn't check whether authentication was successful")? {
            authenticated = true;
            break;
        }
    }
    if !authenticated
        && !session
            .authenticate_none(user)
            .await
            .context("Couldn't try authentication without credentials")?
    {
        anyhow::bail!("Could't authenticate!")
    }

    let mut channel = session
        .channel_open_session()
        .await
        .context("Couldn't open new channel")?;
    // Request execution of `acmed-receive-cert`
    channel
        .exec(true, "acmed-receive-cert")
        .await
        .context("Couldn't send exec message via ssh")?;
    // Send payload to remote program
    channel
        .data(serde_json::to_vec(&payload)?.as_ref())
        .await
        .context("Couldn't send json payload via ssh")?;
    // Request closing of channel
    channel
        .close()
        .await
        .context("Couldn't close ssh channel")?;

    let mut failed = false;

    // Read ssh messages out of the channel until it's actually closed, printing all data send back
    // and failing if the execution fails on the remote host
    while let Some(msg) = channel.wait().await {
        match msg {
            russh::ChannelMsg::Data { data } => std::io::stdout().write_all(&data)?,
            russh::ChannelMsg::ExtendedData { data, .. } => std::io::stdout().write_all(&data)?,
            russh::ChannelMsg::ExitStatus { exit_status } => {
                if exit_status != 0 {
                    failed = true;
                }
            }
            _ => {}
        }
    }
    if failed {
        bail!("Execution on of `acmed-receive-cert` on the server failed");
    }

    Ok(())
}

struct SshfpDnssecHandler {
    hostname: String,
}

#[async_trait]
impl Handler for SshfpDnssecHandler {
    type Error = anyhow::Error;
    async fn check_server_key(
        self,
        server_public_key: &PublicKey,
    ) -> Result<(Self, bool), Self::Error> {
        for sshfp in RESOLVER
            .lookup(&self.hostname, trust_dns_client::rr::RecordType::SSHFP)
            .await?
        {
            if let Some(sshfp) = sshfp.as_sshfp() {
                // Only ed25519 with SHA2-256 is supported by russh
                if sshfp.algorithm() != Algorithm::Ed25519
                    || sshfp.fingerprint_type() != FingerprintType::SHA256
                {
                    continue;
                }
                let sshfp_decoded = sshfp.fingerprint();
                let key_to_check_fingerprint_decoded =
                    base64::engine::general_purpose::STANDARD_NO_PAD
                        .decode(server_public_key.fingerprint())
                        .context("failed to decode fingerprint generated by russh")?;
                if sshfp_decoded == key_to_check_fingerprint_decoded {
                    return Ok((self, true));
                }
            }
        }
        Ok((self, false))
    }
}

static RESOLVER: Lazy<TokioAsyncResolver> = Lazy::new(|| {
    AsyncResolver::tokio_from_system_conf()
        .expect("Couldn't construct tokio resolver from system config")
});
