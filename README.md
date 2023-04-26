# `acmed-hook-ssh`

`acmed-hook-ssh` is hook program for
[`acmed`](https://github.com/breard-r/acmed) for distributing certificates from
a central `acmed` instance to other hosts that actually end up using them.

## Installation

To be determined!

## Usage

`acmed-hook-ssh` consists of two parts:
 - `acmed-send-cert`, which is supposed to be called from the host running
   `acmed`.
 - `acmed-receive-cert`, which is supposed to be running on the host actually
   using the certificate.

In it's essence, `acmed-hook-ssh` works by connecting to a target host via ssh
and transferring the certificate chain and private key encoded as a json blob.

### `acmed-send-cert`

```text
Usage: acmed-send-cert --certificate <CERTIFICATE> --key <KEY> --user <USER> --host <HOST>

Options:
      --certificate <CERTIFICATE>  Path to full certificate chain
      --key <KEY>                  Path to private key
      --user <USER>                User to connect as for SSH
      --host <HOST>                DNS name of host to connect to with SSH
  -h, --help                       Print help
  -V, --version                    Print version
```

`acmed-send-cert` connects to a host as identified by the DNS name passed in
`--host`. It uses happy eyeballs to use either IPv6 or IPv4, depending on
availability. It then verifies that the fingerprint presented by the server
matches the fingerprint provided in the SSHFP record for the host, which is
fetched while validating DNSSEC. After all of this was successful, it runs
`acmed-receive-cert` on the remote host, and feeds the certificate and key
encoded as a json payload to the remote process via it's stdin. After receiving
info that the payload was stored successfully, it locally deletes the private
key, so that the central instance can't use the certificate itself anymore.

### `acmed-receive-cert`

This is running on the remote host, and receives the certificate and private key
via its stdin stream. After parsing the JSON payload, it parses the two pem
sections contained, tries to find the certificate matching the private key, and
validates the certificate against the system trust store. In addition to that,
it'll also check what required SANs are configured for the certificate based on
the CN as the identifier, and that the certificate is currently valid and not
expired yet.

`acmed-receive-cert` expects to find a configuration under
`/etc/acmed-receive-cert.yaml`, containing the following content:

```yaml
target: '/var/ssl'
certificates:
  example.com:
    sans:
      - dns_name: "example.com"
      - dns_name: "*.example.com"
```

To ensure that these checks are actually being run, the SSH key given to
`acmed-send-cert` must have `acmed-receive-cert` set as a forced command in the
`authorized_keys` file.

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[AGPL-3.0-only](https://choosealicense.com/licenses/agpl-3.0/)
