//! TOML-serializable validator configuration.

use commonware_codec::{Read as CodecRead, ReadExt};
use commonware_cryptography::{
    Signer,
    bls12381::{
        dkg,
        primitives::{group::Share, sharing::ModeVersion, variant::MinSig},
    },
    ed25519,
};
use commonware_deployer::aws::Hosts;
use commonware_p2p::{Ingress, authenticated::discovery::Bootstrapper};
use commonware_utils::{NZU32, from_hex};
use constantinople_primitives::{Account, Address};
use std::{collections::HashMap, net::SocketAddr, path::Path};

pub(crate) const fn default_max_propose_bytes() -> usize {
    4 * 1024 * 1024 // 4 MiB
}

pub(crate) const fn default_max_pool_bytes() -> usize {
    64 * 1024 * 1024 // 64 MiB
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ValidatorConfig {
    pub private_key: String,
    pub dkg_output: String,
    pub dkg_share: String,
    pub listen: String,
    pub genesis_leader: String,
    pub partition_prefix: String,
    pub num_validators: u32,
    pub log_level: String,
    pub worker_threads: usize,
    pub http_port: u16,
    /// Max bytes of transactions per propose() call.
    #[serde(default = "default_max_propose_bytes")]
    pub max_propose_bytes: usize,
    /// Max bytes of pending transactions before rejecting.
    #[serde(default = "default_max_pool_bytes")]
    pub max_pool_bytes: usize,
    pub bootstrappers: Vec<BootstrapperEntry>,
    #[serde(default)]
    pub genesis_allocations: Vec<GenesisAllocation>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DeployerValidatorConfig {
    pub private_key: String,
    pub dkg_output: String,
    pub dkg_share: String,
    pub listen_port: u16,
    pub genesis_leader: String,
    pub partition_prefix: String,
    pub num_validators: u32,
    pub log_level: String,
    pub worker_threads: usize,
    pub http_port: u16,
    /// Max bytes of transactions per propose() call.
    #[serde(default = "default_max_propose_bytes")]
    pub max_propose_bytes: usize,
    /// Max bytes of pending transactions before rejecting.
    #[serde(default = "default_max_pool_bytes")]
    pub max_pool_bytes: usize,
    pub bootstrappers: Vec<NamedBootstrapperEntry>,
    #[serde(default)]
    pub genesis_allocations: Vec<GenesisAllocation>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BootstrapperEntry {
    pub public_key: String,
    pub address: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct NamedBootstrapperEntry {
    pub public_key: String,
    pub name: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct GenesisAllocation {
    pub address: String,
    pub balance: u64,
}

/// Decoded key material and network info ready for use by the engine.
pub struct DecodedConfig {
    pub signer: ed25519::PrivateKey,
    pub public_key: ed25519::PublicKey,
    pub dkg_output: dkg::Output<MinSig, ed25519::PublicKey>,
    pub share: Share,
    pub genesis_leader: ed25519::PublicKey,
    pub listen: SocketAddr,
    pub bootstrappers: Vec<Bootstrapper<ed25519::PublicKey>>,
    pub partition_prefix: String,
    pub genesis_allocations: Vec<(Address, Account)>,
}

pub struct LoadedConfig {
    pub decoded: DecodedConfig,
    pub log_level: String,
    pub worker_threads: usize,
    pub http_listen: SocketAddr,
    pub max_propose_bytes: usize,
    pub max_pool_bytes: usize,
}

fn decode_hex(field_name: &str, hex_str: &str) -> Vec<u8> {
    from_hex(hex_str).unwrap_or_else(|| panic!("bad {field_name} hex"))
}

fn decode_private_key(hex_str: &str) -> ed25519::PrivateKey {
    let bytes = decode_hex("private_key", hex_str);
    ed25519::PrivateKey::read(&mut &bytes[..]).expect("failed to decode private key")
}

fn decode_dkg_output(
    hex_str: &str,
    num_validators: u32,
) -> dkg::Output<MinSig, ed25519::PublicKey> {
    let bytes = decode_hex("dkg_output", hex_str);
    dkg::Output::read_cfg(
        &mut &bytes[..],
        &(NZU32!(num_validators), ModeVersion::v0()),
    )
    .expect("failed to decode DKG output")
}

fn decode_share(hex_str: &str) -> Share {
    let bytes = decode_hex("dkg_share", hex_str);
    Share::read(&mut &bytes[..]).expect("failed to decode DKG share")
}

fn decode_public_key(field_name: &str, hex_str: &str) -> ed25519::PublicKey {
    let bytes = decode_hex(field_name, hex_str);
    ed25519::PublicKey::read(&mut &bytes[..]).expect("failed to decode public key")
}

fn decode_genesis_allocations(allocations: &[GenesisAllocation]) -> Vec<(Address, Account)> {
    allocations
        .iter()
        .map(|allocation| {
            let bytes = decode_hex("genesis allocation address", &allocation.address);
            let address = Address::read(&mut &bytes[..]).expect("failed to decode genesis address");
            (
                address,
                Account {
                    balance: allocation.balance,
                    nonce: 0,
                },
            )
        })
        .collect()
}

impl ValidatorConfig {
    pub fn decode(&self) -> DecodedConfig {
        let signer = decode_private_key(&self.private_key);
        let public_key = signer.public_key();
        let dkg_output = decode_dkg_output(&self.dkg_output, self.num_validators);
        let share = decode_share(&self.dkg_share);
        let genesis_leader = decode_public_key("genesis_leader", &self.genesis_leader);
        let listen: SocketAddr = self.listen.parse().expect("bad listen address");

        let bootstrappers = self
            .bootstrappers
            .iter()
            .map(|bootstrapper| {
                let public_key =
                    decode_public_key("bootstrapper public_key", &bootstrapper.public_key);
                let address: SocketAddr = bootstrapper
                    .address
                    .parse()
                    .expect("bad bootstrapper address");
                (public_key, Ingress::Socket(address))
            })
            .collect();

        DecodedConfig {
            signer,
            public_key,
            dkg_output,
            share,
            genesis_leader,
            listen,
            bootstrappers,
            partition_prefix: self.partition_prefix.clone(),
            genesis_allocations: decode_genesis_allocations(&self.genesis_allocations),
        }
    }
}

impl DeployerValidatorConfig {
    fn decode(&self, hosts: &Hosts) -> LoadedConfig {
        let signer = decode_private_key(&self.private_key);
        let public_key = signer.public_key();
        let dkg_output = decode_dkg_output(&self.dkg_output, self.num_validators);
        let share = decode_share(&self.dkg_share);
        let genesis_leader = decode_public_key("genesis_leader", &self.genesis_leader);
        let listen: SocketAddr = format!("0.0.0.0:{}", self.listen_port)
            .parse()
            .expect("bad listen address");
        let http_listen: SocketAddr = format!("0.0.0.0:{}", self.http_port)
            .parse()
            .expect("bad HTTP listen address");
        let hosts_by_name = hosts
            .hosts
            .iter()
            .map(|host| (host.name.as_str(), host.ip))
            .collect::<HashMap<_, _>>();

        let bootstrappers = self
            .bootstrappers
            .iter()
            .map(|bootstrapper| {
                let public_key =
                    decode_public_key("bootstrapper public_key", &bootstrapper.public_key);
                let ip = hosts_by_name
                    .get(bootstrapper.name.as_str())
                    .unwrap_or_else(|| panic!("missing bootstrapper host '{}'", bootstrapper.name));
                let address = SocketAddr::new(*ip, self.listen_port);
                (public_key, Ingress::Socket(address))
            })
            .collect();

        LoadedConfig {
            decoded: DecodedConfig {
                signer,
                public_key,
                dkg_output,
                share,
                genesis_leader,
                listen,
                bootstrappers,
                partition_prefix: self.partition_prefix.clone(),
                genesis_allocations: decode_genesis_allocations(&self.genesis_allocations),
            },
            log_level: self.log_level.clone(),
            worker_threads: self.worker_threads,
            http_listen,
            max_propose_bytes: self.max_propose_bytes,
            max_pool_bytes: self.max_pool_bytes,
        }
    }
}

pub fn load_local_config(path: &Path) -> LoadedConfig {
    let raw = std::fs::read_to_string(path).expect("failed to read config file");
    let config: ValidatorConfig = toml::from_str(&raw).expect("failed to parse config");
    let http_listen: SocketAddr = format!("127.0.0.1:{}", config.http_port)
        .parse()
        .expect("bad HTTP listen address");

    LoadedConfig {
        decoded: config.decode(),
        log_level: config.log_level,
        worker_threads: config.worker_threads,
        http_listen,
        max_propose_bytes: config.max_propose_bytes,
        max_pool_bytes: config.max_pool_bytes,
    }
}

pub fn load_deployer_config(hosts_path: &Path, config_path: &Path) -> LoadedConfig {
    let raw_hosts = std::fs::read_to_string(hosts_path).expect("failed to read hosts file");
    let hosts: Hosts = serde_yaml::from_str(&raw_hosts).expect("failed to parse hosts file");
    let raw_config = std::fs::read_to_string(config_path).expect("failed to read config file");
    let config: DeployerValidatorConfig =
        toml::from_str(&raw_config).expect("failed to parse config");
    config.decode(&hosts)
}

#[cfg(test)]
mod tests {
    use super::{DeployerValidatorConfig, GenesisAllocation, NamedBootstrapperEntry};
    use commonware_codec::{Encode, FixedSize};
    use commonware_cryptography::{
        Signer,
        bls12381::{
            dkg,
            primitives::{group::Share, variant::MinSig},
        },
        ed25519,
    };
    use commonware_deployer::aws::{Host, Hosts};
    use commonware_utils::{N3f1, TryCollect, hex};
    use constantinople_primitives::Address;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn deployer_config_resolves_bootstrapper_hosts() {
        let validators = (0_u64..2)
            .map(ed25519::PrivateKey::from_seed)
            .collect::<Vec<_>>();
        let public_keys = validators
            .iter()
            .map(Signer::public_key)
            .collect::<Vec<_>>();
        let participants = public_keys.clone().into_iter().try_collect().unwrap();
        let mut rng = commonware_utils::test_rng();
        let (dkg_output, raw_shares) =
            dkg::deal::<MinSig, _, N3f1>(&mut rng, Default::default(), participants)
                .expect("DKG deal failed");
        let shares = raw_shares
            .into_iter()
            .collect::<std::collections::BTreeMap<_, Share>>();
        let signer = &validators[0];
        let public_key = signer.public_key();
        let share = shares.get(&public_key).expect("missing share");
        let peer_name = hex(&public_keys[1].encode());

        let config = DeployerValidatorConfig {
            private_key: hex(&signer.encode()),
            dkg_output: hex(&dkg_output.encode()),
            dkg_share: hex(&share.encode()),
            listen_port: 9000,
            genesis_leader: hex(&public_key.encode()),
            partition_prefix: "validator-0".to_string(),
            num_validators: 2,
            log_level: "info".to_string(),
            worker_threads: 2,
            http_port: 8080,
            max_propose_bytes: super::default_max_propose_bytes(),
            max_pool_bytes: super::default_max_pool_bytes(),
            bootstrappers: vec![NamedBootstrapperEntry {
                public_key: peer_name.clone(),
                name: peer_name,
            }],
            genesis_allocations: vec![GenesisAllocation {
                address: "00".repeat(Address::SIZE),
                balance: 100,
            }],
        };
        let hosts = Hosts {
            monitoring: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            hosts: vec![Host {
                name: hex(&public_keys[1].encode()),
                region: "us-east-1".to_string(),
                ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            }],
        };

        let loaded = config.decode(&hosts);

        assert_eq!(loaded.http_listen, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(loaded.decoded.listen, "0.0.0.0:9000".parse().unwrap());
        assert_eq!(
            loaded.decoded.bootstrappers[0].1,
            commonware_p2p::Ingress::Socket(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                9000,
            ))
        );
    }
}
