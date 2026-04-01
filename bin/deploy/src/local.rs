use crate::{
    ClusterMaterial, GenerateArgs, LocalArgs, PEERS_CONFIG_FILE, PeerEntry, PeersConfig,
    SPAMMER_CONFIG_FILE, ValidatorConfig, absolute_path, build_spammer_config,
    default_max_pool_bytes, default_max_propose_bytes, ensure_output_dir_missing,
    generate_cluster_material, write_yaml_config,
};
use commonware_codec::Encode;
use commonware_utils::hex;
use std::{fs, path::PathBuf};

struct GeneratedValidator {
    config_file: PathBuf,
    config: ValidatorConfig,
    peer: PeerEntry,
}

pub(super) fn generate(args: &GenerateArgs, local: &LocalArgs) {
    assert!(args.validators >= 1, "need at least one validator");

    let output_dir = absolute_path(&args.output_dir);
    ensure_output_dir_missing(&output_dir);

    let material = generate_cluster_material(args.validators);
    let validators = build_validators(args, local, &output_dir, &material);
    let peers = PeersConfig {
        validators: validators
            .iter()
            .map(|validator| validator.peer.clone())
            .collect(),
    };
    let spammer = build_spammer_config(
        args,
        validators
            .iter()
            .map(|validator| validator.peer.name.clone())
            .collect(),
        local.base_http_port,
    );

    fs::create_dir_all(&output_dir).expect("failed to create output directory");
    for validator in &validators {
        write_yaml_config(&validator.config_file, &validator.config);
    }
    write_yaml_config(&output_dir.join(PEERS_CONFIG_FILE), &peers);
    if let Some(spammer) = spammer.as_ref() {
        write_yaml_config(&output_dir.join(SPAMMER_CONFIG_FILE), spammer);
    }

    print_local_run_commands(&output_dir, args.validators, spammer.is_some());
}

fn build_validators(
    args: &GenerateArgs,
    local: &LocalArgs,
    output_dir: &std::path::Path,
    material: &ClusterMaterial,
) -> Vec<GeneratedValidator> {
    let mut validators = Vec::with_capacity(args.validators as usize);

    for index in 0..args.validators {
        let validator_index = index as usize;
        let public_key = &material.public_keys[validator_index];
        let public_key_hex = hex(&public_key.encode());
        let share = material
            .shares
            .get(public_key)
            .expect("missing share for validator");
        let listen_port = local
            .base_port
            .checked_add(index as u16)
            .expect("listen port overflow");
        let http_port = local
            .base_http_port
            .checked_add(index as u16)
            .expect("http port overflow");

        let bootstrappers = material
            .public_keys
            .iter()
            .enumerate()
            .filter(|(peer_index, _)| *peer_index != validator_index)
            .map(|(_, peer_key)| {
                let name = hex(&peer_key.encode());
                crate::NamedBootstrapperEntry {
                    public_key: name.clone(),
                    name,
                }
            })
            .collect();

        let config = ValidatorConfig {
            private_key: hex(&material.signers[validator_index].encode()),
            dkg_output: hex(&material.dkg_output.encode()),
            dkg_share: hex(&share.encode()),
            listen_port,
            genesis_leader: material.genesis_leader.clone(),
            partition_prefix: format!("validator-{index}"),
            num_validators: args.validators,
            log_level: args.log_level.clone(),
            worker_threads: args.worker_threads,
            http_port,
            max_propose_bytes: default_max_propose_bytes(),
            max_pool_bytes: default_max_pool_bytes(),
            bootstrappers,
        };

        validators.push(GeneratedValidator {
            config_file: output_dir.join(format!("validator-{index}.yaml")),
            config,
            peer: PeerEntry {
                name: public_key_hex,
                p2p: format!("127.0.0.1:{listen_port}"),
                http: format!("127.0.0.1:{http_port}"),
            },
        });
    }

    validators
}

fn print_local_run_commands(output_dir: &std::path::Path, validators: u32, spammer: bool) {
    let peers_path = output_dir.join(PEERS_CONFIG_FILE);
    let commands = (0..validators)
        .map(|index| {
            let path = output_dir.join(format!("validator-{index}.yaml"));
            format!(
                "cargo run --bin constantinople -- --config {} --peers {}",
                path.display(),
                peers_path.display()
            )
        })
        .collect::<Vec<_>>();
    let mprocs = commands
        .iter()
        .map(|command| format!("\"{command}\""))
        .collect::<Vec<_>>()
        .join(" ");
    println!("mprocs {mprocs}");

    if spammer {
        println!(
            "cargo run --bin constantinople-spammer -- --config {} --peers {}",
            output_dir.join(SPAMMER_CONFIG_FILE).display(),
            peers_path.display()
        );
    }
}
