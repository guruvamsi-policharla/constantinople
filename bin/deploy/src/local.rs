use crate::{
    BootstrapperEntry, ClusterMaterial, GenerateArgs, LocalArgs, ValidatorConfig, absolute_path,
    default_max_pool_bytes, default_max_propose_bytes, ensure_output_dir_missing,
    generate_cluster_material, load_genesis_allocations, write_toml_config,
};
use commonware_codec::Encode;
use commonware_utils::hex;
use std::{fs, path::PathBuf};

struct GeneratedValidator {
    config_file: PathBuf,
    config: ValidatorConfig,
}

pub(super) fn generate(args: &GenerateArgs, local: &LocalArgs) {
    assert!(args.validators >= 1, "need at least one validator");

    let output_dir = absolute_path(&args.output_dir);
    ensure_output_dir_missing(&output_dir);

    let genesis_allocations = load_genesis_allocations(args.genesis.as_deref());
    let material = generate_cluster_material(args.validators);
    let validators = build_validators(args, local, &output_dir, &genesis_allocations, &material);

    fs::create_dir_all(&output_dir).expect("failed to create output directory");
    for validator in &validators {
        write_toml_config(&validator.config_file, &validator.config);
    }

    print_local_run_commands(&output_dir, args.validators);
}

fn build_validators(
    args: &GenerateArgs,
    local: &LocalArgs,
    output_dir: &std::path::Path,
    genesis_allocations: &[crate::GenesisAllocation],
    material: &ClusterMaterial,
) -> Vec<GeneratedValidator> {
    let mut validators = Vec::with_capacity(args.validators as usize);

    for index in 0..args.validators {
        let validator_index = index as usize;
        let public_key = &material.public_keys[validator_index];
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
            .map(|(peer_index, peer_key)| BootstrapperEntry {
                public_key: hex(&peer_key.encode()),
                address: format!(
                    "127.0.0.1:{}",
                    local
                        .base_port
                        .checked_add(peer_index as u16)
                        .expect("listen port overflow")
                ),
            })
            .collect();

        let config = ValidatorConfig {
            private_key: hex(&material.signers[validator_index].encode()),
            dkg_output: hex(&material.dkg_output.encode()),
            dkg_share: hex(&share.encode()),
            listen: format!("127.0.0.1:{listen_port}"),
            genesis_leader: material.genesis_leader.clone(),
            partition_prefix: format!("validator-{index}"),
            num_validators: args.validators,
            log_level: args.log_level.clone(),
            worker_threads: args.worker_threads,
            http_port,
            max_propose_bytes: default_max_propose_bytes(),
            max_pool_bytes: default_max_pool_bytes(),
            bootstrappers,
            genesis_allocations: genesis_allocations.to_vec(),
        };

        validators.push(GeneratedValidator {
            config_file: output_dir.join(format!("validator-{index}.toml")),
            config,
        });
    }

    validators
}

fn print_local_run_commands(output_dir: &std::path::Path, validators: u32) {
    let commands = (0..validators)
        .map(|index| {
            let path = output_dir.join(format!("validator-{index}.toml"));
            format!(
                "cargo run --bin constantinople -- --config {}",
                path.display()
            )
        })
        .collect::<Vec<_>>();
    let mprocs = commands
        .iter()
        .map(|command| format!("\"{command}\""))
        .collect::<Vec<_>>()
        .join(" ");
    println!("mprocs {mprocs}");
}
