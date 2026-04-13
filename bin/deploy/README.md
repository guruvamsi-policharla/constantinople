# Deployment

`constantinople-deploy` generates deployment artifacts for local and remote Constantinople clusters.

## Local Deployment

Generate a local bundle:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 4 \
  --output-dir ./local \
  --worker-threads 2 \
  --rayon-threads 2 \
  local \
  --base-port 3000 \
  --base-http-port 8080
```

This writes:

- `validator-0.yaml`, `validator-1.yaml`, ...
- `peers.yaml`

It also prints an `mprocs` command that starts the whole local cluster.

Run a single validator directly:

```sh
cargo run --bin constantinople -- \
  --config ./local/validator-0.yaml \
  --peers ./local/peers.yaml
```

Run the whole local cluster with the printed `mprocs` command, or start each validator in a
separate terminal:

```sh
cargo run --bin constantinople -- --config ./local/validator-0.yaml --peers ./local/peers.yaml
cargo run --bin constantinople -- --config ./local/validator-1.yaml --peers ./local/peers.yaml
cargo run --bin constantinople -- --config ./local/validator-2.yaml --peers ./local/peers.yaml
cargo run --bin constantinople -- --config ./local/validator-3.yaml --peers ./local/peers.yaml
```

## Remote Deployment

`generate remote` writes the deployment bundle, but it does not build the validator binary. Use
`--output-dir ./deploy` if you want to use the bundled `just` targets unchanged.

Generate the remote bundle:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 20 \
  --output-dir ./deploy \
  --worker-threads 4 \
  --rayon-threads 4 \
  remote \
  --http-cidr 0.0.0.0/0 \
  --regions us-east-1,us-west-2 \
  --instance-type c8g.2xlarge \
  --storage-size 75 \
  --monitoring-instance-type c8g.2xlarge \
  --monitoring-storage-size 100 \
  --dashboard ./docker/dashboard.json
```

This writes:

- one validator YAML config per validator
- `config.yaml` for `commonware-deployer`
- `dashboard.json`

Build the deployable validator binary into `./deploy`:

```sh
just validator-graviton-binary
```

For Intel instances such as `c8i.*`, use:

```sh
just validator-intel-binary
```

Both targets write `deploy/validator` and `deploy/validator-debug`. See
[`docker/README.md`](../../docker/README.md) for the Docker build details.

Create the remote deployment:

```sh
cd ./deploy
deployer aws create --config config.yaml
```

`--http-cidr` controls who can reach validator mempool HTTP ports in remote deployments.

## Runtime Interfaces

Use `--peers` for local bundles:

```sh
constantinople --config ./validator.yaml --peers ./peers.yaml
```

Use `--hosts` for deployer-managed remote bundles:

```sh
constantinople --config ./validator.yaml --hosts ./hosts.yaml
```
