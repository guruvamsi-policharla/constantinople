# Local tracing

This stack runs Tempo, Prometheus, and Grafana for local Constantinople
traces and metrics.

Start it from the repository root:

```sh
docker compose -f docker/tracing/docker-compose.yml up
```

Tempo receives OTLP HTTP traces on:

```text
http://127.0.0.1:4318/v1/traces
```

Grafana is available at:

```text
http://127.0.0.1:3001
```

Prometheus is available at:

```text
http://127.0.0.1:19090
```

Generate a local bundle with trace export enabled:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 4 \
  --indexer \
  --relayer \
  --output-dir ./local \
  --spammer \
  --spammer-workload private \
  local \
  --traces 1.0
```

Run the printed `mprocs` command, then open Grafana and use the preconfigured
`Tempo` data source for traces or the preconfigured `Prometheus` data source
for dashboards. Search for service names matching validator public keys, then
inspect spans such as `application.execute.operations` and
`application.executor.private_batch_verify`.
