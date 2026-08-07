#!/bin/sh
set -eu

image=${1:-relaybox:test}
run_id="relaybox-smoke-$$"
container="${run_id}-app"
receiver="${run_id}-receiver"
receiver_image="${run_id}-receiver:test"
network="${run_id}-network"
volume="${run_id}-data"
operator_token=container-smoke-operator-token
work_dir=$(mktemp -d)

cleanup() {
	docker rm -f "$container" >/dev/null 2>&1 || true
	docker rm -f "$receiver" >/dev/null 2>&1 || true
	docker network rm "$network" >/dev/null 2>&1 || true
	docker volume rm "$volume" >/dev/null 2>&1 || true
	docker image rm "$receiver_image" >/dev/null 2>&1 || true
	rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM

test "$(docker image inspect "$image" --format '{{.Config.User}}')" = "65532:65532"
docker build --quiet --target receiver --tag "$receiver_image" . >/dev/null
docker network create "$network" >/dev/null
docker volume create "$volume" >/dev/null
docker create \
	--name "$receiver" \
	--network "$network" \
	"$receiver_image" -addr :9090 >/dev/null

docker run --detach \
	--name "$container" \
	--network "$network" \
	--publish 127.0.0.1::8080 \
	--read-only \
	--cap-drop ALL \
	--security-opt no-new-privileges \
	--volume "$volume:/data" \
	--env "RELAYBOX_OPERATOR_TOKEN=$operator_token" \
	"$image" serve \
		-addr 0.0.0.0:8080 \
		-data /data/relaybox.ndjson \
		-forward "http://$receiver:9090/hooks" \
		-allow-private-targets \
		-attempts 10 >/dev/null

host_port=$(docker port "$container" 8080/tcp | sed -n 's/.*://p' | head -n 1)
test -n "$host_port"

wait_for_ready() {
	ready=0
	for _ in $(seq 1 80); do
		if curl --fail --silent "http://127.0.0.1:$host_port/readyz" >/dev/null 2>&1; then
			ready=1
			break
		fi
		sleep 0.25
	done
	if [ "$ready" != 1 ]; then
		docker logs "$container" >&2 || true
		return 1
	fi
}

wait_for_ready
docker exec "$container" /relaybox healthcheck >/dev/null

response=$(curl --fail --silent --show-error \
	-X POST "http://127.0.0.1:$host_port/inbox" \
	-H 'X-GitHub-Delivery: container-restart-test' \
	--data 'container restart payload')
request_id=$(printf '%s' "$response" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
test -n "$request_id"

# Simulate an ungraceful process interruption after the atomic capture/intent
# commit. The forwarding receiver is intentionally stopped at this point.
docker kill "$container" >/dev/null
docker start "$receiver" >/dev/null
docker start "$container" >/dev/null
host_port=$(docker port "$container" 8080/tcp | sed -n 's/.*://p' | head -n 1)
test -n "$host_port"
wait_for_ready

delivered=0
for _ in $(seq 1 80); do
	if docker logs "$receiver" 2>&1 | grep -q "id=$request_id"; then
		delivered=1
		break
	fi
	sleep 0.25
done
test "$delivered" = 1

detail=$(curl --fail --silent --show-error \
	-H "Authorization: Bearer $operator_token" \
	"http://127.0.0.1:$host_port/api/requests/$request_id")
printf '%s' "$detail" | grep -q '"Status":204'
metrics=$(curl --fail --silent --show-error \
	-H "Authorization: Bearer $operator_token" \
	"http://127.0.0.1:$host_port/api/metrics")
printf '%s' "$metrics" | grep -q '"succeeded":1'

docker export "$container" >"$work_dir/rootfs.tar"
tar -tf "$work_dir/rootfs.tar" | grep -q '^etc/ssl/certs/ca-certificates.crt$'

docker stop --time 25 "$container" >/dev/null
test "$(docker inspect "$container" --format '{{.State.ExitCode}}')" = 0
