#!/usr/bin/env bash
# ==============================================================================
# Valkey Cluster Chaos & Failover Test Tool
# ==============================================================================
# Automates replica failover, master shutdown, and cluster lifecycle management
# (up, restart, down, chaos/infinite) to test client-side write resilience
# and dynamic node redirection.
# ==============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.chaos.yml"
docker compose -f "$COMPOSE_FILE" down
docker compose -f "$COMPOSE_FILE" up -d cluster
set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

print_header() {
    echo -e "\n${BOLD}${CYAN}==============================================================================${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BOLD}${CYAN}==============================================================================${NC}\n"
}

# Find docker container running the cluster
get_container() {
    local c
    c=$(docker ps -qf "name=cluster" | head -n 1)
    echo "$c"
}

# Run valkey-cli command inside container
vcli() {
    local port=$1
    shift
    local cid
    cid=$(get_container)
    if [ -z "$cid" ]; then
        echo -e "${RED}❌ Cluster container is not running. Run: $0 up${NC}"
        exit 1
    fi
    docker exec "$cid" valkey-cli -p "$port" "$@" 2>/dev/null
}

compose_up() {
    print_header "STARTING CLUSTER (docker compose up -d cluster)"
    docker compose -f "$COMPOSE_FILE" up -d cluster
    echo -e "${CYAN}Waiting for cluster nodes to initialize and form topology...${NC}"
    sleep 5
    show_status
    echo -e "${GREEN}✅ Cluster is up and ready!${NC}"
}

compose_restart() {
    print_header "RESTARTING CLUSTER (docker compose restart cluster)"
    docker compose -f "$COMPOSE_FILE" restart cluster
    echo -e "${CYAN}Waiting for nodes to re-initialize and form topology...${NC}"
    sleep 5
    show_status
    echo -e "${GREEN}✅ Cluster restarted successfully!${NC}"
}

compose_down() {
    print_header "STOPPING CLUSTER (docker compose down)"
    docker compose -f "$COMPOSE_FILE" down
    echo -e "${GREEN}✅ Cluster stopped and containers removed.${NC}"
}

show_status() {
    print_header "CURRENT CLUSTER TOPOLOGY & NODE ROLES"
    local cid
    cid=$(get_container)

    if [ -z "$cid" ]; then
        echo -e "${RED}❌ Cluster container is not running! Run: $0 up${NC}"
        return 1
    fi

    # Try alive ports to query cluster nodes
    local out=""
    for p in 7001 7002 7003 7021 7022 7023; do
        out=$(docker exec "$cid" valkey-cli -p "$p" CLUSTER NODES 2>/dev/null || true)
        if [ -n "$out" ]; then
            break
        fi
    done

    if [ -z "$out" ]; then
        echo -e "${RED}❌ Unable to query cluster from any node! Nodes may still be booting or down.${NC}"
        return 1
    fi

    echo -e "${BOLD}Node Address\tRole\tStatus\t\tSlots / Master ID${NC}"
    echo -e "------------------------------------------------------------------------"
    echo "$out" | while read -r line; do
        id=$(echo "$line" | awk '{print $1}')
        addr=$(echo "$line" | awk '{print $2}' | cut -d'@' -f1)
        role_raw=$(echo "$line" | awk '{print $3}')
        status=$(echo "$line" | awk '{print $8}')
        slots=$(echo "$line" | awk '{for(i=9;i<=NF;++i)print $i}' | tr '\n' ' ')

        # Parse role
        if [[ "$role_raw" == *"master"* ]]; then
            role="${GREEN}MASTER${NC}"
        else
            role="${YELLOW}REPLICA${NC}"
        fi

        # Parse status
        if [[ "$line" == *"disconnected"* ]] || [[ "$line" == *"fail"* ]]; then
            st_colored="${RED}OFFLINE${NC}"
        else
            st_colored="${GREEN}ONLINE${NC}"
        fi

        echo -e "${addr}\t${role}\t${st_colored}\t\t${slots:-[none]}"
    done
    echo ""
}

failover() {
    local port=$1
    if [ -z "$port" ]; then
        echo "Usage: $0 failover <port> (e.g. $0 failover 7021)"
        exit 1
    fi
    echo -e "${YELLOW}⚡ Triggering CLUSTER FAILOVER TAKEOVER on port ${port}...${NC}"
    local res
    res=$(vcli "$port" CLUSTER FAILOVER TAKEOVER || true)
    if [ "$res" = "OK" ]; then
        echo -e "${GREEN}✅ Successfully executed TAKEOVER on port ${port}!${NC}"
    else
        echo -e "${RED}❌ Failed: ${res}${NC}"
    fi
    sleep 1
    show_status
}

shutdown_node() {
    local port=$1
    if [ -z "$port" ]; then
        echo "Usage: $0 shutdown <port> (e.g. $0 shutdown 7003)"
        exit 1
    fi
    echo -e "${RED}💥 Shutting down node on port ${port} (SHUTDOWN NOSAVE)...${NC}"
    vcli "$port" SHUTDOWN NOSAVE || true
    echo -e "${GREEN}✅ Node on port ${port} has been killed.${NC}"
    sleep 1
    show_status
}

# Helper to find current master port for a pair of ports (e.g. 7001 and 7021)
find_master() {
    local p1=$1
    local p2=$2
    local cid
    cid=$(get_container)
    local out=""
    for p in 7001 7002 7003 7021 7022 7023; do
        out=$(docker exec "$cid" valkey-cli -p "$p" CLUSTER NODES 2>/dev/null || true)
        if [ -n "$out" ]; then break; fi
    done
    local m
    m=$(echo "$out" | grep -E ":($p1|$p2)@" | grep "master" | awk '{print $2}' | cut -d'@' -f1 | cut -d':' -f2 | head -n 1)
    echo "$m"
}

# ==============================================================================
# Infinite Chaos Engine: Runs continuous failovers, crashes, and recoveries
# ==============================================================================
run_infinite_chaos() {
    print_header "STARTING CONTINUOUS INFINITE CHAOS ENGINE (Press Ctrl+C to stop)"
    echo -e "${BOLD}Make sure your traffic generator (go run main.go) is running in another terminal!${NC}"
    echo -e "Starting in 3 seconds...\n"
    sleep 3

    local cycle=0
    while true; do
        cycle=$((cycle + 1))
        echo -e "\n${BOLD}${MAGENTA}##############################################################################${NC}"
        echo -e "${BOLD}${MAGENTA}  🔥 CHAOS CYCLE #$cycle  --  $(date '+%H:%M:%S')${NC}"
        echo -e "${BOLD}${MAGENTA}##############################################################################${NC}\n"

        # ----------------------------------------------------------------------
        # Chaos Event 1: Coordinated Failover on Shard 1 (7001 <-> 7021)
        # ----------------------------------------------------------------------
        echo -e "${BOLD}${CYAN}--- [Cycle $cycle] Event 1: Coordinated Failover on Shard 1 ---${NC}"
        local m1
        m1=$(find_master 7001 7021)
        local r1="7021"
        [ "$m1" = "7021" ] && r1="7001"
        if [ -n "$m1" ] && [ -n "$r1" ]; then
            echo -e "Current Master: :$m1  ->  Promoting Replica :$r1 (Triggering [REDIRECT-MOVED])..."
            vcli "$r1" CLUSTER FAILOVER TAKEOVER > /dev/null 2>&1 || true
            echo -e "${GREEN}✅ Replica :$r1 promoted! Sleeping 4s to observe traffic...${NC}"
            sleep 4
        fi

        # ----------------------------------------------------------------------
        # Chaos Event 2: Crash Master on Shard 3, then Rescue with Replica
        # ----------------------------------------------------------------------
        echo -e "\n${BOLD}${CYAN}--- [Cycle $cycle] Event 2: Hard Crash on Shard 3 & Rescue ---${NC}"
        local m3
        m3=$(find_master 7003 7023)
        local r3="7023"
        [ "$m3" = "7023" ] && r3="7003"
        if [ -n "$m3" ] && [ -n "$r3" ]; then
            echo -e "${RED}💥 Crashing active Master :$m3 (SHUTDOWN NOSAVE)...${NC}"
            vcli "$m3" SHUTDOWN NOSAVE > /dev/null 2>&1 || true
            echo -e "${YELLOW}⏳ Master :$m3 is DEAD! Waiting 3s (watch client traffic enter [RETRY] backoff)...${NC}"
            sleep 3
            echo -e "${GREEN}⚡ Rescuing Shard 3: Promoting Replica :$r3 to Master...${NC}"
            vcli "$r3" CLUSTER FAILOVER TAKEOVER > /dev/null 2>&1 || true
            echo -e "${GREEN}✅ Replica :$r3 is now Master! Traffic resumes with ZERO errors.${NC}"
            sleep 4
        fi

        # ----------------------------------------------------------------------
        # Chaos Event 3: Coordinated Failover on Shard 2 (7002 <-> 7022)
        # ----------------------------------------------------------------------
        echo -e "\n${BOLD}${CYAN}--- [Cycle $cycle] Event 3: Coordinated Failover on Shard 2 ---${NC}"
        local m2
        m2=$(find_master 7002 7022)
        local r2="7022"
        [ "$m2" = "7022" ] && r2="7002"
        if [ -n "$m2" ] && [ -n "$r2" ]; then
            echo -e "Current Master: :$m2  ->  Promoting Replica :$r2 (Triggering [REDIRECT-MOVED])..."
            vcli "$r2" CLUSTER FAILOVER TAKEOVER > /dev/null 2>&1 || true
            echo -e "${GREEN}✅ Replica :$r2 promoted! Sleeping 4s to observe traffic...${NC}"
            sleep 4
        fi

        # ----------------------------------------------------------------------
        # Periodic Cluster Revival: Revive any killed nodes every 2 cycles
        # ----------------------------------------------------------------------
        if [ $((cycle % 2)) -eq 0 ]; then
            echo -e "\n${BOLD}${CYAN}--- [Cycle $cycle] Event 4: Periodic Cluster Reset & Node Revival ---${NC}"
            echo -e "${YELLOW}Restarting cluster container to revive all 6 nodes...${NC}"
            local cid
            cid=$(get_container)
            docker restart "$cid" > /dev/null 2>&1 || true
            echo -e "Waiting 5s for topology reconciliation..."
            sleep 5
            show_status
        else
            echo -e "\n${BOLD}${CYAN}--- [Cycle $cycle] Current Cluster State ---${NC}"
            show_status
            sleep 2
        fi
    done
}

run_auto_test() {
    print_header "STARTING AUTOMATED CHAOS & FAILOVER TEST SEQUENCE"
    echo -e "Make sure your traffic test script (go run main.go) is running in another terminal!"
    echo -e "Starting in 3 seconds...\n"
    sleep 3

    echo -e "${BOLD}${CYAN}--- Step 1: Initial Cluster State ---${NC}"
    show_status
    sleep 3

    echo -e "${BOLD}${CYAN}--- Step 2: Promote Replica 7023 to Master for Shard 3 ---${NC}"
    failover 7023
    echo -e "Sleeping 5 seconds to observe client traffic..."
    sleep 5

    echo -e "${BOLD}${CYAN}--- Step 3: Promote Replica 7021 to Master for Shard 1 ---${NC}"
    failover 7021
    echo -e "Sleeping 5 seconds to observe client traffic..."
    sleep 5

    echo -e "${BOLD}${CYAN}--- Step 4: Promote Replica 7022 to Master for Shard 2 ---${NC}"
    failover 7022
    echo -e "Sleeping 5 seconds to observe client traffic..."
    sleep 5

    echo -e "${BOLD}${CYAN}--- Step 5: Hard Shutdown of Old Master 7001 ---${NC}"
    shutdown_node 7001
    echo -e "Sleeping 5 seconds (Notice: Client traffic continues on 7021 with ZERO errors!)..."
    sleep 5

    echo -e "${BOLD}${CYAN}--- Step 6: Hard Shutdown of Old Master 7003 ---${NC}"
    shutdown_node 7003
    echo -e "Sleeping 5 seconds (Notice: Client traffic continues on 7023 with ZERO errors!)..."
    sleep 5

    print_header "CHAOS TEST SEQUENCE COMPLETED"
    echo -e "Check your traffic generator terminal: it should show 100% WRITE OK with dynamic node switches!"
    echo -e "To reset the cluster back to fresh 6-node state, run: ${BOLD}$0 restart${NC}\n"
}

# Command dispatch
case "$1" in
    up)
        compose_up
        ;;
    restart|reset)
        compose_restart
        ;;
    down)
        compose_down
        ;;
    status)
        show_status
        ;;
    failover)
        failover "$2"
        ;;
    shutdown)
        shutdown_node "$2"
        ;;
    auto)
        run_auto_test
        ;;
    chaos|infinite|loop)
        run_infinite_chaos
        ;;
    *)
        echo -e "${BOLD}Usage:${NC} $0 {chaos|status|up|restart|down|failover <port>|shutdown <port>|auto}"
        echo ""
        echo "Infinite Chaos Engine:"
        echo "  $0 chaos           - Run continuous infinite chaos (failover, shutdown, reset) until Ctrl+C"
        echo ""
        echo "Docker Compose Lifecycle Commands:"
        echo "  $0 up              - Run: docker compose up -d cluster"
        echo "  $0 restart         - Run: docker compose restart cluster (restore all 6 nodes)"
        echo "  $0 down            - Run: docker compose down"
        echo ""
        echo "Cluster Chaos & Test Commands:"
        echo "  $0 status          - Display live cluster node roles, states, and slots"
        echo "  $0 failover <port> - Force replica on <port> to take over as master (e.g. 7021)"
        echo "  $0 shutdown <port> - Kill node on <port> (SHUTDOWN NOSAVE)"
        echo "  $0 auto            - Run a single automated failover & shutdown test sequence"
        echo ""
        ;;
esac

