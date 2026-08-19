#!/bin/bash
# =========================================================================
# NAME: run-master-pipeline.sh
# DESCRIPTION: Master coordinator to sequentially execute VCSA, ESXi, and VM
#              STIG pipelines. Employs execution tracking and state guards.
# =========================================================================

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export HOME="/root"

MASTER_LOG="/usr/share/stigs/orchestration_overlay/logs/master_orchestration_trace.log"
LOCK_FILE="/var/run/master_stig_orchestration.lock"

# Target scripts to run sequentially
SCRIPT_VCSA="/usr/share/stigs/orchestration_overlay/bin/run-cron-vcsa.sh"
SCRIPT_ESXI="/usr/share/stigs/orchestration_overlay/bin/run-cron-esxi.sh"
SCRIPT_VM="/usr/share/stigs/orchestration_overlay/bin/run-cron-vm.sh"

mkdir -p "$(dirname "$MASTER_LOG")"

# Redirect stdout and stderr to the master log
exec >> "$MASTER_LOG" 2>&1

# Prevent concurrent overlapping execution runs
(
    if ! flock -n 9; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] Master STIG Orchestration is already running under another process. Exiting."
        exit 1
    fi

    MASTER_START=$(date +%s)
    echo "========================================================================="
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] --- Starting Master Sequential STIG Orchestration ---"
    echo "========================================================================="

    # Helper function to execute and track sub-pipelines
    run_phase() {
        local name="$1"
        local path="$2"
        
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] >>> [PHASE START] Running $name pipeline..."
        
        if [ ! -f "$path" ]; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] Script missing at $path"
            return 2
        fi
        
        if [ ! -x "$path" ]; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] Marking $path as executable..."
            chmod +x "$path"
        fi

        # Run script natively
        $path
        local exit_code=$?
        
        if [ $exit_code -eq 0 ]; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] <<< [PHASE COMPLETE] $name pipeline finalized cleanly."
            return 0
        else
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] <<< [PHASE FAILED] $name pipeline failed with exit code: $exit_code"
            return 1
        fi
    }

    # 1. Execute VCSA Audit
    run_phase "VCSA STIG Audit" "$SCRIPT_VCSA"
    STATUS_VCSA=$?

    echo "-------------------------------------------------------------------------"

    # 2. Execute ESXi Audit
    run_phase "ESXi STIG Audit" "$SCRIPT_ESXI"
    STATUS_ESXI=$?

    echo "-------------------------------------------------------------------------"

    # 3. Execute VM Remediation
    run_phase "VM STIG Remediation" "$SCRIPT_VM"
    STATUS_VM=$?

    # Compile final execution metrics
    MASTER_END=$(date +%s)
    DURATION=$((MASTER_END - MASTER_START))
    MIN=$((DURATION / 60))
    SEC=$((DURATION % 60))

    # Determine execution outcomes
    ANY_FAILED=0
    [ $STATUS_VCSA -ne 0 ] && ANY_FAILED=1
    [ $STATUS_ESXI -ne 0 ] && ANY_FAILED=1
    [ $STATUS_VM -ne 0 ] && ANY_FAILED=1

    echo "========================================================================="
    echo "                      ORCHESTRATION PIPELINE SUMMARY"
    echo "========================================================================="
    echo "  VCSA STIG Audit Phase:     $( [ $STATUS_VCSA -eq 0 ] && echo 'SUCCESS' || echo 'FAILED' )"
    echo "  ESXi STIG Audit Phase:     $( [ $STATUS_ESXI -eq 0 ] && echo 'SUCCESS' || echo 'FAILED' )"
    echo "  VM STIG Remediation Phase:  $( [ $STATUS_VM -eq 0 ] && echo 'SUCCESS' || echo 'FAILED' )"
    echo "-------------------------------------------------------------------------"
    echo "  Total Execution Duration:  ${MIN}m ${SEC}s"
    echo "========================================================================="

    if [ $ANY_FAILED -eq 0 ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] Master Orchestration pipeline completed successfully."
        exit 0
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] Master Orchestration pipeline encountered failures in one or more phases."
        exit 1
    fi

) 9>"$LOCK_FILE"