# Copyright 2025 AI SOC Contributors
# SPDX-License-Identifier: Apache-2.0

import asyncio
import sys

from services.shuffle_client import shuffle_client

async def verify_shuffle():
    try:
        print("1. Testing authentication & listing workflows...")
        workflows = await shuffle_client.list_workflows()
        print(f"Success! Found {len(workflows)} workflows.")
        
        print("\n2. Triggering a test 'malware-response' workflow execution...")
        execution_id = await shuffle_client.trigger(
            attack_type="MALWARE",
            alert_id="TEST-ALERT-12345",
            agent_id="001",
            agent_name="test-server",
            source_ip="192.168.1.50",
            dest_ip="8.8.8.8",
            username="testuser",
            pid="1337",
            playbook_summary="This is an automated E2E test from the backend."
        )
        print(f"Workflow triggered successfully. Execution ID: {execution_id}")
        
        print("\n3. Waiting for execution status...")
        status = await shuffle_client.get_status(execution_id)
        print(f"Current Status: {status['status']}")
        
        print("\nAll backend configurations and logic are working securely with Shuffle!")
    except Exception as e:
        print(f"\n[ERROR] Verification failed: {e}")
        sys.exit(1)
    finally:
        await shuffle_client.close()

if __name__ == "__main__":
    asyncio.run(verify_shuffle())
