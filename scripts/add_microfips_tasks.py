#!/usr/bin/env python3
"""Add microFIPS-ESP32 tasks to FIPS kanban board"""

import sqlite3
import time
import uuid

def add_task(db_path, title, body, priority, status="backlog"):
    """Add a task to the kanban database"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    now = int(time.time())
    task_id = str(uuid.uuid4())
    
    cursor.execute("""
        INSERT INTO tasks (id, title, body, status, priority, created_by, created_at, workspace_kind, tenant)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'scratch', 'fips')
    """, (task_id, title, body, status, priority, 'hermes-agent', now))
    
    conn.commit()
    conn.close()
    return task_id

tasks = [
    {
        "title": "MFE-001: Fix ESP-NOW binary linking",
        "body": "Critical (1 day) - Resolve undefined symbol errors during ESP-NOW binary linking. ESP-IDF symbols (nvs_flash_init, esp_netif_init, etc.) declared via FFI but not linked. Need esp-rtos/esp-bootloader linker config or espflash build. Blocking all flashable demos.",
        "priority": 3
    },
    {
        "title": "MFE-002: Flash and validate ESP-NOW binary",
        "body": "Critical (0.5 days) - Flash ESP-NOW binary to physical ESP32-C3 hardware. Verify boot sequence, serial output shows 'ESP-NOW initialized' with MAC address, LED blink pattern works. Hardware: ESP32-C3 on /dev/ttyACM2.",
        "priority": 3
    },
    {
        "title": "MFE-003: Port erasure coding from balloon-fresh",
        "body": "High (3-4 days) - Port PRBS23-XOR erasure coding from C to Rust. Source: ~/repos/balloon-fresh/tracker/firmware/components/erasure/erasure.c (325 lines C). Create Rust crate crates/microfips-erasure/. Implement fragment_header (6 bytes: block_id + frag_index + original_count + crc16), erasure_encode(), erasure_decode().",
        "priority": 2
    },
    {
        "title": "MFE-004: Implement pipeline layer",
        "body": "High (2 days) - Create pipeline layer to fragment FIPS frames and reassemble them. Design Pipeline trait (encode, decode, mtu methods). Split 2048B into 9 fragments ~244B each. Integrate with ESP-NOW transport.",
        "priority": 2
    },
    {
        "title": "MFE-005: Merge MAC-to-node-address mapping",
        "body": "Medium (1 day) - Merge feat/mac-mapping branch and implement node discovery. Review feat/mac-mapping branch (commit 962657c), resolve conflicts and merge into feat/fips-v0-compat. Test mapping.",
        "priority": 1
    },
    {
        "title": "MFE-006: Implement FIPS STP + bloom filters",
        "body": "Medium (2-3 days) - Implement spanning tree protocol and bloom filters for mesh routing. STP algorithm (root election, path cost, forwarding). Bloom filters for cycle detection.",
        "priority": 1
    },
    {
        "title": "MFE-007: Two-node ESP-NOW demo",
        "body": "High (1 day) - Validate ESP-NOW communication between two physical ESP32-C3 boards. Board A on /dev/ttyACM1, Board B on /dev/ttyACM2, same channel (1), no router. Proof of concept milestone.",
        "priority": 2
    },
    {
        "title": "MFE-008: FIPS handshake over ESP-NOW",
        "body": "High (1 day) - Demonstrate FIPS Noise handshake directly over ESP-NOW. Skip VPS1 dependency. Complete demo milestone: handshake completes without VPS1, crypto verification succeeds.",
        "priority": 2
    }
]

def main():
    fips_db_path = "/home/c03rad0r/.hermes/profiles/manager/kanban/boards/fips/kanban.db"
    
    print(f"Adding {len(tasks)} microFIPS-ESP32 tasks to FIPS board...")
    
    added_tasks = []
    for task in tasks:
        task_id = add_task(
            db_path=fips_db_path,
            title=task["title"],
            body=task["body"],
            priority=task["priority"]
        )
        added_tasks.append((task_id, task["title"]))
        print(f"  ✅ {task['title'][:55]}")
    
    print(f"\nAdded {len(added_tasks)} tasks to FIPS board.")
    print(f"Run: python3 ~/.hermes/profiles/manager/scripts/kanban_auto_assigner.py --board fips --dry-run")

if __name__ == "__main__":
    main()