#!/usr/bin/env python3
import json
import time
import os
import re
from datetime import datetime, timedelta
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

# --- Configuration ---
EVE_DIR = os.getenv("EVE_DIR", "/var/log/suricata")
INFLUX_URL = os.getenv("INFLUX_URL", "http://localhost:8086")
INFLUX_TOKEN = os.getenv("INFLUX_TOKEN", "iot-admin-token-123")
INFLUX_ORG = os.getenv("INFLUX_ORG", "iot-org")
INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "iot-data")

# Cache: (src_ip, src_port) -> (client_id, last_seen)
client_map = {}
CACHE_TTL = 86400  # 24 hours
PAYLOAD_LIMIT = 1024

# MQTT field mappings
MQTT_FIELDS_TOP = [
    "dup", "message_id", "password", "protocol_string", "protocol_version",
    "qos", "retain", "return_code", "session_present", "topic", "username"
]
MQTT_FIELDS_JSON = ["topics", "qos_granted", "reason_codes"]
MQTT_FIELDS_FLAGS = ["clean_session", "password", "username", "will", "will_retain"]


def get_latest_eve_file(directory):
    files = [f for f in os.listdir(directory) if f.startswith("eve.json") and not f.endswith(".gz")]
    if not files:
        return None
    files.sort(key=lambda x: os.path.getmtime(os.path.join(directory, x)), reverse=True)
    return os.path.join(directory, files[0])


def tail_f(directory):
    current_file = get_latest_eve_file(directory)
    if not current_file:
        print(f"No eve.json found in {directory}, retrying...")
        while not current_file:
            time.sleep(5)
            current_file = get_latest_eve_file(directory)
    print(f"Tailing: {current_file}")

    while True:
        with open(current_file, "r") as f:
            f.seek(0, 1)
            while True:
                line = f.readline()
                if not line:
                    new_file = get_latest_eve_file(directory)
                    if new_file and new_file != current_file:
                        print(f"File rotated -> {new_file}")
                        current_file = new_file
                        break
                    time.sleep(0.1)
                    continue
                yield line


def cleanup_client_map():
    now = datetime.utcnow()
    expired = [k for k, (_, t) in client_map.items() if (now - t).total_seconds() > CACHE_TTL]
    for k in expired:
        del client_map[k]
    if expired:
        print(f"[CLEANUP] Removed {len(expired)} expired clients")


def clean_payload_for_json(payload_str):
    """Basic clean for JSON-like strings (remove repeated pattern artifacts)."""
    payload_str = re.sub(r'"[^"]*\s*\*\s*\d+"', '"REPEATED_DATA"', payload_str)
    return payload_str


def process_mqtt_event(event, write_api):
    timestamp = event.get("timestamp")
    src_ip = event.get("src_ip")
    dest_ip = event.get("dest_ip")
    src_port = event.get("src_port")
    dest_port = event.get("dest_port")

    if not src_ip or not src_port:
        return

    key = (src_ip, src_port)
    client_id = "unknown"

    # Retrieve from cache if exists
    if key in client_map:
        client_id, last_seen = client_map[key]
        client_map[key] = (client_id, datetime.utcnow())

    # Handle MQTT flow event
    if event.get("app_proto") == "mqtt" and event.get("event_type") == "flow":
        flow = event.get("flow", {})
        bytes_toserver = flow.get("bytes_toserver", 0)
        pkts_toserver = flow.get("pkts_toserver", 0)
        state = flow.get("state", "unknown")

        mqtt_type = "publish_flow" if bytes_toserver > 200 else "flow"

        point = (
            Point("mqtt_event")
            .tag("mqtt_type", mqtt_type)
            .tag("src_ip", src_ip)
            .tag("src_port", str(src_port))
            .tag("dest_ip", dest_ip or "")
            .tag("dest_port", str(dest_port) if dest_port else "")
            .tag("client_id", client_id)
            .field("bytes_toserver", bytes_toserver)
            .field("pkts_toserver", pkts_toserver)
            .field("state", state)
            .field("topic", "unknown_flow_topic")
            .field("payload_raw", f"Flow data: {bytes_toserver} bytes")
            .time(timestamp, WritePrecision.NS)
        )
        write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)
        print(f"[WRITE FLOW] {mqtt_type} | {src_ip}:{src_port} | client_id: {client_id} | bytes: {bytes_toserver}")
        return

    # Handle MQTT application-layer events
    mqtt_data = event.get("mqtt", {})
    if not mqtt_data:
        return

    mqtt_type = list(mqtt_data.keys())[0]  # e.g. 'connect', 'publish'
    mqtt_value = mqtt_data[mqtt_type]

    # Update cache on CONNECT
    if mqtt_type == "connect" and "client_id" in mqtt_value:
        client_id = mqtt_value["client_id"]
        client_map[key] = (client_id, datetime.utcnow())

    point = (
        Point("mqtt_event")
        .tag("mqtt_type", mqtt_type)
        .tag("src_ip", src_ip)
        .tag("src_port", str(src_port))
        .tag("dest_ip", dest_ip or "")
        .tag("dest_port", str(dest_port) if dest_port else "")
        .tag("client_id", client_id)
        .time(timestamp, WritePrecision.NS)
    )

    # Add top-level MQTT fields
    for field in MQTT_FIELDS_TOP:
        if field in mqtt_value:
            point = point.field(field, mqtt_value[field])

    # Add JSON/list fields
    for field in MQTT_FIELDS_JSON:
        if field in mqtt_value:
            point = point.field(field, json.dumps(mqtt_value[field]))

    # Add flag fields
    if "flags" in mqtt_value and isinstance(mqtt_value["flags"], dict):
        flags = mqtt_value["flags"]
        for flag in MQTT_FIELDS_FLAGS:
            if flag in flags:
                point = point.field(f"flags_{flag}", flags[flag])

    # Add client identifier
    if "client_id" in mqtt_value:
        point = point.field("client_identifier", mqtt_value["client_id"])

    # Handle payload in PUBLISH
    if mqtt_type == "publish":
        payload = mqtt_value.get("payload") or mqtt_value.get("payload_printable", "")
        if payload:
            cleaned = clean_payload_for_json(str(payload))
            point = point.field("payload_raw", cleaned[:PAYLOAD_LIMIT])

            try:
                payload_data = json.loads(cleaned)
                if isinstance(payload_data, dict):
                    def flatten_payload(d, parent_key='payload', sep='_'):
                        items = []
                        for k, v in d.items():
                            new_key = f"{parent_key}{sep}{k}" if parent_key else k
                            if isinstance(v, dict):
                                items.extend(flatten_payload(v, new_key, sep=sep).items())
                            else:
                                items.append((new_key, str(v)))
                        return dict(items)

                    payload_flattened = flatten_payload(payload_data)
                    for pkey, pvalue in payload_flattened.items():
                        point = point.field(pkey, pvalue)
                else:
                    point = point.field("payload_value", str(payload_data))
            except json.JSONDecodeError:
                pass  # keep payload_raw only

    write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)
    print(f"[WRITE] {mqtt_type} | {src_ip}:{src_port} | client_id: {client_id}")

    if len(client_map) % 100 == 0:
        cleanup_client_map()


def main():
    print("MQTT EVE Forwarder Starting...")
    client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
    write_api = client.write_api(write_options=SYNCHRONOUS)

#    try:
#        health = client.health()
#        print(f"[INFO] InfluxDB health: {health.status}")
#    except Exception as e:
#        print(f"[FATAL] Cannot connect to InfluxDB: {e}")
#        return

    for line in tail_f(EVE_DIR):
        try:
            event = json.loads(line)
            event_type = event.get("event_type")
            app_proto = event.get("app_proto")

            # Only process MQTT-related events
            if event_type == "mqtt" or (app_proto == "mqtt" and event_type == "flow"):
                process_mqtt_event(event, write_api)

        except json.JSONDecodeError:
            continue
        except Exception as e:
            print(f"[ERROR] {e}")


if __name__ == "__main__":
    main()
