#!/usr/bin/env python3
import json
import time
from datetime import datetime, timedelta
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

# --- Configuration ---
EVE_FILE = "/var/log/suricata/eve.json"  # Path to Suricata eve.json
INFLUX_URL = "http://localhost:8086"
INFLUX_TOKEN = "iot-admin-token-123"
INFLUX_ORG = "iot-org"
INFLUX_BUCKET = "iot-data"

# --- Cache: maps (src_ip, src_port) -> (client_id, last_seen_time) ---
client_map = {}
CACHE_TTL = 3600  # seconds (1 hour): remove inactive clients after this time

def tail_f(filename):
    """Continuously yield new lines from a file (like tail -f)."""
    with open(filename, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line

def cleanup_client_map():
    """Remove old client entries to prevent memory growth."""
    now = datetime.utcnow()
    expired = [key for key, (_, last_seen) in client_map.items()
               if (now - last_seen).total_seconds() > CACHE_TTL]
    for key in expired:
        del client_map[key]
    if expired:
        print(f"[CLEANUP] Removed {len(expired)} expired client entries")

def process_mqtt_event(event, write_api):
    mqtt_data = event.get("mqtt", {})
    timestamp = event.get("timestamp")
    src_ip = event.get("src_ip")
    dest_ip = event.get("dest_ip")
    src_port = event.get("src_port")
    dest_port = event.get("dest_port")

    # Skip events without essential info
    if not src_ip or not src_port:
        return

    for key, value in mqtt_data.items():
        # --- Cache key per connection ---
        key_tuple = (src_ip, src_port)
        client_id = value.get("client_id")

        # --- Update or retrieve client_id ---
        if client_id:
            client_map[key_tuple] = (client_id, datetime.utcnow())
        elif key_tuple in client_map:
            client_id, _ = client_map[key_tuple]
            # refresh timestamp
            client_map[key_tuple] = (client_id, datetime.utcnow())
        else:
            client_id = "unknown"

        # --- Build InfluxDB point ---
        point = (
            Point("mqtt_event")
            .tag("mqtt_type", key)
            .tag("src_ip", src_ip)
            .tag("src_port", str(src_port))
            .tag("dest_ip", dest_ip)
            .tag("dest_port", str(dest_port))
            .tag("client_id", client_id)
            .time(timestamp, WritePrecision.NS)
        )

        # --- Flatten MQTT subfields ---
        for subkey, subvalue in value.items():
            if isinstance(subvalue, dict):
                for sk, sv in subvalue.items():
                    point.field(f"{subkey}_{sk}", sv)
            else:
                point.field(subkey, str(subvalue))

        # --- Normalize payload (attempt JSON parse) ---
        payload = value.get("payload") or value.get("payload_printable")
        if payload:
            try:
                payload_data = json.loads(payload)
                if isinstance(payload_data, dict):
                    for pkey, pvalue in payload_data.items():
                        point.field(f"payload_{pkey}", pvalue)
                else:
                    point.field("payload_value", str(payload_data))
            except Exception:
                point.field("payload_raw", str(payload))

        # --- Write to InfluxDB ---
        write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)
        print(f"[{timestamp}] MQTT {key} event (client_id={client_id}) sent to InfluxDB")

    # --- Periodic cleanup (every 500 events roughly) ---
    if len(client_map) % 500 == 0:
        cleanup_client_map()

def main():
    client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
    write_api = client.write_api(write_options=SYNCHRONOUS)

    print(f"Watching {EVE_FILE} for MQTT events...")
    for line in tail_f(EVE_FILE):
        try:
            event = json.loads(line)
            if event.get("event_type") == "mqtt":
                process_mqtt_event(event, write_api)
        except json.JSONDecodeError:
            continue
        except Exception as e:
            print(f"[ERROR] {e}")

if __name__ == "__main__":
    main()
