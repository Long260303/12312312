#!/usr/bin/env python3
import time
import re
import pandas as pd
import ipaddress
import json
from datetime import datetime
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
import yagmail
import os
import warnings

# --- Ignore warnings ---
warnings.filterwarnings("ignore", message=".*arrow.*", category=FutureWarning)
warnings.filterwarnings("ignore", message=".*DeprecationWarning:.*pandas.*", category=DeprecationWarning)

# --- Configuration (env override) ---
INFLUX_URL = os.getenv("INFLUX_URL", "http://localhost:8086")
INFLUX_TOKEN = os.getenv("INFLUX_TOKEN", "iot-admin-token-123")
INFLUX_ORG = os.getenv("INFLUX_ORG", "iot-org")
SRC_BUCKET = os.getenv("SRC_BUCKET", "iot-data")
ALERT_BUCKET = os.getenv("ALERT_BUCKET", "iot-data")

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
EMAIL_TO = [e.strip() for e in os.getenv("EMAIL_TO", "").split(",") if e.strip()]

CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", "5"))
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "300"))
PAYLOAD_LIMIT = int(os.getenv("PAYLOAD_LIMIT", "1024"))

# Thresholds
RECONNECT_THRESHOLD = int(os.getenv("RECONNECT_THRESHOLD", "5"))
RETAIN_THRESHOLD = int(os.getenv("RETAIN_THRESHOLD", "5"))
PUBLISH_FLOOD_THRESHOLD = int(os.getenv("PUBLISH_FLOOD_THRESHOLD", "10"))
ENUMERATION_THRESHOLD = int(os.getenv("ENUMERATION_THRESHOLD", "5"))

ANOMALY_KEYWORDS = [
    "AAAAAA", "script", "DROP TABLE", "rm -rf", "<script>",
    "SELECT", "UNION", "payload_attack", "alert(", "onload=",
    "wildcard_abuser", "flood_attacker", "duplicate_attacker", "topic_enum",
    "replayer", "retain_abuse", "attack_type", "abuse", "storm_data",
    "flood_payload", "retain_data"
]

VALID_TOPICS = [
    "factory/office/", "factory/security/", "factory/production/",
    "factory/storage/", "factory/energy/", "system/status", "system/health"
]

PRIVATE_NETS = [
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
]

ALERT_COOLDOWN = {}
COOLDOWN_SECONDS = int(os.getenv("COOLDOWN_SECONDS", "300"))

SIMULATED_ZONES = ["office", "production", "storage", "security", "energy"]


# --- Utilities ---
def send_email(subject, message):
    try:
        if not EMAIL_USER or not EMAIL_PASS or not EMAIL_TO:
            print("[WARN] Email credentials not configured, skipping send.")
            return
        yag = yagmail.SMTP(EMAIL_USER, EMAIL_PASS)
        full_msg = f"""{message}

[Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 
[Source: MQTT Rule Detect Daemon]
"""
        yag.send(to=EMAIL_TO, subject=subject, contents=full_msg)
        print(f"[EMAIL] Sent: {subject}")
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")


def should_alert(key):
    now = time.time()
    if key in ALERT_COOLDOWN and now - ALERT_COOLDOWN[key] < COOLDOWN_SECONDS:
        return False
    ALERT_COOLDOWN[key] = now
    return True


def write_alert(write_api, alert_type, src_ip, client_id, message):
    try:
        safe_client_id = str(client_id).strip() if client_id else "unknown"
        if safe_client_id.lower() in ["nan", "none", ""]:
            safe_client_id = "unknown"
        point = (
            Point("mqtt_alert")
            .tag("type", alert_type)
            .tag("src_ip", src_ip or "unknown")
            .tag("client_id", safe_client_id)
            .field("message", message)
            .time(time.time_ns(), WritePrecision.NS)
        )
        write_api.write(bucket=ALERT_BUCKET, org=INFLUX_ORG, record=point)
        print(f"[ALERT] {alert_type} | {src_ip} | {safe_client_id} | {message[:120]}")
    except Exception as e:
        print(f"[WRITE ERROR] {e}")


def is_public(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return not any(addr in net for net in PRIVATE_NETS)
    except ValueError:
        return False


def parse_subscribe_topics(topics_str):
    if not topics_str or topics_str == "[]":
        return set()
    try:
        topics_list = json.loads(topics_str)
        if isinstance(topics_list, list):
            return {t.get("topic", "") for t in topics_list if t.get("topic")}
    except Exception:
        cleaned = re.sub(r'[\[\]\"]', '', str(topics_str))
        return {p.strip() for p in re.split(r'[,\s]+', cleaned) if p.strip()}
    return set()


def detect_wildcard_abuse(topics_set):
    return any(t.count("#") > 0 or t.count("+") > 2 for t in topics_set)


def detect_payload_anomaly(payload):
    if not payload:
        return False
    if len(payload) > PAYLOAD_LIMIT:
        return True
    low = payload.lower()
    if any(kw.lower() in low for kw in ANOMALY_KEYWORDS):
        return True
    if re.search(r"[^a-zA-Z0-9\s\.,:{}_\-\[\]\(\)\"']", payload) and len(payload) > 500:
        return True
    return False


def is_simulated_device(client_id, topic, payload):
    if client_id and "-replayer" in client_id:
        return True
    if topic and any(topic.startswith(f"factory/{z}/") for z in SIMULATED_ZONES):
        return True
    if payload:
        try:
            data = json.loads(payload)
            if isinstance(data, dict) and data.get("zone") in SIMULATED_ZONES:
                return True
        except Exception:
            pass
    return False


# --- Main ---
def main():
    print("[INIT] Connecting to InfluxDB...")
    client = query_api = write_api = None
    while True:
        try:
            client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
            query_api = client.query_api()
            write_api = client.write_api(write_options=SYNCHRONOUS)
            client.health()
            print("[INIT] Connected successfully.")
            break
        except Exception as e:
            print(f"[CONNECT ERROR] {e}. Retrying in 10s...")
            time.sleep(10)

    print(f"[START] Detection loop started. Window: {WINDOW_SECONDS}s, Interval: {CHECK_INTERVAL}s")

    while True:
        try:
            query = f'''
from(bucket: "{SRC_BUCKET}")
  |> range(start: -{WINDOW_SECONDS}s)
  |> filter(fn: (r) => r._measurement == "mqtt_event")
  |> filter(fn: (r) => r._field != "client_id")
  |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
  |> keep(columns: ["_time", "src_ip", "client_id", "mqtt_type", "topic", "payload_raw", 
                    "retain", "qos", "client_identifier", "topics", "app_proto"])
'''
            df_list = query_api.query_data_frame(org=INFLUX_ORG, query=query)

            if isinstance(df_list, list):
                df = pd.concat(df_list, ignore_index=True) if df_list else pd.DataFrame()
            else:
                df = df_list

            if df.empty:
                print(f"[QUERY] Empty. Sleeping {CHECK_INTERVAL}s...")
                time.sleep(CHECK_INTERVAL)
                continue

            print(f"[QUERY] Loaded {len(df)} events.")

            # --- Normalize columns safely ---
            def ensure_column(col, default):
                if col not in df.columns:
                    df[col] = pd.Series([default] * len(df))
                df[col] = df[col].fillna(default)

            ensure_column("client_id", "unknown")
            ensure_column("payload_raw", "")
            ensure_column("topic", "")
            ensure_column("retain", "0")
            ensure_column("qos", "0")
            ensure_column("src_ip", "unknown")
            ensure_column("topics", "[]")

            # Remove simulated devices
            df["is_simulated"] = df.apply(
                lambda r: is_simulated_device(r["client_id"], r["topic"], r["payload_raw"]), axis=1
            )
            simulated_count = df["is_simulated"].sum()
            df = df[~df["is_simulated"]].copy()
            print(f"[FILTER] Removed {simulated_count} simulated events. Remaining: {len(df)}")

            if df.empty:
                print("[INFO] All simulated. Skipping.")
                time.sleep(CHECK_INTERVAL)
                continue

            subscribe_df = df[df["mqtt_type"] == "subscribe"].copy() if "mqtt_type" in df.columns else pd.DataFrame()

            # --- RULES ---

            # Duplicate ID
            connect_df = df[df["mqtt_type"] == "connect"] if "mqtt_type" in df.columns else pd.DataFrame()
            if not connect_df.empty:
                for cid, cnt in connect_df.groupby("client_id").size().items():
                    if cnt >= 2 and should_alert(("duplicate_id", cid)):
                        ips = connect_df[connect_df["client_id"] == cid]["src_ip"].unique()
                        msg = f"Duplicate client_id '{cid}' used {cnt} times from: {', '.join(ips)}"
                        write_alert(write_api, "duplicate_id", ",".join(ips), cid, msg)
                        send_email("MQTT Duplicate ID", msg)

            # Reconnect storm
            recon_df = df[df["mqtt_type"].isin(["connect", "disconnect"])] if "mqtt_type" in df.columns else pd.DataFrame()
            for (ip, cid), cnt in recon_df.groupby(["src_ip", "client_id"]).size().items():
                if cnt >= RECONNECT_THRESHOLD and should_alert(("reconnect_storm", ip, cid)):
                    msg = f"Reconnect storm: {cnt} events from {ip} (client_id: {cid})"
                    write_alert(write_api, "reconnect_storm", ip, cid, msg)
                    send_email("Reconnect Storm", msg)

            # Wildcard abuse
            if not subscribe_df.empty:
                subscribe_df["topics_set"] = subscribe_df["topics"].apply(parse_subscribe_topics)
                for _, r in subscribe_df.iterrows():
                    if detect_wildcard_abuse(r["topics_set"]) and should_alert(("wildcard_abuse", r["src_ip"], r["client_id"])):
                        bad = [t for t in r["topics_set"] if "#" in t or "+" in t]
                        msg = f"Wildcard abuse: {bad} from {r['src_ip']} (client_id: {r['client_id']})"
                        write_alert(write_api, "wildcard_abuse", r["src_ip"], r["client_id"], msg)
                        send_email("Wildcard Abuse", msg)

            # Retain + QoS
            retain_df = df[(df["mqtt_type"] == "publish") & (df["retain"] == "1") & (df["qos"].isin(["1", "2"]))] if "mqtt_type" in df.columns else pd.DataFrame()
            for (ip, cid), cnt in retain_df.groupby(["src_ip", "client_id"]).size().items():
                if cnt >= RETAIN_THRESHOLD and should_alert(("retain_qos_abuse", ip, cid)):
                    msg = f"Retain QoS abuse: {cnt} msgs from {ip} (client_id: {cid})"
                    write_alert(write_api, "retain_qos_abuse", ip, cid, msg)
                    send_email("Retain QoS Abuse", msg)

            # Payload anomaly
            payload_df = df[df["mqtt_type"].isin(["publish", "publish_flow"])] if "mqtt_type" in df.columns else df
            for _, r in payload_df.iterrows():
                if detect_payload_anomaly(r["payload_raw"]) and should_alert(("payload_anomaly", r["src_ip"], r["client_id"])):
                    msg = f"Payload anomaly from {r['src_ip']} (client_id: {r['client_id']}) | Sample: {r['payload_raw'][:200]}..."
                    write_alert(write_api, "payload_anomaly", r["src_ip"], r["client_id"], msg)
                    send_email("Payload Anomaly", msg)

            # Unauthorized topic
            topic_df = df[df["mqtt_type"].isin(["publish", "subscribe"]) & (df["topic"] != "")]
            for _, r in topic_df.iterrows():
                if not any(r["topic"].startswith(v) for v in VALID_TOPICS) and should_alert(("unauthorized_topic", r["src_ip"], r["client_id"], r["topic"][:50])):
                    msg = f"Unauthorized topic '{r['topic']}' ({r['mqtt_type']}) from {r['src_ip']} (client_id: {r['client_id']})"
                    write_alert(write_api, "unauthorized_topic", r["src_ip"], r["client_id"], msg)
                    send_email("Unauthorized Topic", msg)

            # Publish flood
            publish_df = df[df["mqtt_type"].isin(["publish", "publish_flow"])] if "mqtt_type" in df.columns else pd.DataFrame()
            for (ip, cid), cnt in publish_df.groupby(["src_ip", "client_id"]).size().items():
                if cnt > PUBLISH_FLOOD_THRESHOLD and should_alert(("publish_flood", ip, cid)):
                    msg = f"Publish flood: {cnt} msgs from {ip} (client_id: {cid})"
                    write_alert(write_api, "publish_flood", ip, cid, msg)
                    send_email("MQTT Publish Flood", msg)

            # Topic enumeration
            if not subscribe_df.empty:
                subscribe_df["topics_set"] = subscribe_df["topics"].apply(parse_subscribe_topics)
                grouped = subscribe_df.groupby(["src_ip", "client_id"])["topics_set"].agg(lambda x: set().union(*x)).reset_index()
                grouped["count"] = grouped["topics_set"].apply(len)
                for _, r in grouped.iterrows():
                    if r["count"] > ENUMERATION_THRESHOLD and should_alert(("topic_enumeration", r["src_ip"], r["client_id"])):
                        msg = f"Topic enumeration: {r['count']} unique topics from {r['src_ip']} (client_id: {r['client_id']})"
                        write_alert(write_api, "topic_enumeration", r["src_ip"], r["client_id"], msg)
                        send_email("Topic Enumeration", msg)

        except Exception as e:
            print(f"[ERROR] {e}")
            import traceback
            traceback.print_exc()

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
