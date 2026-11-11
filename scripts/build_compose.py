#!/usr/bin/env python3
"""Generate plain Compose JSON (valid YAML) using reviewed image locks."""
import json
from pathlib import Path


def build():
    images = json.loads(Path("deploy/images.lock.json").read_text())["images"]
    services = {}
    volumes = {}

    def service(name, profile, memory, cpu, env=None, deps=(), command=None, health=None, mounts=(), ports=()):
        s = {"image": images[name]["image"], "profiles": [profile], "restart": "unless-stopped",
            "labels": {"org.ti-brief.managed": "true"},
            "platform": "linux/amd64", "mem_limit": f"{memory}m", "memswap_limit": f"{memory}m", "cpus": cpu,
            "logging": {"driver": "json-file", "options": {"max-size": "10m", "max-file": "3"}}}
        if env:
            s["environment"] = env
        if deps:
            s["depends_on"] = {d: {"condition": "service_healthy"} for d in deps}
        if command:
            s["command"] = command
        if mounts:
            s["volumes"] = [f"{v}:{target}" for v, target in mounts]
            volumes.update({v: {} for v, _ in mounts})
        if ports:
            s["ports"] = ports
        if health:
            s["healthcheck"] = {"test": health, "interval": "15s", "timeout": "5s", "retries": 40, "start_period": "120s"}
        services[name] = s
        return s

    def secret(name):
        return "${" + name + ":?Run python3 scripts/init_env.py first}"

    service("misp-db", "misp", 384, 0.75, {
        "MYSQL_DATABASE": "misp", "MYSQL_USER": "misp", "MYSQL_PASSWORD": secret("MYSQL_PASSWORD"),
        "MYSQL_ROOT_PASSWORD": secret("MYSQL_ROOT_PASSWORD")},
        command=["--innodb-buffer-pool-size=128M", "--innodb-log-file-size=64M", "--max-connections=40"],
        health=["CMD", "healthcheck.sh", "--connect", "--innodb_initialized"], mounts=[("misp_db", "/var/lib/mysql")])
    service("misp-redis", "misp", 128, 0.25, {"REDIS_PASSWORD": secret("REDIS_PASSWORD")},
        command=["sh", "-c", 'exec valkey-server --requirepass "$$REDIS_PASSWORD" --maxmemory 64mb --maxmemory-policy noeviction --appendonly yes'],
        health=["CMD-SHELL", 'REDISCLI_AUTH="$$REDIS_PASSWORD" valkey-cli ping | grep -q PONG'], mounts=[("misp_cache", "/data")])
    service("misp-modules", "misp", 512, 0.5,
        health=["CMD-SHELL", "bash -c '</dev/tcp/localhost/6666'"])
    core_env = {key: secret(key) for key in ("ADMIN_PASSWORD", "ADMIN_KEY", "MYSQL_PASSWORD", "REDIS_PASSWORD", "GPG_PASSPHRASE", "ENCRYPTION_KEY", "SALT")}
    core_env.update({"BASE_URL": "${BASE_URL:-http://localhost:8081}", "ADMIN_EMAIL": "${ADMIN_EMAIL:-admin@intel.test}",
        "ADMIN_ORG": "${ADMIN_ORG:-Private Intel Lab}", "MYSQL_HOST": "misp-db", "MYSQL_DATABASE": "misp", "MYSQL_USER": "misp",
        "REDIS_HOST": "misp-redis", "MISP_MODULES_FQDN": "http://misp-modules", "MISP_MODULES_PORT": "6666",
        "PHP_MEMORY_LIMIT": "256M", "PHP_FCGI_CHILDREN": "2", "PHP_FCGI_START_SERVERS": "1", "PHP_FCGI_SPARE_SERVERS": "1",
        "NUM_WORKERS_DEFAULT": "1", "NUM_WORKERS_PRIO": "1", "NUM_WORKERS_EMAIL": "1", "NUM_WORKERS_CACHE": "1", "NUM_WORKERS_UPDATE": "1",
        "ENABLE_BACKGROUND_UPDATES": "false", "DISABLE_PRINTING_PLAINTEXT_CREDENTIALS": "true", "TZ": "UTC"})
    service("misp-core", "misp", 1024, 1.5, core_env, deps=("misp-db", "misp-redis", "misp-modules"),
        mounts=[("misp_config", "/var/www/MISP/app/Config"), ("misp_files", "/var/www/MISP/app/files"),
                ("misp_logs", "/var/www/MISP/app/tmp/logs"), ("misp_gpg", "/var/www/MISP/.gnupg")],
        health=["CMD-SHELL", "bash -c 'echo >/dev/tcp/127.0.0.1/9002'"])
    nginx = service("misp-nginx", "misp", 64, 0.25, {"BASE_URL": "${BASE_URL:-http://localhost:8081}",
        "FASTCGI_LISTEN": "misp-core:9002", "FASTCGI_LISTEN_STATUS": "misp-core:9003", "TZ": "UTC"},
        deps=("misp-core",), ports=["127.0.0.1:8081:8080"],
        health=["CMD", "curl", "-fsS", "--max-time", "4", "--output", "/dev/null", "http://127.0.0.1:8080/users/login"])
    nginx.update(user="nginx", read_only=True, security_opt=["no-new-privileges:true"], cap_drop=["ALL"],
        tmpfs=["/etc/nginx/conf.d:mode=0755,uid=101,gid=101", "/var/cache/nginx:mode=0755,uid=101,gid=101", "/tmp:mode=1777"])
    service("elasticsearch", "opencti", 1536, 1.5, {"discovery.type": "single-node", "xpack.security.enabled": "false",
        "xpack.ml.enabled": "false", "ES_JAVA_OPTS": "-Xms768m -Xmx768m"}, mounts=[("opencti_es", "/usr/share/elasticsearch/data")],
        health=["CMD-SHELL", "curl -fsS 'http://localhost:9200/_cluster/health?wait_for_status=yellow' >/dev/null"])
    service("redis", "opencti", 256, 0.5, command=["redis-server", "--maxmemory", "128mb", "--maxmemory-policy", "noeviction", "--appendonly", "yes"],
        mounts=[("opencti_redis", "/data")], health=["CMD", "redis-cli", "ping"])
    rabbit = service("rabbitmq", "opencti", 384, 0.5, {"RABBITMQ_DEFAULT_USER": secret("RABBITMQ_DEFAULT_USER"),
        "RABBITMQ_DEFAULT_PASS": secret("RABBITMQ_DEFAULT_PASS"), "RABBITMQ_SERVER_ADDITIONAL_ERL_ARGS": "+S 1:1"},
        mounts=[("opencti_rabbit", "/var/lib/rabbitmq")], health=["CMD", "rabbitmq-diagnostics", "-q", "ping"])
    rabbit.setdefault("volumes", []).append("./rabbitmq.conf:/etc/rabbitmq/rabbitmq.conf:ro")
    service("minio", "opencti", 192, 0.5, {"MINIO_ROOT_USER": secret("MINIO_ROOT_USER"), "MINIO_ROOT_PASSWORD": secret("MINIO_ROOT_PASSWORD")},
        command=["server", "/data"], mounts=[("opencti_s3", "/data")], health=["CMD", "silo", "healthcheck", "ready"])
    env = {"NODE_OPTIONS": "--max-old-space-size=1024", "APP__PORT": "8080", "APP__BASE_URL": "http://localhost:8080",
        "APP__ADMIN__EMAIL": "${OPENCTI_ADMIN_EMAIL:-admin@intel.test}", "APP__ADMIN__PASSWORD": secret("OPENCTI_ADMIN_PASSWORD"),
        "APP__ADMIN__TOKEN": secret("OPENCTI_ADMIN_TOKEN"), "APP__ENCRYPTION_KEY": secret("OPENCTI_ENCRYPTION_KEY"),
        "APP__HEALTH_ACCESS_KEY": secret("OPENCTI_HEALTH_KEY"), "REDIS__HOSTNAME": "redis", "REDIS__PORT": "6379",
        "ELASTICSEARCH__URL": "http://elasticsearch:9200", "ELASTICSEARCH__NUMBER_OF_REPLICAS": "0",
        "MINIO__ENDPOINT": "minio", "MINIO__PORT": "9000", "MINIO__USE_SSL": "false",
        "MINIO__ACCESS_KEY": secret("MINIO_ROOT_USER"), "MINIO__SECRET_KEY": secret("MINIO_ROOT_PASSWORD"),
        "RABBITMQ__HOSTNAME": "rabbitmq", "RABBITMQ__PORT": "5672", "RABBITMQ__PORT_MANAGEMENT": "15672",
        "RABBITMQ__MANAGEMENT_SSL": "false", "RABBITMQ__USERNAME": secret("RABBITMQ_DEFAULT_USER"),
        "RABBITMQ__PASSWORD": secret("RABBITMQ_DEFAULT_PASS"), "PROVIDERS__LOCAL__STRATEGY": "LocalStrategy"}
    service("opencti", "opencti", 1536, 1.5, env, deps=("elasticsearch", "redis", "rabbitmq", "minio"),
        ports=["127.0.0.1:8080:8080"], health=["CMD-SHELL", 'wget -qO- "http://127.0.0.1:8080/health?health_access_key=$$APP__HEALTH_ACCESS_KEY" >/dev/null'])
    service("worker", "opencti", 192, 0.75, {"OPENCTI_URL": "http://opencti:8080", "OPENCTI_TOKEN": secret("OPENCTI_ADMIN_TOKEN")}, deps=("opencti",))
    # Connector profile requires both platform profiles; one-way import only.
    service("connector-misp", "integration", 256, 0.5, {"OPENCTI_URL": "http://opencti:8080",
        "OPENCTI_TOKEN": secret("OPENCTI_ADMIN_TOKEN"), "CONNECTOR_ID": secret("MISP_CONNECTOR_ID"),
        "CONNECTOR_NAME": "MISP private lab", "CONNECTOR_SCOPE": "misp", "CONNECTOR_LOG_LEVEL": "info", "CONNECTOR_DURATION_PERIOD": "PT5M",
        "MISP_URL": "http://misp-nginx:8080", "MISP_KEY": secret("ADMIN_KEY"), "MISP_SSL_VERIFY": "true",
        "MISP_REFERENCE_URL": "http://localhost:8081", "MISP_IMPORT_FROM_DATE": "${MISP_IMPORT_FROM_DATE:-2026-11-01}",
        "MISP_CREATE_REPORTS": "true", "MISP_CREATE_INDICATORS": "true", "MISP_CREATE_OBSERVABLES": "true",
        "MISP_IMPORT_ONLY_PUBLISHED": "false", "MISP_IMPORT_WITH_ATTACHMENTS": "false", "MISP_GUESS_THREATS_FROM_TAGS": "false",
        "MISP_SEARCH_LIMIT": "100", "OPENCTI_TLS_REJECT_UNAUTHORIZED": "true"}, deps=("opencti", "misp-nginx"))
    return {"name": "ti-lab", "services": services, "volumes": volumes}


if __name__ == "__main__":
    Path("deploy/compose.json").write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")
