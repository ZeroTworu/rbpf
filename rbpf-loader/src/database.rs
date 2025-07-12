use log::{info, warn};
use rbpf_common::rules::rules::RuleWithName;
use sqlx::{Row, SqlitePool, migrate::Migrator};
use std::net::Ipv6Addr;
use std::path::Path;
use std::str::FromStr;
use std::sync::OnceLock;
use tokio::fs::OpenOptions;

static DB: OnceLock<SqlitePool> = OnceLock::new();

pub async fn init_db(db_url: &str) -> anyhow::Result<()> {
    if !Path::new(db_url).exists() {
        OpenOptions::new()
            .create(true)
            .write(true)
            .open(db_url)
            .await?;
    }
    let url = format!("sqlite://{}", db_url);
    info!("Connecting to {}", url);
    let pool = SqlitePool::connect(&url).await.expect("DB init failed");
    DB.set(pool).expect("DB already initialized");
    Ok(())
}

pub fn get_db() -> &'static SqlitePool {
    DB.get().expect("DB not initialized")
}

pub async fn migrate(migrations_path: &str) -> anyhow::Result<()> {
    let path = Path::new(migrations_path);
    if !path.exists() {
        warn!(
            "Can not migrate database from {}, path does not exist.",
            path.display()
        );
        return Ok(());
    }
    info!("Migrating database from {}", path.display());
    let migrations = Migrator::new(path).await?;
    migrations.run(get_db()).await?;
    Ok(())
}

pub async fn fetch_rules() -> anyhow::Result<Vec<RuleWithName>> {
    let rows = sqlx::query(
        r#"
        SELECT
            rule_name, id as rule_id, "drop", ok, v4, v6, tcp, udp, "on",
            source_addr_v6, destination_addr_v6,
            source_addr_v4, destination_addr_v4,
            ifindex, "order",
            source_port_start, source_port_end,
            destination_port_start, destination_port_end,
            input, output,
            source_mask_v4, destination_mask_v4,
            source_mask_v6, destination_mask_v6
        FROM rules
        "#,
    )
    .fetch_all(get_db())
    .await?;

    let mut rules = Vec::with_capacity(rows.len());

    for row in rows {
        let src_v6: String = row.get("source_addr_v6");
        let dst_v6: String = row.get("destination_addr_v6");

        let src_ip = parse_ipv6(&src_v6).unwrap_or_else(|_| 0);
        let dst_ip = parse_ipv6(&dst_v6).unwrap_or_else(|_| 0);

        rules.push(RuleWithName {
            name: row.get("rule_name"),
            order: row.get("order"),

            drop: row.get("drop"),
            ok: row.get("ok"),
            v4: row.get("v4"),
            v6: row.get("v6"),
            tcp: row.get("tcp"),
            udp: row.get("udp"),
            on: row.get("on"),

            src_ip_high: (src_ip >> 64) as u64,
            src_ip_low: src_ip as u64,
            dst_ip_high: (dst_ip >> 64) as u64,
            dst_ip_low: dst_ip as u64,

            source_addr_v4: row.get("source_addr_v4"),
            destination_addr_v4: row.get("destination_addr_v4"),
            rule_id: row.get("rule_id"),
            ifindex: row.get("ifindex"),

            source_port_start: row.get("source_port_start"),
            source_port_end: row.get("source_port_end"),
            destination_port_start: row.get("destination_port_start"),
            destination_port_end: row.get("destination_port_end"),

            input: row.get("input"),
            output: row.get("output"),

            source_mask_v4: row.get("source_mask_v4"),
            destination_mask_v4: row.get("destination_mask_v4"),
            source_mask_v6: row.get("source_mask_v6"),
            destination_mask_v6: row.get("destination_mask_v6"),
            from_db: true,
        });
    }

    Ok(rules)
}

pub async fn update_rule(rule: &RuleWithName) -> bool {
    let src_v6 = u128::from(rule.src_ip_high) << 64 | rule.src_ip_low as u128;
    let dst_v6 = u128::from(rule.dst_ip_high) << 64 | rule.dst_ip_low as u128;

    let src_v6_str = Ipv6Addr::from(src_v6).to_string();
    let dst_v6_str = Ipv6Addr::from(dst_v6).to_string();

    let result = sqlx::query(
        r#"
        UPDATE rules SET
            rule_name = ?,
            "drop" = ?, ok = ?, v4 = ?, v6 = ?, tcp = ?, udp = ?, "on" = ?,
            source_addr_v6 = ?, destination_addr_v6 = ?,
            source_addr_v4 = ?, destination_addr_v4 = ?,
            ifindex = ?, "order" = ?,
            source_port_start = ?, source_port_end = ?,
            destination_port_start = ?, destination_port_end = ?,
            input = ?, output = ?,
            source_mask_v4 = ?, destination_mask_v4 = ?,
            source_mask_v6 = ?, destination_mask_v6 = ?
        WHERE id = ?
        "#,
    )
    .bind(&rule.name)
    .bind(rule.drop)
    .bind(rule.ok)
    .bind(rule.v4)
    .bind(rule.v6)
    .bind(rule.tcp)
    .bind(rule.udp)
    .bind(rule.on)
    .bind(&src_v6_str)
    .bind(&dst_v6_str)
    .bind(rule.source_addr_v4)
    .bind(rule.destination_addr_v4)
    .bind(rule.ifindex)
    .bind(rule.order)
    .bind(rule.source_port_start)
    .bind(rule.source_port_end)
    .bind(rule.destination_port_start)
    .bind(rule.destination_port_end)
    .bind(rule.input)
    .bind(rule.output)
    .bind(rule.source_mask_v4)
    .bind(rule.destination_mask_v4)
    .bind(rule.source_mask_v6)
    .bind(rule.destination_mask_v6)
    .bind(rule.rule_id)
    .execute(get_db())
    .await;

    match result {
        Ok(_) => {
            info!(
                "DB update_rule success, id: {}, name {}",
                rule.rule_id, rule.name
            );
            true
        }
        Err(e) => {
            warn!(
                "DB err in update_rule: {:?}, id: {}, name {}",
                e, rule.rule_id, rule.name
            );
            false
        }
    }
}

pub async fn insert_rule(rule: &RuleWithName) -> i64 {
    let src_v6 = u128::from(rule.src_ip_high) << 64 | rule.src_ip_low as u128;
    let dst_v6 = u128::from(rule.dst_ip_high) << 64 | rule.dst_ip_low as u128;

    let src_v6_str = Ipv6Addr::from(src_v6).to_string();
    let dst_v6_str = Ipv6Addr::from(dst_v6).to_string();

    let row = sqlx::query(
        r#"
        INSERT INTO rules (
            rule_name,
            "drop", ok, v4, v6, tcp, udp, "on",
            source_addr_v6, destination_addr_v6,
            source_addr_v4, destination_addr_v4,
            ifindex, "order",
            source_port_start, source_port_end,
            destination_port_start, destination_port_end,
            input, output,
            source_mask_v4, destination_mask_v4,
            source_mask_v6, destination_mask_v6
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING id
        "#,
    )
    .bind(&rule.name)
    .bind(rule.drop)
    .bind(rule.ok)
    .bind(rule.v4)
    .bind(rule.v6)
    .bind(rule.tcp)
    .bind(rule.udp)
    .bind(rule.on)
    .bind(&src_v6_str)
    .bind(&dst_v6_str)
    .bind(rule.source_addr_v4)
    .bind(rule.destination_addr_v4)
    .bind(rule.ifindex)
    .bind(rule.order)
    .bind(rule.source_port_start)
    .bind(rule.source_port_end)
    .bind(rule.destination_port_start)
    .bind(rule.destination_port_end)
    .bind(rule.input)
    .bind(rule.output)
    .bind(rule.source_mask_v4)
    .bind(rule.destination_mask_v4)
    .bind(rule.source_mask_v6)
    .bind(rule.destination_mask_v6)
    .execute(get_db())
    .await;

    match row {
        Ok(row) => {
            let rule_id = row.last_insert_rowid();
            info!(
                "DB insert_rule success, id: {}, name: {}",
                rule_id, rule.name
            );
            rule_id
        }
        Err(e) => {
            warn!("DB err in insert_rule: {:?}, name: {}", e, rule.name);
            0
        }
    }
}

fn parse_ipv6(s: &str) -> anyhow::Result<u128> {
    if let Ok(ip) = Ipv6Addr::from_str(s) {
        return Ok(u128::from(ip));
    }

    if let Some(stripped) = s.strip_prefix("0x") {
        return Ok(u128::from_str_radix(stripped, 16)?);
    }

    Err(anyhow::anyhow!("Invalid IPv6/hex address: {}", s))
}
