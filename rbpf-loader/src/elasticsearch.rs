use crate::logs::WLogMessage;
use elasticsearch::{
    Elasticsearch,
    http::{response::Response, transport::Transport},
    indices::{IndicesCreateParts, IndicesExistsParts},
};
use log::{error, info};
use serde_json::json;
use std::net::{Ipv4Addr, Ipv6Addr};

const INDEX_NAME: &str = "log_messages";

pub struct ElasticLogs {
    client: Elasticsearch,
}

impl ElasticLogs {
    pub async fn new(host: &str) -> anyhow::Result<Self> {
        let transport = Transport::single_node(host)?;
        let client = Elasticsearch::new(transport);
        info!("Initializing Elasticsearch on host {}", host);
        Ok(ElasticLogs { client })
    }
    pub async fn create_index(&self) -> anyhow::Result<()> {
        let exists: Response = self
            .client
            .indices()
            .exists(IndicesExistsParts::Index(&[INDEX_NAME]))
            .send()
            .await?;

        if exists.status_code().is_success() {
            info!("Index already exists");
            return Ok(());
        }

        let body = json!({
            "mappings": {
                "properties": {
                    "message": { "type": "keyword", "ignore_above": 128 },
                    "input": { "type": "boolean" },
                    "output": { "type": "boolean" },
                    "v4": { "type": "boolean" },
                    "v6": { "type": "boolean" },
                    "tcp": { "type": "boolean" },
                    "udp": { "type": "boolean" },

                    "src_ip_high": { "type": "unsigned_long" },
                    "src_ip_low": { "type": "unsigned_long" },
                    "dst_ip_high": { "type": "unsigned_long" },
                    "dst_ip_low": { "type": "unsigned_long" },

                    "source_addr_v4": { "type": "ip" },
                    "destination_addr_v4": { "type": "ip" },
                    "rule_name": { "type": "keyword", "ignore_above": 128 },
                    "ifindex": { "type": "integer" },
                    "unhandled_protocol": { "type": "integer" },

                    "source_port": { "type": "integer" },
                    "destination_port": { "type": "integer" },

                    "level": { "type": "byte" },
                    "timestamp": { "type": "date", "format": "epoch_second" },
                    "source_addr_v6": { "type": "ip" },
                    "destination_addr_v6": { "type": "ip" },
                },
            },
        });

        // Создаем индекс
        let response: Response = self
            .client
            .indices()
            .create(IndicesCreateParts::Index(INDEX_NAME))
            .body(body)
            .send()
            .await?;

        if response.status_code().is_success() {
            info!("Index created successfully");
        } else {
            let error = response.text().await?;
            error!("Elasticsearch indexing failed {}", error);
            return Err(anyhow::anyhow!("Elasticsearch indexing failed {}", error));
        }

        Ok(())
    }

    pub async fn index_log_message(&self, log: &WLogMessage) -> anyhow::Result<()> {
        let message_str = String::from_utf8_lossy(&log.msg.message)
            .trim_end_matches('\0')
            .to_string();

        let source_v4 = Ipv4Addr::from(log.msg.source_addr_v4).to_string();
        let dest_v4 = Ipv4Addr::from(log.msg.destination_addr_v4).to_string();

        let src_v6_addr = ((log.msg.src_ip_high as u128) << 64) | (log.msg.src_ip_low as u128);
        let dst_v6_addr = ((log.msg.dst_ip_high as u128) << 64) | (log.msg.dst_ip_low as u128);

        let doc = json!({
            "message": message_str,
            "input": log.msg.input,
            "output": log.msg.output,
            "v4": log.msg.v4,
            "v6": !log.msg.v4,
            "tcp": log.msg.tcp,
            "udp": log.msg.udp,

            "src_ip_high": log.msg.src_ip_high,
            "src_ip_low": log.msg.src_ip_low,
            "dst_ip_high": log.msg.dst_ip_high,
            "dst_ip_low": log.msg.dst_ip_low,

            "source_addr_v4": source_v4,
            "destination_addr_v4": dest_v4,
            "rule_name": log.get_rule_name().await.to_string(),
            "ifindex": log.msg.ifindex,
            "unhandled_protocol": log.msg.unhandled_protocol,

            "source_port": log.msg.source_port,
            "destination_port": log.msg.destination_port,

            "level": log.msg.level,
            "timestamp": log.unix_time_stamp(),
            "source_addr_v6": Ipv6Addr::from(src_v6_addr).to_string(),
            "destination_addr_v6": Ipv6Addr::from(dst_v6_addr).to_string(),
        });

        let response = self
            .client
            .index(elasticsearch::IndexParts::Index(INDEX_NAME))
            .body(doc)
            .send()
            .await?;

        if !response.status_code().is_success() {
            let error = response.text().await?;
            return Err(anyhow::anyhow!("Elasticsearch indexing failed {}", error,));
        }

        Ok(())
    }
}
