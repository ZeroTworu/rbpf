use crate::database;
use aya::Ebpf;
use aya::Pod;
use aya::maps::{HashMap, MapData};
use log::{info, warn};
use rbpf_common::{rules::Rule, rules::rules::RuleWithName};
use std::collections::HashMap as RustHashMap;
use std::fs::read_dir;
use std::sync::Arc;
use std::sync::LazyLock;
use std::vec::Vec;
use tokio::fs::read_to_string;
use tokio::sync::RwLock;
use yaml_rust2::YamlLoader;

const RULES: &str = "RULES";

static STORE: LazyLock<Arc<RwLock<RustHashMap<u32, RuleWithName>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(RustHashMap::new())));

pub async fn set_rule(value: RuleWithName) {
    let mut store = STORE.write().await;
    store.insert(value.rule_id, value);
}

pub async fn change_rule(value: RuleWithName) {
    let mut store = STORE.write().await;
    if value.from_db {
        database::update_rule(&value).await;
    }
    store.remove(&value.rule_id);
    store.insert(value.rule_id, value);
}

pub async fn get_rule_name(key: u32) -> Option<RuleWithName> {
    let store = STORE.read().await;
    store.get(&key).cloned()
}

pub async fn get_rules() -> RustHashMap<u32, RuleWithName> {
    let store = STORE.read().await;
    store.clone()
}

pub async fn get_rules_len() -> u32 {
    let store = STORE.read().await;
    u32::try_from(store.len()).unwrap()
}

pub async fn load_rules_from_dir(path: &str) -> anyhow::Result<()> {
    info!("Loading rules from dir {}...", path);
    let paths = read_dir(path);
    match paths {
        Ok(paths) => {
            for path in paths {
                let path = path?.path();
                if !path
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .ends_with(".yaml")
                {
                    continue;
                }
                let srule = read_to_string(path).await?;
                let yrule = &YamlLoader::load_from_str(&srule)?[0];
                let rule = RuleWithName::from_yaml(yrule);
                set_rule(rule.clone()).await;
            }
            Ok(())
        }
        Err(_) => {
            warn!("No rules found in dir {}, skip loading yaml.", path);
            Ok(())
        }
    }
}

pub async fn load_rules_from_db() -> anyhow::Result<()> {
    info!("Loading rules from DB...");
    let rules = database::fetch_rules().await?;
    for rule in rules {
        set_rule(rule.clone()).await;
    }
    Ok(())
}

pub async fn reload_rules(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let mut rules_input: HashMap<_, u32, Rule> = HashMap::try_from(ebpf.map_mut(RULES).unwrap())?;

    clear_hashmap(&mut rules_input);
    make_bpf_maps(ebpf).await?;

    Ok(())
}

pub async fn make_bpf_maps(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    {
        let mut rules_map: HashMap<_, u32, Rule> = HashMap::try_from(ebpf.map_mut(RULES).unwrap())?;

        let mut rules: Vec<_> = get_rules().await.into_values().collect();
        rules.sort_by_key(|rule| rule.order);

        for (new_order, rule) in rules.into_iter().enumerate() {
            rules_map.insert(new_order as u32, rule.to_common_rule(), 0)?;
            info!(
                "Loading rule {}, original order: {}, set as {}",
                rule.name, rule.order, new_order
            );
        }
    }
    Ok(())
}

pub fn clear_hashmap<K, V>(map: &mut HashMap<&mut MapData, K, V>)
where
    K: Pod + Eq + Copy,
    V: Pod,
{
    let keys: Vec<K> = map.keys().filter_map(Result::ok).collect();
    for key in keys {
        match map.remove(&key) {
            Ok(_) => {}
            Err(e) => {
                warn!("Err {} while clearing hashmap", e);
            }
        };
    }
}
