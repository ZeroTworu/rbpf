use crate::database;
use aya::maps::{HashMap, MapData};
use aya::Ebpf;
use aya::Pod;
use log::{info, warn};
use rbpf_common::{rules::rules::RuleWithName, rules::Rule};
use std::collections::HashMap as RustHashMap;
use std::fs::read_dir;
use std::sync::Arc;
use std::sync::LazyLock;
use std::vec::Vec;
use tokio::fs::read_to_string;
use tokio::sync::RwLock;
use yaml_rust2::YamlLoader;

const RULES_IN_V4: &str = "RULES_IN_V4";

const RULES_OUT_V4: &str = "RULES_OUT_V4";

const RULES_IN_V6: &str = "RULES_IN_V6";

const RULES_OUT_V6: &str = "RULES_OUT_V6";

static STORE: LazyLock<Arc<RwLock<RustHashMap<u32, RuleWithName>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(RustHashMap::new())));

pub async fn set_rule(value: RuleWithName) {
    let mut store = STORE.write().await;
    store.insert(value.rule_id, value);
}

// pub async fn calc_rule_uindex(value: RuleWithName) {
//     let store = STORE.read().await;
//     store.values().filter(|r| {
//         r.v4 && value.v4
//     })
// }

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

pub async fn load_rules_from_dir(path: &str, ebpf: &mut Ebpf) -> anyhow::Result<()> {
    info!("Loading rules from dir {}", path);
    let paths = read_dir(path);
    match paths {
        Ok(paths) => {
            let mut rules: Vec<RuleWithName> = Vec::new();
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
                rules.push(rule);
            }
            make_bpf_maps(&mut rules, ebpf).await?;
            Ok(())
        }
        Err(_) => {
            warn!("No rules found in dir {}, skip loading yaml.", path);
            Ok(())
        }
    }
}

pub async fn load_rules_from_db(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    info!("Loading rules from DB...");
    let mut rules = database::fetch_rules().await?;
    make_bpf_maps(&mut rules, ebpf).await?;
    Ok(())
}

pub async fn reload_rules(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let rules = get_rules()
        .await
        .values()
        .cloned()
        .collect::<Vec<RuleWithName>>();
    {
        let mut rules_input: HashMap<_, u32, Rule> =
            HashMap::try_from(ebpf.map_mut(RULES_IN_V4).unwrap())?;

        clear_hashmap(&mut rules_input);

        for (index, rule) in rules.iter().filter(|r| r.input && r.v4).enumerate() {
            let uindex = u32::try_from(index)?;
            rules_input.insert(uindex, rule.to_common_rule(), 0)?;
            info!(
                "ReLoading input rule IPv4: {}, Old index: {}, New index: {}",
                rule.name, rule.uindex, uindex
            );
        }
    }

    {
        let mut rules_output: HashMap<_, u32, Rule> =
            HashMap::try_from(ebpf.map_mut(RULES_OUT_V4).unwrap())?;

        clear_hashmap(&mut rules_output);

        for (index, rule) in rules.iter().filter(|r| r.output && r.v4).enumerate() {
            let uindex = u32::try_from(index)?;
            rules_output.insert(uindex, rule.to_common_rule(), 0)?;
            info!(
                "ReLoading output rule IPv4: {}, Old index: {}, New index: {}",
                rule.name, rule.uindex, uindex
            );
        }
    }

    {
        let mut rules_output_v6: HashMap<_, u32, Rule> =
            HashMap::try_from(ebpf.map_mut(RULES_OUT_V6).unwrap())?;

        clear_hashmap(&mut rules_output_v6);

        for (index, rule) in rules.iter().filter(|r| r.output && r.v6).enumerate() {
            let uindex = u32::try_from(index)?;
            rules_output_v6.insert(uindex, rule.to_common_rule(), 0)?;
            info!(
                "ReLoading output rule IPv6: {}, Old index: {}, New index: {}",
                rule.name, rule.uindex, uindex
            );
        }
    }

    {
        let mut rules_input_v6: HashMap<_, u32, Rule> =
            HashMap::try_from(ebpf.map_mut(RULES_IN_V6).unwrap())?;

        clear_hashmap(&mut rules_input_v6);

        for (index, rule) in rules.iter().filter(|r| r.input && r.v6).enumerate() {
            let uindex = u32::try_from(index)?;
            rules_input_v6.insert(uindex, rule.to_common_rule(), 0)?;
            info!(
                "ReLoading input rule IPv6: {}, Old index: {}, New index: {}",
                rule.name, rule.uindex, uindex
            );
        }
    }

    Ok(())
}

pub async fn make_current_bpf_maps(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let mut rules = get_rules()
        .await
        .values()
        .cloned()
        .collect::<Vec<RuleWithName>>();
    make_bpf_maps(&mut rules, ebpf).await?;
    Ok(())
}

pub async fn make_bpf_maps(rules: &mut Vec<RuleWithName>, ebpf: &mut Ebpf) -> anyhow::Result<()> {
    {
        let mut rules_input: HashMap<_, u32, Rule> =
            HashMap::try_from(ebpf.map_mut(RULES_IN_V4).unwrap())?;
        for (index, rule) in rules.iter_mut().filter(|r| r.input && r.v4).enumerate() {
            let uindex = u32::try_from(index)?;
            rules_input.insert(uindex, rule.to_common_rule(), 0)?;
            rule.uindex = uindex;
            set_rule(rule.clone()).await;
            info!("Loading input rule IPv4: {}, index: {}", rule.name, index);
        }
    }

    {
        let mut rules_output: HashMap<_, u32, Rule> =
            HashMap::try_from(ebpf.map_mut(RULES_OUT_V4).unwrap())?;
        for (index, rule) in rules.iter_mut().filter(|r| r.output && r.v4).enumerate() {
            let uindex = u32::try_from(index)?;
            rules_output.insert(uindex, rule.to_common_rule(), 0)?;
            rule.uindex = uindex;
            set_rule(rule.clone()).await;
            info!("Loading output rule IPv4: {}, index: {}", rule.name, index);
        }
    }

    {
        let mut rules_output_v6: HashMap<_, u32, Rule> =
            HashMap::try_from(ebpf.map_mut(RULES_OUT_V6).unwrap())?;
        for (index, rule) in rules.iter_mut().filter(|r| r.output && r.v6).enumerate() {
            let uindex = u32::try_from(index)?;
            rules_output_v6.insert(uindex, rule.to_common_rule(), 0)?;
            set_rule(rule.clone()).await;
            rule.uindex = uindex;
            info!("Loading output rule IPv6: {}, index: {}", rule.name, index);
        }
    }

    {
        let mut rules_input_v6: HashMap<_, u32, Rule> =
            HashMap::try_from(ebpf.map_mut(RULES_IN_V6).unwrap())?;
        for (index, rule) in rules.iter_mut().filter(|r| r.input && r.v6).enumerate() {
            let uindex = u32::try_from(index)?;
            rules_input_v6.insert(uindex, rule.to_common_rule(), 0)?;
            rule.uindex = uindex;
            set_rule(rule.clone()).await;
            info!("Loading input rule IPv6: {}, index: {}", rule.name, index);
        }
    }

    {
        for rule in rules
            .iter()
            .filter(|r| (!r.v6 && !r.v4) || (!r.input && !r.output))
            .collect::<Vec<&RuleWithName>>()
        {
            set_rule(rule.clone()).await;
            info!("Rule {} not v4 and not v6, just cache it ", rule.name);
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
            Err(_) => {
                warn!("Err while clearing hashmap");
            }
        };
    }
}
