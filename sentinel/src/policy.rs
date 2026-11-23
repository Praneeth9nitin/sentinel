use anyhow::Context;
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Default, Deserialize)]
pub struct Rules {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Policy {
    pub agent: String,
    #[serde(default)]
    pub files: Rules,
    #[serde(default)]
    pub programs: Rules,
    #[serde(default)]
    pub network: Rules,
}

pub enum Verdict {
    Allowed,
    Violation(String),
}

fn path_matches(rule: &str, path: &str) -> bool {
    if rule.ends_with('/') {
        path.starts_with(rule)
    } else {
        path == rule
    }
}

impl Policy {
    pub fn load(path: &str) -> anyhow::Result<Self>{
        let text = std::fs::read_to_string(path).
            with_context(|| format!("cannot read the policy file {path}"))?;
        yaml_serde::from_str(&text).with_context(|| format!("invalid policy file {path}"))
    }
    pub fn check_file(&self, path: &str) -> Verdict{
        if path.split('/').any(|c| c == ".."){
            return Verdict::Violation(format!("{path} : path contains .."));
        }

        if let Some(r) = self.files.deny.iter().find(|r| path_matches(r, path)) {
            return Verdict::Violation(format!("{path}: matches deny rule {r}"));
        }

        if self.files.allow.iter().any(|r| path_matches(r, path)){
            return Verdict::Allowed;
        }
        
        else {
            Verdict::Violation(format!("{path}: not in allowed files"))
        }
    }

    pub fn check_program(&self, path: &str) -> Verdict{
        if self.programs.allow.iter().any(|r| path_matches(r, path)){
            Verdict::Allowed
        }else{
            Verdict::Violation(format!("{path}: program not allowed"))
        }
    }

    pub fn check_connect(&self, ip: IpAddr, port: u16) -> Verdict{
        let dest = SocketAddr::new(ip, port).to_string();
        if self.network.allow.iter().any(|r| *r == dest) {
            Verdict::Allowed
        } else {
            Verdict::Violation(format!("{dest}: destination not allowed"))
        } 
    }
}