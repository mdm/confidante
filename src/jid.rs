use std::str::FromStr;

use anyhow::{bail, Error};
use regex::Regex;

#[derive(Debug)]
struct DomainPart(String);

#[derive(Debug)]
struct LocalPart(String);

#[derive(Debug)]
struct ResourcePart(String);

#[derive(Debug)]
pub struct Jid {
    local: Option<LocalPart>,
    domain: DomainPart,
    resource: Option<ResourcePart>,
}

impl FromStr for Jid {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let regex = Regex::new("(?:(?P<local>.+)@)?(?P<domain>.+)(?:/(?P<resource>.+))?").unwrap();
        match regex.captures(s) {
            Some(captures) => {
                let local = captures
                    .name("local")
                    .map(|m| LocalPart(m.as_str().to_string()));
                let domain = captures
                    .name("domain")
                    .map(|m| DomainPart(m.as_str().to_string()))
                    .unwrap();
                let resource = captures
                    .name("resource")
                    .map(|m| ResourcePart(m.as_str().to_string()));

                Ok(Jid {
                    local,
                    domain,
                    resource,
                })
            }
            None => bail!("Could not parse JID: \"{s}\""),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Jid;

    #[test]
    fn fail_on_empty_string() {
        let result = "".parse::<Jid>();
        assert!(matches!(result, Err(_)));
    }
}
