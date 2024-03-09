use std::{fmt::{Display, Formatter}, str::FromStr};

use anyhow::{bail, Error};
use regex::Regex;
use serde_with::DeserializeFromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DomainPart(String);

impl Display for DomainPart {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LocalPart(String);

impl Display for LocalPart {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ResourcePart(String);

impl Display for ResourcePart {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, DeserializeFromStr)]
pub struct Jid {
    local: Option<LocalPart>,
    domain: DomainPart,
    resource: Option<ResourcePart>,
}

impl Jid {
    pub fn new(local: Option<String>, domain: String, resource: Option<String>) -> Self {
        Jid {
            local: local.map(LocalPart),
            domain: DomainPart(domain),
            resource: resource.map(ResourcePart),
        }
    }

    pub fn bind(&self, resource: String) -> Self {
        Jid {
            local: self.local.clone(),
            domain: self.domain.clone(),
            resource: Some(ResourcePart(resource)),
        }
    }
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

impl Display for Jid {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.local {
            Some(local) => write!(f, "{}@{}", local, self.domain)?,
            None => write!(f, "{}", self.domain)?,
        }
        match &self.resource {
            Some(resource) => write!(f, "/{}", resource)?,
            None => (),
        }
        Ok(())
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
