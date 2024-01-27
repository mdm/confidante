use std::{fmt::{Display, Formatter}, str::FromStr};

use anyhow::{bail, Error};
use regex::Regex;

#[derive(Debug)]
struct DomainPart(String);

impl Display for DomainPart {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug)]
struct LocalPart(String);

impl Display for LocalPart {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug)]
struct ResourcePart(String);

impl Display for ResourcePart {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

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
