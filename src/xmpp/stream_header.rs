use super::jid::Jid;
use super::stream::StreamId;

#[derive(Debug)]
pub struct LanguageTag(pub String);

#[derive(Debug)]
pub struct StreamHeader {
    pub from: Option<Jid>,
    pub to: Option<Jid>,
    pub id: Option<StreamId>,
    pub language: Option<LanguageTag>,
}
