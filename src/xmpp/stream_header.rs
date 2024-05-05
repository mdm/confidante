use super::jid::Jid;
use super::StreamId;

#[derive(Debug)]
pub struct LanguageTag(pub String); // TODO: make inner field private

#[derive(Debug)]
pub struct StreamHeader {
    pub from: Option<Jid>,
    pub to: Option<Jid>,
    pub id: Option<StreamId>,
    pub language: Option<LanguageTag>,
    // TODO: add version
}
