//! Vault: data model, recipient list, store orchestration, three-way merge.

pub mod generator;
pub mod merge;
pub mod migrate;
pub mod model;
pub mod recipients;
pub mod store;

pub use model::{
    Category, DEFAULT_VAULT, Entry, FORMAT_VERSION, Field, FieldType, Reveal, TokenMeta, Vault,
};
pub use recipients::{RecipientKind, RecipientRecord, Recipients};
pub use store::Store;
