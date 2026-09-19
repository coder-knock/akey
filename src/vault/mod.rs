//! Vault: data model, recipient list, store orchestration, three-way merge.

pub mod merge;
pub mod model;
pub mod recipients;
pub mod store;

pub use model::{
    Category, DEFAULT_VAULT, Entry, Field, FieldType, FORMAT_VERSION, Reveal, TokenMeta, Vault,
};
pub use recipients::{RecipientKind, RecipientRecord, Recipients};
pub use store::Store;
