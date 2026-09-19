//! 金库：数据模型、收件人清单、存储编排、三方合并。

pub mod merge;
pub mod model;
pub mod recipients;
pub mod store;

pub use model::{
    Category, DEFAULT_VAULT, Entry, Field, FieldType, FORMAT_VERSION, Reveal, TokenMeta, Vault,
};
pub use recipients::{RecipientKind, RecipientRecord, Recipients};
pub use store::Store;
