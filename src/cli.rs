//! The command surface. **This is the single source of truth for the CLI contract** — `akey schema` is generated from it too.
//!
//! Design stance: AI first. Flat verbs rather than noun-verb, `--json` everywhere, never interactive.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use clap_complete::Shell;

use crate::i18n;
use crate::output::Format;
use crate::sync::SyncMode;
use crate::vault::model::Category;

#[derive(Debug, Parser)]
#[command(
    name = "akey",
    version,
    about = i18n::m("Encrypted credential store for AI agents", "供 AI agent 使用的加密凭证库"),
    long_about = None,
    disable_help_subcommand = true,
    propagate_version = true
)]
pub struct Cli {
    #[arg(
        help = i18n::m("Machine-readable output (same as `--format json`)", "机器可读输出（等于 `--format json`）"),
        long, global = true)]
    pub json: bool,

    #[arg(long, global = true, value_enum, default_value_t = Format::Human)]
    pub format: Format,

    #[arg(long, global = true)]
    pub no_color: bool,

    #[arg(
        long,
        global = true,
        value_name = "TAG",
        env = "AKEY_LANG",
        help = i18n::m(
            "Output language (default: follow $LC_ALL / $LC_MESSAGES / $LANG, else en)",
            "输出语言（默认跟随 $LC_ALL / $LC_MESSAGES / $LANG，否则 en）"
        )
    )]
    pub lang: Option<String>,

    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,

    #[arg(long, global = true)]
    pub debug: bool,

    #[arg(
        help = i18n::m("Override `$AKEY_HOME`", "覆盖 `$AKEY_HOME`"),
        long, global = true, value_name = "DIR")]
    pub home: Option<PathBuf>,

    #[arg(
        help = i18n::m("Override the repository path from the config", "覆盖配置里的仓库路径"),
        long, global = true, value_name = "PATH")]
    pub repo: Option<PathBuf>,

    #[arg(
        help = i18n::m("Capability token (same as `$AKEY_TOKEN`)", "能力令牌（等价于 `$AKEY_TOKEN`）"),
        long, global = true, env = "AKEY_TOKEN", hide_env_values = true)]
    pub token: Option<String>,

    #[arg(
        help = i18n::m("Skip confirmation", "跳过确认"),
        long, short = 'y', global = true)]
    pub yes: bool,

    #[arg(
        help = i18n::m("Preview only; write nothing", "只预览不落盘"),
        long, global = true)]
    pub dry_run: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = i18n::m("Create the local identity and the sync repository", "初始化本地身份与同步仓库"))]
    Init(InitArgs),
    #[command(about = i18n::m("Resolve a reference to plaintext", "把引用解析为明文"))]
    Read(ReadArgs),
    #[command(about = i18n::m("Run a command with secrets injected into its environment", "在注入了秘密的环境里运行一条命令"))]
    Run(RunArgs),
    #[command(about = i18n::m("Render references into a template", "把引用渲染进模板"))]
    Inject(InjectArgs),
    #[command(about = i18n::m("Show an entry (secret fields hidden by default)", "查看条目（默认隐藏秘密字段）"))]
    Get(GetArgs),
    #[command(about = i18n::m("Create an entry", "新建条目"))]
    Set(SetArgs),
    #[command(about = i18n::m("Modify an existing entry", "修改已有条目"))]
    Edit(EditArgs),
    #[command(about = i18n::m("Delete an entry (soft by default)", "删除条目（默认软删）"))]
    Rm(RmArgs),
    #[command(about = i18n::m("Restore a soft-deleted entry", "恢复软删的条目"))]
    Restore(RestoreArgs),
    #[command(about = i18n::m("Copy an entry", "复制条目"))]
    Cp(CpArgs),
    #[command(about = i18n::m("Rename an entry", "重命名条目"))]
    Mv(MvArgs),
    #[command(about = i18n::m("List entries", "列出条目"))]
    List(ListArgs),
    #[command(about = i18n::m("Show the built-in field template for a category", "查看条目分类的内置字段模板"))]
    Template(TemplateArgs),
    #[command(about = i18n::m("Read and write file attachments", "读写文件附件"))]
    Doc(DocArgs),
    #[command(about = i18n::m("Manage capability tokens", "管理能力令牌"))]
    Token(TokenArgs),
    #[command(about = i18n::m("Manage devices", "管理设备"))]
    Devices(DevicesArgs),
    #[command(about = i18n::m("Recovery passphrase", "恢复密码"))]
    Recovery(RecoveryArgs),
    #[command(about = i18n::m("Sync with the remote", "与远端同步"))]
    Sync(SyncArgs),
    #[command(about = i18n::m("List merge conflicts", "列出合并冲突"))]
    Conflicts(ConflictsArgs),
    #[command(about = i18n::m("Resolve one conflict", "收敛一个冲突"))]
    Resolve(ResolveArgs),
    #[command(about = i18n::m("Show the audit log", "查看审计日志"))]
    Log(LogArgs),
    #[command(about = i18n::m("Show this machine's identity and the repository's", "显示本机与仓库身份"))]
    Whoami,
    #[command(about = i18n::m("Self-check", "自检"))]
    Doctor(DoctorArgs),
    #[command(about = i18n::m("Print the machine-readable command list", "输出机器可读的命令清单"))]
    Schema(SchemaArgs),
    #[command(about = i18n::m("Generate shell completions", "生成 shell 补全"))]
    Completion(CompletionArgs),
    #[command(about = i18n::m("Export (plaintext!)", "导出（明文！）"))]
    Export(ExportArgs),
    #[command(about = i18n::m("Import", "导入"))]
    Import(ImportArgs),
    #[command(about = i18n::m("Run as an MCP stdio server (metadata only, never values)", "以 MCP stdio 服务运行（只暴露元数据，永不返回值）"))]
    Mcp,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    #[arg(
        help = i18n::m("Repository path (default `$AKEY_HOME/repo`)", "仓库路径（默认 `$AKEY_HOME/repo`）"),
        long, value_name = "PATH")]
    pub repo: Option<PathBuf>,
    #[arg(
        help = i18n::m("Git remote URL", "git 远端 URL"),
        long, value_name = "URL")]
    pub remote: Option<String>,
    #[arg(
        help = i18n::m("Bootstrap a new device from the remote repository", "从远端仓库引导一台新设备"),
        long, value_name = "URL")]
    pub from: Option<String>,
    #[arg(
        help = i18n::m("Name for this device", "本机设备名"),
        long, value_name = "NAME")]
    pub device: Option<String>,
    #[arg(
        help = i18n::m("Set a recovery passphrase (for a new machine or a lost one)", "设置恢复密码（换机/找回用）"),
        long)]
    pub recovery: bool,
    #[arg(
        help = i18n::m("Do not set a recovery passphrase", "不设恢复密码"),
        long, conflicts_with = "recovery")]
    pub no_recovery: bool,
}

#[derive(Debug, Args)]
pub struct ReadArgs {
    /// `akey://[vault/]item/[section/]field`
    pub reference: String,
    #[arg(long, short = 'o', value_name = "FILE")]
    pub out_file: Option<PathBuf>,
    #[arg(long)]
    pub no_newline: bool,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    #[arg(
        help = i18n::m("Inject a secret: `VAR=REF`, `VAR=ITEM`, or `ITEM`", "注入一个秘密：`VAR=REF` 或 `VAR=ITEM` 或 `ITEM`"),
        long = "with", value_name = "SPEC", action = clap::ArgAction::Append)]
    pub with: Vec<String>,
    #[arg(
        help = i18n::m("Resolve the `akey://` references in this file and inject them as environment variables", "解析其中的 `akey://` 引用后作为环境变量注入"),
        long = "env-file", value_name = "FILE", action = clap::ArgAction::Append)]
    pub env_file: Vec<PathBuf>,
    #[arg(
        help = i18n::m("Inject every field of an `env-bundle` entry", "注入某条 `env-bundle` 条目的全部字段"),
        long = "bundle", value_name = "ITEM", action = clap::ArgAction::Append)]
    pub bundle: Vec<String>,
    #[arg(
        help = i18n::m("Stop masking secrets in the child's output (also keeps the TTY that interactive programs need)", "关闭子进程输出的秘密遮蔽（同时保留 TTY，交互式程序需要）"),
        long = "no-masking")]
    pub no_masking: bool,
    #[arg(
        help = i18n::m("The command to run", "要运行的命令"),
        required = true, trailing_var_arg = true, allow_hyphen_values = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

#[derive(Debug, Args)]
pub struct InjectArgs {
    #[arg(long, short = 'i', value_name = "FILE")]
    pub in_file: Option<PathBuf>,
    #[arg(long, short = 'o', value_name = "FILE")]
    pub out_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct GetArgs {
    pub item: String,
    #[arg(
        help = i18n::m("Show only these fields (repeatable)", "只看这些字段（可重复）"),
        long = "field", value_name = "LABEL", action = clap::ArgAction::Append)]
    pub fields: Vec<String>,
    #[arg(
        help = i18n::m("Reveal concealed fields in plaintext", "展开隐藏字段的明文"),
        long)]
    pub reveal: bool,
    #[arg(
        help = i18n::m("Compute a one-time password for an `otp` field", "对 `otp` 字段现算一次性口令"),
        long)]
    pub otp: bool,
}

#[derive(Debug, Args)]
pub struct SetArgs {
    pub item: String,
    #[arg(
        help = i18n::m("`[section.]field[[type]]=value` (warns when it appears in argv)", "`[section.]field[[type]]=value`（出现在 argv 中会告警）"),
        value_name = "ASSIGN")]
    pub assignments: Vec<String>,
    #[arg(long, value_enum)]
    pub category: Option<Category>,
    #[arg(long)]
    pub title: Option<String>,
    #[arg(long, value_delimiter = ',')]
    pub tags: Vec<String>,
    #[arg(long, value_name = "FILE")]
    pub template: Option<PathBuf>,
    #[arg(
        help = i18n::m("Read the secret from stdin (preferred: keeps it out of argv)", "从 stdin 读秘密值（推荐：不进 argv）"),
        long)]
    pub stdin: bool,
    #[arg(
        help = i18n::m("With `--stdin`: which field to write", "与 `--stdin` 搭配：写入哪个字段"),
        long, value_name = "LABEL")]
    pub secret_field: Option<String>,
    #[arg(
        help = i18n::m("Generate a random password, optionally with a recipe: `letters,digits,symbols,32`", "生成随机密码，可选配方 `letters,digits,symbols,32`"),
        long, num_args = 0..=1, default_missing_value = "")]
    pub generate_password: Option<String>,
}

#[derive(Debug, Args)]
pub struct EditArgs {
    pub item: String,
    #[arg(value_name = "ASSIGN")]
    pub assignments: Vec<String>,
    #[arg(long)]
    pub title: Option<String>,
    #[arg(long, value_delimiter = ',')]
    pub tags: Vec<String>,
    #[arg(long)]
    pub favorite: bool,
    #[arg(long)]
    pub unfavorite: bool,
    #[arg(long, value_name = "FILE")]
    pub template: Option<PathBuf>,
    #[arg(
        help = i18n::m("Mark as rotated (refreshes `rotated_at`)", "标记为已轮换（刷新 `rotated_at`）"),
        long)]
    pub rotate: bool,
    #[arg(
        help = i18n::m("Whether plaintext may be revealed directly", "是否允许直接取明文"),
        long, value_enum)]
    pub reveal_policy: Option<RevealPolicy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum RevealPolicy {
    Allow,
    Deny,
}

#[derive(Debug, Args)]
pub struct RmArgs {
    pub items: Vec<String>,
    #[arg(
        help = i18n::m("Remove the record entirely (writes a tombstone so a peer cannot revive it)", "彻底移除记录（写墓碑，防止被对端复活）"),
        long)]
    pub purge: bool,
}

#[derive(Debug, Args)]
pub struct RestoreArgs {
    pub items: Vec<String>,
}

#[derive(Debug, Args)]
pub struct CpArgs {
    pub source: String,
    pub destination: String,
}

#[derive(Debug, Args)]
pub struct MvArgs {
    pub old: String,
    pub new: String,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    #[arg(long, value_delimiter = ',')]
    pub tags: Vec<String>,
    #[arg(long, value_enum)]
    pub category: Option<Category>,
    #[arg(
        help = i18n::m("Show only entries expiring within this window, e.g. `30d`", "只看在此时长内过期的条目，如 `30d`"),
        long, value_name = "DURATION")]
    pub expiring: Option<String>,
    #[arg(long)]
    pub favorite: bool,
    #[arg(
        help = i18n::m("Include soft-deleted entries", "含已软删的条目"),
        long)]
    pub all: bool,
}

#[derive(Debug, Args)]
pub struct TemplateArgs {
    #[command(subcommand)]
    pub command: TemplateCommand,
}

#[derive(Debug, Subcommand)]
pub enum TemplateCommand {
    #[command(about = i18n::m("List every category", "列出全部分类"))]
    List,
    #[command(about = i18n::m("Print a category's JSON template", "输出某分类的 JSON 模板"))]
    Get {
        category: Category,
        #[arg(long, short = 'o', value_name = "FILE")]
        out_file: Option<PathBuf>,
    },
}

#[derive(Debug, Args)]
pub struct DocArgs {
    #[command(subcommand)]
    pub command: DocCommand,
}

#[derive(Debug, Subcommand)]
pub enum DocCommand {
    Get {
        reference: String,
        #[arg(long, short = 'o', value_name = "FILE")]
        out_file: Option<PathBuf>,
    },
    Put {
        item: String,
        file: PathBuf,
        #[arg(long, value_name = "LABEL", default_value = "file")]
        field: String,
    },
}

#[derive(Debug, Args)]
pub struct TokenArgs {
    #[command(subcommand)]
    pub command: TokenCommand,
}

#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    #[command(about = i18n::m("Issue a capability token (the plaintext is shown once)", "签发一个能力令牌（明文只回显一次）"))]
    Create {
        #[arg(long, value_name = "NAME")]
        name: String,
        #[arg(
            help = i18n::m("Restrict to these entries (comma-separated); defaults to all", "只允许这些条目（逗号分隔）；缺省为全部"),
            long, value_delimiter = ',', value_name = "ITEM")]
        allow: Vec<String>,
        #[arg(
            help = i18n::m("Forbid this token from revealing plaintext", "禁止该令牌取明文"),
            long)]
        deny_reveal: bool,
        #[arg(
            help = i18n::m("Lifetime, e.g. `30d`", "有效期，如 `30d`"),
            long, value_name = "DURATION")]
        ttl: Option<String>,
    },
    #[command(about = i18n::m("List tokens (never the plaintext)", "列出令牌（不含明文）"))]
    List,
    #[command(about = i18n::m("Revoke a token", "吊销令牌"))]
    Rm { name: String },
}

#[derive(Debug, Args)]
pub struct DevicesArgs {
    #[command(subcommand)]
    pub command: DevicesCommand,
}

#[derive(Debug, Subcommand)]
pub enum DevicesCommand {
    List,
    #[command(about = i18n::m("Add this machine's public key to the recipients and re-encrypt", "把本机公钥加入收件人并重新加密"))]
    Add {
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
    },
    #[command(about = i18n::m("Revoke a device and re-encrypt so it can never open the vault again", "吊销一台设备并重新加密，使其再也解不开"))]
    Rm {
        name: String,
    },
    Rename {
        old: String,
        new: String,
    },
    #[command(about = i18n::m("Approve a recipient (a name or an age1… public key) and encrypt the current vault to it", "批准一个收件人（名字或 age1… 公钥），并立刻把当前金库加密给它"))]
    Trust {
        key: String,
    },
    #[command(about = i18n::m("Withdraw approval for a recipient", "撤回对某个收件人的批准"))]
    Untrust {
        key: String,
    },
}

#[derive(Debug, Args)]
pub struct RecoveryArgs {
    #[command(subcommand)]
    pub command: RecoveryCommand,
}

#[derive(Debug, Subcommand)]
pub enum RecoveryCommand {
    #[command(about = i18n::m("Set a recovery passphrase (creates the bootstrap identity)", "设置恢复密码（生成引导身份）"))]
    Set,
    #[command(about = i18n::m("Rotate the recovery passphrase", "轮换恢复密码"))]
    Rotate,
    #[command(about = i18n::m("Verify that the recovery passphrase works", "验证恢复密码可用"))]
    Unlock,
}

#[derive(Debug, Args)]
pub struct SyncArgs {
    #[arg(long, conflicts_with_all = ["pull", "status"])]
    pub push: bool,
    #[arg(long, conflicts_with_all = ["push", "status"])]
    pub pull: bool,
    #[arg(long, conflicts_with_all = ["push", "pull"])]
    pub status: bool,
}

impl SyncArgs {
    pub fn mode(&self) -> SyncMode {
        if self.push {
            SyncMode::Push
        } else if self.pull {
            SyncMode::Pull
        } else if self.status {
            SyncMode::Status
        } else {
            SyncMode::Auto
        }
    }
}

#[derive(Debug, Args)]
pub struct ConflictsArgs {}

#[derive(Debug, Args)]
pub struct ResolveArgs {
    pub name: String,
    #[arg(
        help = i18n::m("Take the local side", "采用本地一侧"),
        long, conflicts_with = "theirs")]
    pub ours: bool,
    #[arg(
        help = i18n::m("Take the remote side", "采用对端一侧"),
        long, conflicts_with = "ours")]
    pub theirs: bool,
}

#[derive(Debug, Args)]
pub struct LogArgs {
    #[arg(long, value_name = "DURATION")]
    pub since: Option<String>,
    #[arg(long, value_name = "ITEM")]
    pub item: Option<String>,
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {}

#[derive(Debug, Args)]
pub struct SchemaArgs {}

#[derive(Debug, Args)]
pub struct CompletionArgs {
    pub shell: Shell,
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    #[arg(
        help = i18n::m("Encoding of the export payload. Unrelated to the global `--format` (which governs the envelope), hence `--as` — a separate arg id to avoid a clash", "导出载荷的编码。与全局 `--format`（管信封）无关，所以另起 `--as` 以免 arg id 冲突"),
        long = "as", value_enum, default_value_t = ExportFormat::Json)]
    pub encoding: ExportFormat,
    #[arg(long, short = 'o', value_name = "FILE")]
    pub out_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ExportFormat {
    Json,
    Dotenv,
    Csv1p,
}

#[derive(Debug, Args)]
pub struct ImportArgs {
    #[arg(
        help = i18n::m("Encoding of the import payload (same as `export --as`)", "导入载荷的编码（同 `export --as`）"),
        long = "as", value_enum)]
    pub encoding: ExportFormat,
    #[arg(long, short = 'i', value_name = "FILE")]
    pub in_file: Option<PathBuf>,
    #[arg(
        help = i18n::m("Merge with existing entries instead of refusing duplicate names", "与现有条目合并而非拒绝重名"),
        long)]
    pub merge: bool,
}
