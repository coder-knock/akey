//! 命令面定义。**这是 CLI 契约的唯一真相源**——`akey schema` 也从这里生成。
//!
//! 设计取向：AI 优先。扁平动词而非 noun-verb、处处 `--json`、绝不交互。

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use clap_complete::Shell;

use crate::output::Format;
use crate::sync::SyncMode;
use crate::vault::model::Category;

/// 供 AI agent 使用的加密凭证库。
#[derive(Debug, Parser)]
#[command(
    name = "akey",
    version,
    about = "Encrypted credential store for AI agents",
    long_about = None,
    disable_help_subcommand = true,
    propagate_version = true
)]
pub struct Cli {
    /// 机器可读输出（等于 `--format json`）
    #[arg(long, global = true)]
    pub json: bool,

    #[arg(long, global = true, value_enum, default_value_t = Format::Human)]
    pub format: Format,

    #[arg(long, global = true)]
    pub no_color: bool,

    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,

    #[arg(long, global = true)]
    pub debug: bool,

    /// 覆盖 `$AKEY_HOME`
    #[arg(long, global = true, value_name = "DIR")]
    pub home: Option<PathBuf>,

    /// 覆盖配置里的仓库路径
    #[arg(long, global = true, value_name = "PATH")]
    pub repo: Option<PathBuf>,

    /// 能力令牌（等价于 `$AKEY_TOKEN`）
    #[arg(long, global = true, env = "AKEY_TOKEN", hide_env_values = true)]
    pub token: Option<String>,

    /// 跳过确认
    #[arg(long, short = 'y', global = true)]
    pub yes: bool,

    /// 只预览不落盘
    #[arg(long, global = true)]
    pub dry_run: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// 初始化本地身份与同步仓库
    Init(InitArgs),
    /// 把引用解析为明文
    Read(ReadArgs),
    /// 在注入了秘密的环境里运行一条命令
    Run(RunArgs),
    /// 把引用渲染进模板
    Inject(InjectArgs),
    /// 查看条目（默认隐藏秘密字段）
    Get(GetArgs),
    /// 新建条目
    Set(SetArgs),
    /// 修改已有条目
    Edit(EditArgs),
    /// 删除条目（默认软删）
    Rm(RmArgs),
    /// 恢复软删的条目
    Restore(RestoreArgs),
    /// 复制条目
    Cp(CpArgs),
    /// 重命名条目
    Mv(MvArgs),
    /// 列出条目
    List(ListArgs),
    /// 查看条目分类的内置字段模板
    Template(TemplateArgs),
    /// 读写文件附件
    Doc(DocArgs),
    /// 管理能力令牌
    Token(TokenArgs),
    /// 管理设备
    Devices(DevicesArgs),
    /// 恢复密码
    Recovery(RecoveryArgs),
    /// 与远端同步
    Sync(SyncArgs),
    /// 列出合并冲突
    Conflicts(ConflictsArgs),
    /// 收敛一个冲突
    Resolve(ResolveArgs),
    /// 查看审计日志
    Log(LogArgs),
    /// 显示本机与仓库身份
    Whoami,
    /// 自检
    Doctor(DoctorArgs),
    /// 输出机器可读的命令清单
    Schema(SchemaArgs),
    /// 生成 shell 补全
    Completion(CompletionArgs),
    /// 导出（明文！）
    Export(ExportArgs),
    /// 导入
    Import(ImportArgs),
    /// 以 MCP stdio 服务运行（只暴露元数据，永不返回值）
    Mcp,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// 仓库路径（默认 `$AKEY_HOME/repo`）
    #[arg(long, value_name = "PATH")]
    pub repo: Option<PathBuf>,
    /// git 远端 URL
    #[arg(long, value_name = "URL")]
    pub remote: Option<String>,
    /// 从远端仓库引导一台新设备
    #[arg(long, value_name = "URL")]
    pub from: Option<String>,
    /// 本机设备名
    #[arg(long, value_name = "NAME")]
    pub device: Option<String>,
    /// 设置恢复密码（换机/找回用）
    #[arg(long)]
    pub recovery: bool,
    /// 不设恢复密码
    #[arg(long, conflicts_with = "recovery")]
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
    /// 注入一个秘密：`VAR=REF` 或 `VAR=ITEM` 或 `ITEM`
    #[arg(long = "with", value_name = "SPEC", action = clap::ArgAction::Append)]
    pub with: Vec<String>,
    /// 解析其中的 `akey://` 引用后作为环境变量注入
    #[arg(long = "env-file", value_name = "FILE", action = clap::ArgAction::Append)]
    pub env_file: Vec<PathBuf>,
    /// 注入某条 `env-bundle` 条目的全部字段
    #[arg(long = "bundle", value_name = "ITEM", action = clap::ArgAction::Append)]
    pub bundle: Vec<String>,
    /// 关闭子进程输出的秘密遮蔽（同时保留 TTY，交互式程序需要）
    #[arg(long = "no-masking")]
    pub no_masking: bool,
    /// 要运行的命令
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true, value_name = "COMMAND")]
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
    /// 只看这些字段（可重复）
    #[arg(long = "field", value_name = "LABEL", action = clap::ArgAction::Append)]
    pub fields: Vec<String>,
    /// 展开隐藏字段的明文
    #[arg(long)]
    pub reveal: bool,
    /// 对 `otp` 字段现算一次性口令
    #[arg(long)]
    pub otp: bool,
}

#[derive(Debug, Args)]
pub struct SetArgs {
    pub item: String,
    /// `[section.]field[[type]]=value`（出现在 argv 中会告警）
    #[arg(value_name = "ASSIGN")]
    pub assignments: Vec<String>,
    #[arg(long, value_enum)]
    pub category: Option<Category>,
    #[arg(long)]
    pub title: Option<String>,
    #[arg(long, value_delimiter = ',')]
    pub tags: Vec<String>,
    #[arg(long, value_name = "FILE")]
    pub template: Option<PathBuf>,
    /// 从 stdin 读秘密值（推荐：不进 argv）
    #[arg(long)]
    pub stdin: bool,
    /// 与 `--stdin` 搭配：写入哪个字段
    #[arg(long, value_name = "LABEL")]
    pub secret_field: Option<String>,
    /// 生成随机密码，可选配方 `letters,digits,symbols,32`
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
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
    /// 标记为已轮换（刷新 `rotated_at`）
    #[arg(long)]
    pub rotate: bool,
    /// 是否允许直接取明文
    #[arg(long, value_enum)]
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
    /// 彻底移除记录（写墓碑，防止被对端复活）
    #[arg(long)]
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
    /// 只看在此时长内过期的条目，如 `30d`
    #[arg(long, value_name = "DURATION")]
    pub expiring: Option<String>,
    #[arg(long)]
    pub favorite: bool,
    /// 含已软删的条目
    #[arg(long)]
    pub all: bool,
}

#[derive(Debug, Args)]
pub struct TemplateArgs {
    #[command(subcommand)]
    pub command: TemplateCommand,
}

#[derive(Debug, Subcommand)]
pub enum TemplateCommand {
    /// 列出全部分类
    List,
    /// 输出某分类的 JSON 模板
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
    /// 签发一个能力令牌（明文只回显一次）
    Create {
        #[arg(long, value_name = "NAME")]
        name: String,
        /// 只允许这些条目（逗号分隔）；缺省为全部
        #[arg(long, value_delimiter = ',', value_name = "ITEM")]
        allow: Vec<String>,
        /// 禁止该令牌取明文
        #[arg(long)]
        deny_reveal: bool,
        /// 有效期，如 `30d`
        #[arg(long, value_name = "DURATION")]
        ttl: Option<String>,
    },
    /// 列出令牌（不含明文）
    List,
    /// 吊销令牌
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
    /// 把本机公钥加入收件人并重新加密
    Add {
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
    },
    /// 吊销一台设备并重新加密，使其再也解不开
    Rm { name: String },
    Rename { old: String, new: String },
    /// 批准一个收件人（名字或 age1… 公钥），并立刻把当前金库加密给它
    Trust { key: String },
    /// 撤回对某个收件人的批准
    Untrust { key: String },
}

#[derive(Debug, Args)]
pub struct RecoveryArgs {
    #[command(subcommand)]
    pub command: RecoveryCommand,
}

#[derive(Debug, Subcommand)]
pub enum RecoveryCommand {
    /// 设置恢复密码（生成引导身份）
    Set,
    /// 轮换恢复密码
    Rotate,
    /// 验证恢复密码可用
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
    /// 采用本地一侧
    #[arg(long, conflicts_with = "theirs")]
    pub ours: bool,
    /// 采用对端一侧
    #[arg(long, conflicts_with = "ours")]
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
    /// 导出载荷的编码。与全局 `--format`（管信封）无关，所以另起 `--as` 以免 arg id 冲突
    #[arg(long = "as", value_enum, default_value_t = ExportFormat::Json)]
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
    /// 导入载荷的编码（同 `export --as`）
    #[arg(long = "as", value_enum)]
    pub encoding: ExportFormat,
    #[arg(long, short = 'i', value_name = "FILE")]
    pub in_file: Option<PathBuf>,
    /// 与现有条目合并而非拒绝重名
    #[arg(long)]
    pub merge: bool,
}
