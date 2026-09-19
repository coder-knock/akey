//! 子进程输出遮蔽：把流经 stdout/stderr 的密钥换成占位符。
//!
//! 这是 `akey run` 默认开启的防线——它让"AI 调用外部工具"这条路径上，
//! 明文即使被工具回显也不会进入对话上下文。
//!
//! 难点是**跨块匹配**：密钥可能被任意切分在两个读块之间，所以必须保留
//! `max_secret_len - 1` 字节的尾巴不输出，直到能确定它不构成匹配。

use crate::output::TAINTED;

/// 短于此长度的值不参与遮蔽——否则会把 `true`、`0`、`prod` 这类短串打成马赛克。
pub const MIN_SECRET_LEN: usize = 8;

/// 流式遮蔽器：喂进子进程读块的字节，吐出**已遮蔽**的字节。
///
/// 算法是左到右的贪心最长匹配：
/// - 位置 `i` 的整扇窗口（`max_len` 字节）还没到齐 → `break`，尾巴留下等下一块；
/// - 窗口到齐后命中某个密钥（先试最长的）→ 输出占位符，前进 `secret.len()`；
/// - 未命中 → 原样输出该字节，前进 1。
///
/// 窗口未到齐就不下结论，是"最长匹配"能跨块成立的前提：否则一块恰好停在较短
/// 密钥末尾时，会先把它换掉、再把较长密钥的尾巴原样漏出去。
///
/// 只有在 `finish()`（流结束）时才放弃保留，把尾巴按同样规则处理完。
#[derive(Default)]
pub struct Masker {
    /// 是否有任何可遮蔽的值。无值时调用方直接 inherit，省掉一次管道拷贝。
    enabled: bool,
    /// 参与遮蔽的密钥，**按长度降序**，保证"先试最长的"，且互不重复。
    secrets: Vec<Vec<u8>>,
    /// `secrets` 中最长的长度；无密钥时为 0。
    max_len: usize,
    /// 已吃进但还不敢输出的尾巴。
    pending: Vec<u8>,
}

/// 永不打印秘密值。
impl std::fmt::Debug for Masker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Masker")
            .field("enabled", &self.enabled)
            .field("secret_count", &self.secrets.len())
            .field("max_len", &self.max_len)
            .field("pending_len", &self.pending.len())
            .finish()
    }
}

impl Masker {
    pub fn new() -> Self {
        Masker::default()
    }

    /// 从一批明文构造。短于 [`MIN_SECRET_LEN`] 的值被忽略。
    pub fn with_secrets<I: IntoIterator<Item = String>>(secrets: I) -> Self {
        let mut masker = Masker::new();
        for secret in secrets {
            masker.add(&secret);
        }
        masker
    }

    /// 添加一个明文。空值、短于 [`MIN_SECRET_LEN`] 的值、本身就是占位符的值、
    /// 以及已存在的重复值都会被忽略。
    pub fn add(&mut self, secret: &str) {
        if secret.len() < MIN_SECRET_LEN || secret == TAINTED {
            return;
        }
        let bytes = secret.as_bytes();
        if self.secrets.iter().any(|s| s.as_slice() == bytes) {
            return;
        }
        self.secrets.push(bytes.to_vec());
        // 降序：扫描时第一个命中的就是最长的那个。
        self.secrets
            .sort_unstable_by_key(|secret| std::cmp::Reverse(secret.len()));
        self.max_len = self.secrets.first().map_or(0, Vec::len);
        self.enabled = true;
    }

    /// 是否有任何可遮蔽的值（无值时应直接 inherit，省掉一次管道拷贝）。
    pub fn is_active(&self) -> bool {
        self.enabled
    }

    /// 吃进一个读块，返回**可以安全输出**的已遮蔽字节。
    ///
    /// 可能返回空——说明全部内容还在等待确认（尾部保留）。
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        if !self.enabled {
            // 无密钥时不缓冲：直接穿透，零拷贝语义（调用方仍持有 chunk）。
            return chunk.to_vec();
        }
        self.pending.extend_from_slice(chunk);
        self.scan(true)
    }

    /// 流结束：把保留的尾巴按同样规则处理后输出。
    pub fn finish(&mut self) -> Vec<u8> {
        if !self.enabled {
            self.pending.clear();
            return Vec::new();
        }
        self.scan(false)
    }

    /// 扫描 `pending`，输出已确定的字节，并把吃掉的头部 `drain` 掉。
    ///
    /// `keep_tail` 为真时保留"可能成为匹配开头"的尾巴；为假（流结束）时全部处理完。
    fn scan(&mut self, keep_tail: bool) -> Vec<u8> {
        let pending = &self.pending;
        let secrets = &self.secrets;
        let max_len = self.max_len;

        let mut out = Vec::with_capacity(pending.len());
        let mut i = 0;
        while i < pending.len() {
            // 位置 `i` 的整扇窗口还没到齐 → 现在下结论可能漏配更长的密钥，
            // 保留尾巴（至多 max_len - 1 字节）等下一块。
            if keep_tail && i + max_len > pending.len() {
                break;
            }
            let rest = &pending[i..];
            // 先试最长的（secrets 已按长度降序），命中即最长匹配。
            if let Some(secret) = secrets.iter().find(|s| rest.starts_with(s)) {
                out.extend_from_slice(TAINTED.as_bytes());
                i += secret.len();
            } else {
                out.push(pending[i]);
                i += 1;
            }
        }
        // drain 一次，避免逐字节 remove(0) 的 O(n²) 搬移。
        self.pending.drain(..i);
        out
    }
}

/// 占位符，供测试与文档引用。
pub fn placeholder() -> &'static str {
    TAINTED
}

#[cfg(test)]
mod tests {
    use super::*;

    const LONG: &str = "ghp_0123456789abcdef";
    const SHORT: &str = "12345678";

    fn mk(secrets: &[&str]) -> Masker {
        Masker::with_secrets(secrets.iter().map(|s| s.to_string()))
    }

    /// 一次性喂完 + finish，返回完整输出。
    fn feed_all(masker: &mut Masker, input: &[u8]) -> Vec<u8> {
        let mut out = masker.push(input);
        out.extend(masker.finish());
        out
    }

    /// 逐字节喂入，返回（含 finish 的）完整输出——用于跨块回归。
    fn feed_bytes(masker: &mut Masker, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for byte in input {
            out.extend(masker.push(std::slice::from_ref(byte)));
        }
        out.extend(masker.finish());
        out
    }

    #[test]
    fn same_chunk() {
        let mut masker = mk(&[LONG]);
        let input = format!("token={LONG} end");
        let out = feed_all(&mut masker, input.as_bytes());
        assert_eq!(
            String::from_utf8(out).expect("输出应为 UTF-8"),
            format!("token={TAINTED} end"),
            "单块内的密钥必须被替换，周围文本原样保留"
        );
    }

    #[test]
    fn split_across_chunks_byte_by_byte() {
        let input = format!("before {LONG} middle {LONG} after").into_bytes();
        let expected = format!("before {TAINTED} middle {TAINTED} after").into_bytes();

        let mut one_shot = mk(&[LONG]);
        let once = feed_all(&mut one_shot, &input);

        let mut drip = mk(&[LONG]);
        let byte_wise = feed_bytes(&mut drip, &input);

        assert_eq!(once, expected, "一次性喂入的结果");
        assert_eq!(byte_wise, once, "1 字节分块必须与一次性喂入逐字节相同");
    }

    #[test]
    fn split_at_every_position() {
        let input = format!("x{LONG}y").into_bytes();
        let expected = format!("x{TAINTED}y").into_bytes();
        for split in 0..=input.len() {
            let mut masker = mk(&[LONG]);
            let mut out = masker.push(&input[..split]);
            out.extend(masker.push(&input[split..]));
            out.extend(masker.finish());
            assert_eq!(out, expected, "切点 {split} 处必须仍被完整替换");
        }
    }

    #[test]
    fn short_values_untouched() {
        let mut masker = mk(&["true", "0", "prod", "1234567"]);
        assert!(!masker.is_active(), "全部短于 MIN_SECRET_LEN → 不启用");

        let out = feed_all(&mut masker, b"true 0 prod 1234567");
        assert_eq!(out, b"true 0 prod 1234567", "短值必须原样通过");

        // 恰好 8 字节开始启用。
        let mut boundary = mk(&["12345678"]);
        assert!(boundary.is_active(), "长度等于 MIN_SECRET_LEN 应启用");
        assert_eq!(feed_all(&mut boundary, b"12345678"), TAINTED.as_bytes());
    }

    #[test]
    fn multiple_secrets_in_one_chunk() {
        let second = "sk-ant-api03-xyz";
        let mut masker = mk(&[LONG, second]);
        let input = format!("{LONG} and {second} and {LONG}").into_bytes();
        let out = feed_all(&mut masker, &input);
        assert_eq!(
            String::from_utf8(out).expect("输出应为 UTF-8"),
            format!("{TAINTED} and {TAINTED} and {TAINTED}")
        );
    }

    #[test]
    fn longest_match_wins_on_shared_prefix() {
        let long = format!("{SHORT}EXTRA");
        for order in [[SHORT, &long[..]], [&long[..], SHORT]] {
            let mut masker = mk(&order);
            // 一次喂入、逐字节喂入，都必须只剩一个占位符，不留 "EXTRA" 碎片。
            assert_eq!(
                feed_all(&mut masker, &long.clone().into_bytes()),
                TAINTED.as_bytes(),
                "一次喂入：应取最长匹配"
            );

            let mut drip = mk(&order);
            assert_eq!(
                feed_bytes(&mut drip, &long.clone().into_bytes()),
                TAINTED.as_bytes(),
                "逐字节喂入：应取最长匹配"
            );
        }

        // 前缀密钥自身单独出现时仍要被遮蔽。
        let mut masker = mk(&[SHORT, &long[..]]);
        assert_eq!(feed_all(&mut masker, SHORT.as_bytes()), TAINTED.as_bytes());
    }

    #[test]
    fn finish_flushes_held_secret() {
        // 较长的候选迫使较短的完整密钥先被保留在缓冲区里。
        let long = "ABCDEFGHIJKLMNOPQRST";
        let mut masker = mk(&[SHORT, long]);
        let held = masker.push(SHORT.as_bytes());
        assert!(held.is_empty(), "完整的短密钥应被保留，等待更长的候选");

        let tail = masker.finish();
        assert_eq!(tail, TAINTED.as_bytes(), "finish 必须清掉缓冲区里的密钥");
        assert!(masker.finish().is_empty(), "finish 应幂等且不重复输出");

        // 流结束时残缺的密钥前缀不是完整密钥，应原样吐出（不能凭空吞掉数据）。
        let mut truncated = mk(&[LONG]);
        assert!(truncated.push(&LONG.as_bytes()[..5]).is_empty());
        assert_eq!(truncated.finish(), LONG.as_bytes()[..5].to_vec());
    }

    #[test]
    fn empty_and_secret_free_inputs_pass_through() {
        let mut empty = Masker::new();
        assert!(!empty.is_active());
        assert!(empty.push(b"").is_empty());
        assert!(empty.finish().is_empty());

        assert!(
            !Masker::with_secrets(Vec::new()).is_active(),
            "空集合不应启用遮蔽"
        );

        let mut plain = Masker::new();
        assert_eq!(feed_all(&mut plain, b"just some output\n"), b"just some output\n");

        // 只含短值时同样穿透。
        let mut shorts = mk(&["true", "0"]);
        assert_eq!(feed_all(&mut shorts, b"true and 0"), b"true and 0");
    }

    #[test]
    fn binary_bytes_pass_through() {
        let mut masker = mk(&[LONG]);
        let mut input = vec![0xff, 0x00, 0xfe, 0x80];
        input.extend_from_slice(LONG.as_bytes());
        input.extend_from_slice(&[0x81, 0xc3, 0x28]);

        let mut expected = vec![0xff, 0x00, 0xfe, 0x80];
        expected.extend_from_slice(TAINTED.as_bytes());
        expected.extend_from_slice(&[0x81, 0xc3, 0x28]);

        assert_eq!(feed_all(&mut masker, &input), expected, "非 UTF-8 字节原样通过");

        let mut drip = mk(&[LONG]);
        assert_eq!(feed_bytes(&mut drip, &input), expected, "逐字节喂入同样成立");
    }

    #[test]
    fn arbitrary_chunkings_match_one_shot() {
        // 确定性伪随机（LCG）分块：多密钥 + 二进制噪声，任何切分都必须与一次性喂入相同。
        const A: &str = "sk-live-0123456789abcdef";
        const B: &str = "ABCDEFGHIJKLMNOPQRST";
        const C: &str = "sk-live-0123"; // 与 A 共享前缀的较短值
        let mut input = Vec::new();
        let mut state: u32 = 0x2545_F491;
        for i in 0..256u32 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223) ^ i;
            if state.is_multiple_of(7) {
                let secret: &[u8] = match state % 3 {
                    0 => A.as_bytes(),
                    1 => B.as_bytes(),
                    _ => C.as_bytes(),
                };
                input.extend_from_slice(secret);
            } else {
                input.push((state >> 11) as u8); // 含任意非 UTF-8 字节
            }
        }

        let mut one_shot = mk(&[A, B, C]);
        let expected = feed_all(&mut one_shot, &input);

        let mut state: u32 = 7;
        for round in 0..64 {
            let mut chunked = mk(&[C, A, B]);
            let mut out = Vec::new();
            let mut pos = 0;
            while pos < input.len() {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let take = (state as usize % 5) + 1;
                let end = (pos + take).min(input.len());
                out.extend(chunked.push(&input[pos..end]));
                pos = end;
            }
            out.extend(chunked.finish());
            assert_eq!(out, expected, "第 {round} 轮随机分块与一次性喂入不一致");
            for secret in [A, B, C] {
                assert!(
                    !out.windows(secret.len()).any(|w| w == secret.as_bytes()),
                    "第 {round} 轮输出里残留明文密钥 {secret}"
                );
            }
        }
    }
}
