"""提交完整性校验：sha256-merkle-v1 摘要算法。

该算法仅在创建会话显式声明 digest_algorithm="sha256-merkle-v1" 时生效；
其它算法标识一律沿用“仅记录、不校验”的旧行为。

字节级规则（所有哈希均为 SHA-256，输入输出均为原始 32 字节）：
- 叶节点：SHA-256(0x00 || 分片摘要原始 32 字节)，其中分片摘要是 complete
  上报的 chunk_digest（64 位小写十六进制）解码所得；
- 父节点：SHA-256(0x01 || 左子节点 32 字节 || 右子节点 32 字节)；
- 每层按分片/节点序号两两配对；该层节点数为奇数时，末节点复制自身后再配对，
  复制只参与配对、不产生新的哈希输入分支；
- 逐层向上直至仅剩单一根节点，其 64 位小写十六进制即为完整文件摘要，
  在提交（finalize）时与创建会话登记的 file_digest 常量时间比较。

单分片会话的根就是其唯一叶节点 SHA-256(0x00 || chunk_digest)，不额外复制。
"""
from __future__ import annotations

import hashlib
import hmac
import re

MERKLE_DIGEST_ALGORITHM = "sha256-merkle-v1"
SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}")
SHA256_DIGEST_LEN = 32
LEAF_PREFIX = b"\x00"
PARENT_PREFIX = b"\x01"


def is_sha256_hex(value: str) -> bool:
    """value 是否恰好为 64 位小写十六进制（拒绝大写/空白/前后缀）。"""
    return bool(SHA256_HEX_RE.fullmatch(value))


def is_merkle_algorithm(digest_algorithm: str) -> bool:
    return digest_algorithm == MERKLE_DIGEST_ALGORITHM


def _leaf_hash(digest_hex: str) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + bytes.fromhex(digest_hex)).digest()


def _parent_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(PARENT_PREFIX + left + right).digest()


def merkle_root_hex(chunk_digests: list[str]) -> str:
    """按分片序号计算 sha256-merkle-v1 根，返回 64 位小写十六进制。

    chunk_digests 必须已按 chunk_index 升序排列，且每项均为 64 位小写十六进制；
    调用方负责在入口处完成格式校验（不合法的会话在创建/完成时即被拒绝）。
    """
    if not chunk_digests:
        raise ValueError("merkle root requires at least one chunk digest")
    level = [_leaf_hash(d) for d in chunk_digests]
    while len(level) > 1:
        if len(level) % 2 == 1:
            # 奇数末节点复制自身后配对
            level.append(level[-1])
        level = [
            _parent_hash(level[i], level[i + 1])
            for i in range(0, len(level), 2)
        ]
    return level[0].hex()


def constant_time_hex_equal(a: str, b: str) -> bool:
    """对两个十六进制摘要做常量时间比较（hmac.compare_digest 对等长 ASCII 字符串
    走常量时间路径），避免提交校验结果泄露期望摘要的逐字节信息。"""
    return hmac.compare_digest(a, b)
