# structured-log-sensitive-field-filter

Python 结构化日志敏感字段过滤库：处理嵌套路径、关联字段、误删保护和审计摘要。

## 功能

- **路径规则**：`users[*].phone`、`**.token`、`*` 通配，支持对象、数组与任意嵌套。
- **字段语义**：字段名映射到 `credential / token / pii / correlation / free_text`，
  无显式路径规则时按语义降级处理，同名字段在不同路径下可有不同语义。
- **关联键策略**：`user_id` 等关联字段用 HMAC-SHA256 伪匿名化（`corr:` 前缀），
  跨日志保持关联性且不可逆，不会被全部清空。
- **自由文本识别**：扫描邮箱、手机号、身份证、银行卡、JWT、Bearer、
  `password=...` 等凭据赋值，并检测组合信息。
- **审计摘要**：每个被处理字段记录加盐 SHA-256 摘要，报告含冲突、截断、
  循环引用与整体链式摘要，原始值不可恢复。
- **健壮性**：类型保持（int→0、str→`[REDACTED]` 等）、重复 key 全部处理、
  循环对象安全终止、超长字符串/深度/节点数截断、规则冲突取更严格动作并记录。

## 用法

```python
from logsanitizer import (
    Action, FieldSemantics, PathRule, Sanitizer, SanitizerConfig, Semantic, sanitize_json,
)

config = SanitizerConfig(
    path_rules=[
        PathRule("**.password", Action.REDACT),
        PathRule("users[*].phone", Action.PARTIAL, keep_prefix=3, keep_suffix=4),
        PathRule("order.id", Action.KEEP),
    ],
    field_semantics=FieldSemantics({
        "secret": Semantic.CREDENTIAL,
        "email": Semantic.PII,
        "user_id": Semantic.CORRELATION,
        "note": Semantic.FREE_TEXT,
    }),
    correlation_key=b"your-secret-key",
)

sanitized_text, report = sanitize_json(raw_json_log, config)
print(report.manual_review)   # 需要人工复核的自由文本
print(report.log_digest)      # 不可逆审计摘要
```

重复 key 的 JSON 请用 `logsanitizer.loads` 解析（`DupDict` 保留所有重复对），
序列化用 `logsanitizer.dumps`。

## 规则优先级

1. 路径规则按特异度排序（字面段多者胜），更具体的路径覆盖通配规则。
2. 同特异度冲突或路径规则与字段语义冲突时，取更严格动作
   （`REDACT > SCAN > PARTIAL > HASH > KEEP`），并写入 `report.conflicts`。

## 必须进入人工复核的自由文本

以下自由文本**不能**只靠自动脱敏，会被标记进 `report.manual_review`：

- **组合信息**：同一段文本出现 ≥2 类实体（如手机号 + 身份证、邮箱 + 银行卡），
  组合后可唯一识别个人，自动遮蔽可能遗漏上下文中的其他线索。
- **敏感上下文但无已知模式**：文本含“身份证 / 密码 / 护照 / 银行卡 / ssn”等
  关键词，但值不匹配任何已知格式（可能是手写、拍照转录或新格式），
  自动规则无法可靠定位敏感值。

此外建议人工抽查：被截断的超长日志（`report.truncations`）和出现规则冲突的
字段（`report.conflicts`），因为截断点之后的内容未被扫描，冲突字段的语义
可能需要业务确认。

## 测试

```bash
python -m unittest discover -s tests
```
