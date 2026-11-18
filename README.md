# pairwise-envelope-guard

数据库字段要加密后，信封加密的细节就开始出错：KEK 和 DEK 混用同一把 key；GCM 的 nonce 重复使用；AAD 没绑定租户和字段名；密文不带 key version，轮换后解不开；解密失败回落到明文；IV 用固定值；认证标签被截断；密钥从环境变量直接拼进日志；旧数据不迁移就切新 key；空值加密成可预测密文。security/envelope_guard.py 是核心，tests/test_envelope_guard.py 15个红。要修的是：KEK/DEK 分离；nonce 唯一；AAD 绑定上下文；key version；失败不回退；随机 IV；完整 tag；密钥脱敏；双写迁移；空值随机化。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：其他；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
