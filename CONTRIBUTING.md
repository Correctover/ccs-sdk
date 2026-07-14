# Contributing to ccs-sdk

## ⚠️ 重要声明 — 商业授权

**ccs-sdk (Correctover Code Scanner SDK) 是商业付费产品，不是开源项目。**

本仓库的源代码公开以供审查和评估，但**不构成开源**。详见 [LICENSE](LICENSE) 的商业授权条款。

## 贡献政策

### 我们不接受外部 Pull Request
本仓库是展示窗口，不是社区协作项目。我们不接受外部的 PR 或功能贡献。
如有 Bug 反馈或功能建议，请通过以下渠道联系。

### 反馈渠道
- **安全漏洞报告**: 请通过 security@correctover.com 私下报告
- **Bug 反馈**: 在 GitHub Issues 提交（注意：不保证及时回复公共 issue）
- **商业合作/采购**: 联系 wangguigui@correctover.com

### 内部开发
所有开发由 Correctover 内部团队完成。提交到此仓库的代码：
- 必须通过完整的自动化测试套件
- 必须遵循现有的代码风格和架构模式
- 必须更新 CHANGELOG.md
- 必须经过代码审查

## 代码规范
（内部使用，外部贡献者无需关注）
- Python 3.10+，类型注解强制
- 遵循 pyproject.toml 中配置的 lint 规则
- 所有新功能必须有单元测试
