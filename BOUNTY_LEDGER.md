# 🏴‍☠️ Correctover 赏金狩猎对账 Ledger

> **All bounty submissions across all agents and channels — single source of truth.**
> Last updated: 2026-07-14T13:00 CST
> Maintainer: Correctover Agent (auto-sync) + Manual entries

---

## 📊 Summary Dashboard

| Channel | Submissions | Status | Expected Reward | Actual |
|---------|------------|--------|----------------|--------|
| ZDI | 50 | OPEN (triage ~30d) | ~$14,000 | $0 |
| HackerOne | 2 | CLOSED → need redirect | — | $0 |
| GitHub Advisory | 4 | Under Review | $20K-$60K | $0 |
| huntr.dev | 2+ | Under Review | $500-$5K | $0 |
| MSRC | 6+ (email) | Under Review | $10K-$50K/each | $0 |
| 阿里云ASRC | 6 (email) | Under Review | TBD | $0 |
| Apple | 1 (portal) | Under Review | TBD | $0 |
| **TOTAL** | **71+** | | **~$54K-$200K+** | **$0** |

---

## 📋 Detailed Ledger

### 1. ZDI — 50 Cases (Correctover0001 ~ Correctover0050)
**提交日期**: 2026-07-12 | **状态**: 全部 OPEN | **排他期**: ~30天

| Case | 目标 | 类型 | CVSS |
|------|------|------|------|
| 0001 | Host Root FS Mount RCE | RCE | 9.8 |
| 0002 | Office-Word/PowerPoint-MCP-Server | Symlink Write | 7.8 |
| 0003 | SingleFile MCP write_file | Symlink Write | 7.8 |
| 0004 | synthadoc MCP export | Symlink Write | 7.8 |
| 0005 | fast-filesystem-mcp | Symlink Write | 7.8 |
| 0006 | douyin-mcp-server | SSRF + File Read | 8.1 |
| 0007 | Tele-AI/doc-ops-mcp | Symlink Write | 7.8 |
| 0008 | claude-thread-continuity | Path Traversal | 8.1 |
| 0009 | oraios/serena | Path Traversal | 8.1 |
| 0010 | facebook-ads-library-mcp | SSRF | 7.5 |
| 0011 | lyonzin/knowledge-rag | SSRF | 7.5 |
| 0012 | Klavis-AI/klavis (Excel) | Symlink Write | 7.8 |
| 0013 | Azure DevOps MCP Server | Symlink Write | 7.8 |
| 0014 | shungyan/genai-desktop-app | Arbitrary File Write | 7.8 |
| 0015 | Klavis-AI/klavis (dup) | Symlink Write | 7.8 |
| 0016 | haris-musa/excel-mcp-server | Symlink Write | 7.8 |
| 0017 | shungyan/genai-desktop-app (dup) | Arbitrary File Write | 7.8 |
| 0018 | mssql_mcp_server | SQL Injection | 8.8 |
| 0019 | pgmcp | SQL Injection | 8.1 |
| 0020 | mysql_mcp_server | SQL Injection | 8.1 |
| 0021 | mongodb-lens | NoSQL Injection + SSRF | 8.3 |
| 0022 | puppeteer-mcp-server | SSRF | 7.5 |
| 0023 | BrowserMCP (Chrome ext) | SSRF | 7.5 |
| 0024 | stealth-browser-mcp | JS Exec + SSRF | 8.1 |
| 0025 | TrendRadar | Path Traversal | 7.5 |
| 0026 | MladenSU/cli-mcp-server | Command Injection | 9.8 |
| 0027 | theailanguage/terminal_server | Command Injection | 9.8 |
| 0028 | lefayjey/linWinPwn | Command Injection | 9.8 |
| 0029 | KiCAD-MCP-Server | Arbitrary File Write | 7.8 |
| 0030 | charlesxu90/ProteinMCP | Command Injection | 9.8 |
| 0031 | TrendRadar | Arbitrary File Read | 7.5 |
| 0032 | ai-bash-agent | Unsafe Cmd Exec Bypass | 9.8 |
| 0033 | LeapLabTHU/cooragent | Path Traversal | 7.5 |
| 0034 | bcurts/agentchattr | Path Traversal | 7.5 |
| 0035 | MAA-AI/MaaMCP | Path Traversal | 7.5 |
| 0036 | MeterLong/MCP-Doc | Symlink Write | 7.8 |
| 0037 | EtaYang10th/Open-M3-Bench | Symlink Write | 7.8 |
| 0038 | assert6/wechat-mcp | Symlink Write | 7.8 |
| 0039 | ZhijingEu/value-investing-tools | Path Traversal | 7.5 |
| 0040 | fosferon/fp | Path Traversal | 7.5 |
| 0041 | Andyfer004/Server-MCP-Local | Arbitrary File Read | 7.5 |
| 0042 | stevenvo780/MCP-delegate-agents | Symlink Write | 7.8 |
| 0043 | osok/claude-code-project-memory | Path Traversal | 7.5 |
| 0044 | 1271004179/mcp-clickhouse | SSRF | 7.5 |
| 0045 | 666ghj/Bella-on-Android | Arbitrary File Read | 7.5 |
| 0046 | 794082274/chat-ppt-agent | SSRF | 7.5 |
| 0047 | 816054419/mcp-server-bigquery | SSRF | 7.5 |
| 0048 | a235799249/mcp-test | SSRF | 7.5 |
| 0049 | AutoGen CaptainAgent | RCE | 9.8 |
| 0050 | CrewAI MCP STDIO | Command Injection | 9.8 |

**漏洞类型分布**: Symlink Write(12) | Path Traversal(10) | SSRF(7) | Cmd Injection(6) | File Write(5) | SQL/NoSQL(3) | RCE(2) | Other(5)

---

### 2. HackerOne (Anthropic)

| Report ID | 目标 | 状态 | 备注 |
|-----------|------|------|------|
| #3859881 | Anthropic MCP Server Path Traversal + Unsanctioned Tool Exec | ❌ CLOSED (N/A) | H1说第三方MCP走GitHub Advisory，不走Anthropic H1 |
| #3859936 | Anthropic MCP DNS Rebinding | ❌ CLOSED (Duplicate) | 与#3859881重复判定 |

**⚠️ ACTION**: 两个报告都需改道 GitHub Security Advisories 提交给 MCP Python SDK 仓库维护者。

---

### 3. GitHub Security Advisories

| Advisory/Issue | 目标 | 漏洞 | CVSS | 状态 | 响应 |
|---------------|------|------|------|------|------|
| BerriAI/litellm #32862 | LiteLLM | Guardrail SSRF (sandbox不防SSRF，可访问169.254.169.254) | 8.6 | Under Review | ✅ "Adding external security to take a look" |
| ckreiling/mcp-server-docker #53 | Docker MCP | STDIO Cmd Injection → RCE + HTTP Header Injection → SSRF | 9.3/9.8 | Under Review | — |
| CrewAIInc/crewAI #3073 | CrewAI AG2 | eval() RCE (沙箱逃逸) | 9.8 | Under Review | — |
| run-llama/llama_index #22296 | LlamaIndex | Pickle RCE (模型加载任意代码执行) | 9.8 | Under Review | — |

---

### 4. huntr.dev

| 目标 | 漏洞 | 状态 |
|------|------|------|
| GongRzhe/Office-Word-MCP-Server | Symlink Arbitrary File Write | Under Review |
| GongRzhe/Office-PowerPoint-MCP-Server | Symlink Arbitrary File Write | Under Review |

---

### 5. MSRC (Microsoft) — 邮件提交 security@microsoft.com

| 报告 | 目标 | 漏洞 | 提交方式 | 状态 |
|------|------|------|---------|------|
| Azure MCP Kusto SSRF | Azure MCP Server | SSRF + Azure AD Token Theft | Email | Under Review |
| Azure MCP Multi-Vuln | Azure MCP Server | SSRF + SQL Injection + Credential Leakage | Email | Under Review |
| Foundry Service SSRF | Azure MCP Foundry | SSRF (CVSS 9.1) | Email | Under Review |
| PostgreSQL SQL Injection | Azure MCP Server | SQL Injection | Email | Under Review |
| Connection String Injection | Azure MCP Server | Injection → SSRF | Email | Under Review |
| Cosmos DB NoSQL Injection | Azure MCP Server | NoSQL Injection | Email | Under Review |

**Pipeline**: 本地AI管道 7/15 9AM首次自动执行，预计新增11+目标

---

### 6. 阿里云 ASRC — 邮件提交 security@service.alibaba.com

| 批次 | 目标 | 提交日期 | 状态 |
|------|------|---------|------|
| Spring AI Alibaba (6个漏洞) | Spring AI Alibaba框架 | 2026-07-13 | Under Review |

---

### 7. Apple Security — Portal提交

| 报告 | 目标 | 漏洞 | CVSS | 状态 |
|------|------|------|------|------|
| AppleComputeEnsembler TLS Bypass | macOS | TLS零验证，MITM可拦截Apple Intelligence推理数据 | 9.8 | Under Review |

---

## 🔄 Update Protocol

### 提交前防重复检查
**每次新提交前必须搜索本文件**：
1. 搜目标名称/域名
2. 搜漏洞类型
3. 搜CVE编号（如有）
→ 找到匹配项则跳过或合并

### 自动更新规则
- **本地AI管道 (MSRC)**: 每次提交后自动追加到 §5
- **Coze Agent**: 每次手动提交后更新状态
- **ZDI Portal**: 每30min检查状态变化
- **HackerOne**: 每次检查时更新报告状态

### 状态定义
| 状态 | 含义 |
|------|------|
| SUBMITTED | 已提交，等待响应 |
| OPEN | ZDI专用，等待triage |
| TRIAGE | 审核中 |
| ACCEPTED | 已接受，等待CVE/赏金 |
| REJECTED | 已拒绝 |
| DUPLICATE | 重复提交 |
| NEEDS_REDIRECT | 需改道其他渠道 |
| PAID | 赏金已到账 |
| CLOSED | 已关闭 |

### 提交渠道定义
| 渠道 | 提交方式 | 备注 |
|------|---------|------|
| ZDI | Portal提交 | 排他期~30天，期间不可转投 |
| HackerOne | Web提交 | 需登录账号 |
| GitHub Advisory | Web提交 | 直接提交给仓库维护者 |
| huntr.dev | Web表单 | 无API，需手动 |
| MSRC | Email | security@microsoft.com |
| ASRC | Email | security@service.alibaba.com |
| Apple | Portal | security.apple.com/submit |
| Bugcrowd | Web提交 | 需登录账号 |

---

## 📅 Daily Reconciliation
- **09:00 CST** — 本地AI管道执行后自动汇总
- **12:00 CST** — Coze Agent 30min检查时同步
- **End of Day** — 全渠道状态汇总，更新Dashboard

---

## 🔒 Confidential
This document contains sensitive security research data.
Do not share externally.
Access: Correctover Agent + Owner (王桂桂)
