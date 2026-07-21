# 🏴‍☠️ Correctover 赏金狩猎对账 Ledger

> **All bounty submissions across all agents and channels — single source of truth.**
> Last updated: 2026-07-21T15:00 CST
> Maintainer: Correctover Agent (auto-sync) + Manual entries

---

## 📊 Summary Dashboard

| Channel | Submissions | Status | Expected Reward | Actual |
|---------|------------|--------|----------------|--------|
| ZDI | 52 | OPEN (triage ~30d) | ~$14,000+ | $0 |
| HackerOne | 3 | 2 CLOSED + 1 ACTIVE (#3878033) | — | $0 |
| GitHub Advisory | 4 | Under Review | $20K-$60K | $0 |
| huntr.dev | 2+ | Under Review | $500-$5K | $0 |
| MSRC | 8 (email) | Under Review | $10K-$50K/each | $0 |
| 阿里云ASRC | 6 (email) | Under Review | TBD | $0 |
| Apple | 1 (portal) | Under Review | TBD | $0 |
| **TOTAL** | **76+** | | **~$54K-$200K+** | **$0** |

---

## 📋 Detailed Ledger

### 1. ZDI — 52 Cases (Correctover0001 ~ Correctover0052)
**提交日期**: 2026-07-12 (50 cases) + 2026-07-21 (2 cases) | **状态**: 全部 OPEN | **排他期**: ~30天

#### Original 50 Cases (2026-07-12)
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

#### New ZDI Cases (2026-07-21)
| Case | 目标 | 类型 | CVSS | 提交时间 | 备注 |
|------|------|------|------|---------|------|
| 0051 | Dify P1-PATH (Apollo Config Path Traversal) | Path Traversal | 9.8 | 2026-07-21 | Apollo config source allows arbitrary file read |
| 0052 | FastMCP ENV-LEAK | Information Disclosure | 7.0 | 2026-07-21 | Full env vars passed to subprocesses |

**漏洞类型分布 (52 cases)**: Symlink Write(12) | Path Traversal(11) | SSRF(7) | Cmd Injection(6) | File Write(5) | SQL/NoSQL(3) | RCE(2) | Information Disclosure(2) | Other(4)

---

### 2. HackerOne

| Report ID | 目标 | 漏洞 | 状态 | 备注 |
|-----------|------|------|------|------|
| #3859881 | Anthropic MCP Server | Path Traversal + Unsanctioned Tool Exec | ❌ CLOSED (N/A) | H1: third-party MCP -> GitHub Advisory |
| #3859936 | Anthropic MCP | DNS Rebinding | ❌ CLOSED (Duplicate) | Same root cause as #3859881 |
| **#3878033** | **MCP Python SDK readOnlyHint Bypass** | **Protocol-level design flaw** | **✅ ACTIVE** | **87 instances/6 frameworks, MSRC confirmed, ZDI submitted. CVSS 7.5** |

---

### 3. GitHub Security Advisories

| Advisory/Issue | 目标 | 漏洞 | CVSS | 状态 |
|---------------|------|------|------|------|
| BerriAI/litellm #32862 | LiteLLM | Guardrail SSRF | 8.6 | Under Review |
| ckreiling/mcp-server-docker #53 | Docker MCP | Cmd Injection + SSRF | 9.3/9.8 | Under Review |
| CrewAIInc/crewAI #3073 | CrewAI AG2 | eval() RCE | 9.8 | Under Review |
| run-llama/llama_index #22296 | LlamaIndex | Pickle RCE | 9.8 | Under Review |

---

### 4. huntr.dev

| 目标 | 漏洞 | 状态 |
|------|------|------|
| GongRzhe/Office-Word-MCP-Server | Symlink Arbitrary File Write | Under Review |
| GongRzhe/Office-PowerPoint-MCP-Server | Symlink Arbitrary File Write | Under Review |

---

### 5. MSRC (Microsoft) — Email to security@microsoft.com

#### Batch 1 (2026-07-xx)
| 报告 | 目标 | 漏洞 | 状态 |
|------|------|------|------|
| Azure MCP Kusto SSRF | Azure MCP Server | SSRF + Azure AD Token Theft | Under Review |
| Azure MCP Multi-Vuln | Azure MCP Server | SSRF + SQL Injection + Credential Leakage | Under Review |
| Foundry Service SSRF | Azure MCP Foundry | SSRF (CVSS 9.1) | Under Review |
| PostgreSQL SQL Injection | Azure MCP Server | SQL Injection | Under Review |
| Connection String Injection | Azure MCP Server | Injection -> SSRF | Under Review |
| Cosmos DB NoSQL Injection | Azure MCP Server | NoSQL Injection | Under Review |

#### Batch 2 (2026-07-21) — Framework-Level
| 报告 | 目标 | 漏洞 | CVSS | Case ID | Status |
|------|------|------|------|---------|--------|
| AutoGen P1-PATH | AutoGen magentic-one-cli | Path Traversal via user-controlled file path | 9.8 | CORRECTOVER-2026-001 | ✅ CONFIRMED |
| Semantic Kernel readOnlyHint | Semantic Kernel MCP | readOnlyHint parsed but not enforced | 7.5 | CORRECTOVER-2026-004 | ✅ CONFIRMED |

---

### 6. 阿里云 ASRC — Email to security@service.alibaba.com

| 批次 | 目标 | 提交日期 | 状态 |
|------|------|---------|------|
| Spring AI Alibaba (6 vulns) | Spring AI Alibaba framework | 2026-07-13 | Under Review |

---

### 7. Apple Security — Portal

| 报告 | 目标 | 漏洞 | CVSS | 状态 |
|------|------|------|------|------|
| AppleComputeEnsembler TLS Bypass | macOS | TLS zero-validation, MITM can intercept Apple Intelligence data | 9.8 | Under Review |

---

### 8. Financial Outreach (2026-07-21)

| Batch | 目标 | 方式 | 日期 | 状态 |
|-------|------|------|------|------|
| Batch 1 | Dukascopy (info@) + Duco (security@, info@) | Email — Security Audit Pitch | 2026-07-21 | ✅ Sent |
| Batch 2 | Dukascopy (security@, dpo@) + UniCredit CISO + Mambu + Blend Labs (vuln report) | Email — Vuln Report + Audit Pitch | 2026-07-21 | ✅ Sent |
| Citi Notification | opensource@citi.com (FINOS AIGF) | Email — H1 #3878033 notification | 2026-07-21 | ✅ Sent |
| SAP | SAP Security Response Portal | AutoGen P1-PATH + readOnlyHint | — | ⏳ Portal unreachable (needs VPN) |
| TSRC | Tencent Cloud TI-ONE (Dify) | Dify P1-PATH | — | ⏳ ZDI covers this |
| JPCERT/CC | Mizuho Financial Group | Dify P1-PATH | — | ⏳ ZDI covers this |

---

## 🔄 Update Protocol

### Pre-submission Duplicate Check
Search this file before every new submission:
1. Target name/domain
2. Vulnerability type
3. CVE ID (if any)
-> Skip or merge if match found

### Auto-Update Rules
- **Local AI Pipeline (MSRC)**: Append to §5 after each submission
- **ZDI Portal**: Check status every 30 min
- **HackerOne**: Update report status on check

### Status Definitions
| Status | Meaning |
|--------|---------|
| SUBMITTED | Submitted, awaiting response |
| OPEN | ZDI: awaiting triage |
| TRIAGE | Under review |
| ACCEPTED | Accepted, awaiting CVE/bounty |
| REJECTED | Rejected |
| DUPLICATE | Duplicate submission |
| NEEDS_REDIRECT | Needs re-routing to another channel |
| PAID | Bounty received |
| CLOSED | Case closed |
| CONFIRMED | MSRC confirmed valid |
| ACTIVE | H1 report is active |

### Submission Channels
| Channel | Method | Notes |
|---------|--------|-------|
| ZDI | Portal | ~30 day embargo |
| HackerOne | Web (CDP) | CDP automation via Chrome v150 |
| GitHub Advisory | Web | Direct to maintainer |
| huntr.dev | Web form | Manual only |
| MSRC | Email | security@microsoft.com |
| ASRC | Email | security@service.alibaba.com |
| Apple | Portal | security.apple.com/submit |
| Bugcrowd | Web | Login required |

---

## 📅 Daily Reconciliation
- **09:00 CST** — Local AI pipeline auto-summary
- **End of Day** — Full channel status update

---

## 🔒 Confidential
This document contains sensitive security research data.
Do not share externally.
Access: Correctover Agent + Owner (王桂桂)
