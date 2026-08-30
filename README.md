# 基于多智能体协同的网络安全威胁智能分析系统

## 📋 项目概述

本项目是一个基于多智能体协同的网络安全威胁智能分析系统，利用Qwen2-7B大语言模型和GPU加速技术，实现对网络威胁的智能分析和预警。

## 🚀 核心功能

### 多智能体架构
- 🧭 **路由智能体**：负责威胁初步分类和路由决策
- 🕷️ **Web攻击专家**：专注Web应用安全分析（SQL注入、XSS、CSRF等）
- 💥 **漏洞利用专家**：深度分析系统漏洞（命令注入、目录遍历等）
- 🌐 **非法连接专家**：检测恶意网络行为（DDoS、暴力破解、扫描等）

### 技术特性
- 🤖 基于Qwen2-7B大语言模型
- ⚡ RTX 4070 SUPER GPU加速
- 🔄 RAG（检索增强生成）技术
- 📊 实时威胁可视化
- 💾 支持Excel数据导入分析

## 🏗️ 项目结构

```
multi-agent-security-analysis/
├── src/                          # 源代码目录
│   ├── agents/                   # 智能体模块
│   ├── analysis/                 # 分析引擎
│   ├── api/                      # API服务
│   ├── models/                   # 模型管理
│   ├── parsers/                  # 日志解析
│   ├── rag/                      # RAG系统
│   └── utils/                    # 工具模块
├── web_app/                      # Web应用
├── web_demo/                     # 演示系统
├── models/                       # 模型文件
├── data/                         # 数据目录
├── logs/                         # 日志文件
├── config/                       # 配置文件
└── docs/                         # 文档目录
```

## 🛠️ 环境要求

- Python 3.9+
- CUDA 11.0+ (GPU加速)
- PyTorch 2.0+
- Streamlit
- FastAPI
- Plotly

## 📦 安装步骤

1. 克隆项目
```bash
git clone https://github.com/insistgang/multi-agent-security-analysis.git
cd multi-agent-security-analysis
```

2. 安装依赖
```bash
pip install -r requirements.txt
```

3. 启动系统
```bash
# API (default bind is 127.0.0.1:8000; pass --host 0.0.0.0 only if you intend to expose it)
python -m src.api.server --host 127.0.0.1 --port 8000

# Optional: require a key on /api/v1/*
# export API_KEY=your-secret
# export CORS_ORIGINS=http://localhost:7777,http://localhost:8886

# Web application (calls the API)
cd web_app && streamlit run app.py --server.port 7777

# Demo dashboard (does not call the API)
cd web_demo && streamlit run excel_final.py --server.port 8886
```

Analyze endpoint body is nested:

```json
{
  "alert_data": {
    "attack_type": "SQL Injection",
    "payload": "' UNION SELECT * FROM users --",
    "source_ip": "192.168.1.200",
    "target_ip": "10.0.0.10"
  },
  "enable_rag_enhancement": true
}
```

## 📊 演示系统

### Excel数据可视化（推荐）
- 地址：http://localhost:8886
- 功能：Excel数据转JSON格式可视化
- 数据：13,926条真实攻击记录

### 多智能体协同分析
- 地址：http://localhost:7777 (`web_app/app.py`)
- 功能：单条/批量告警分析，依赖已启动的 API

## 📈 数据支持

- 攻击日志V2.xlsx（100,000条记录）
- 风险信息.xlsx（3,926条记录）
- 支持Excel自动转JSON格式

## 🧪 核心测试

无需下载 Qwen2-7B 或安装深度学习依赖，即可运行核心可靠性测试：

```bash
python3 -m unittest discover -s tests -v
```

当前测试覆盖熔断器行为、规则引擎、路由关键词、路径允许列表和威胁等级判定。

后续可移植性、安全和测试改进见 [`docs/IMPROVEMENT_ROADMAP.md`](docs/IMPROVEMENT_ROADMAP.md)。

## 🤖 AI模型

- 主模型：Qwen2-7B
- GPU：RTX 4070 SUPER
- 显存：12GB
- 推理速度：< 1秒

## 📞 联系方式

- 技术支持：[联系方式]
- 项目文档：docs/

## 📄 许可证

[许可证类型]

---

**注意**：本项目仅用于学习和研究目的。
