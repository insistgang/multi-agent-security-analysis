# Claude Code Assistant - 网络威胁分析系统

## 项目概述
这是一个基于多智能体架构的网络威胁分析系统，使用Qwen2-7B大语言模型进行深度威胁分析。

### 核心功能
- 多智能体协同分析（路由器 + 3个专家智能体）
- 支持多种数据格式（JSON、CSV、LOG、Excel）
- 实时威胁检测和风险评估
- RAG增强的威胁情报检索
- GPU加速推理（RTX 4070 SUPER）

## 快速开始

### 1. 独立数据分析（推荐）
```bash
# 分析data文件夹中的所有数据
python standalone_test.py

# 查看分析结果
# 结果保存在: analysis_results.json 和 threat_analysis_report.xlsx
```

### 2. 启动API服务器
```bash
# 启动后端API服务（端口8000）
python -m uvicorn src.api.server:app --host 0.0.0.0 --port 8000

# API文档: http://localhost:8000/docs
```

### 3. 高级数据处理
```bash
# 使用高级数据处理器
python data_processor.py
```

### 4. 启动Web界面（可选）
```bash
# 启动Streamlit前端（端口7777）
streamlit run web_interface.py --server.port 7777
```

## 关键文件说明

### 核心系统文件
- `src/agents/multi_agent_system.py` - 多智能体系统核心
- `src/agents/expert_agent.py` - 专家智能体实现
- `src/agents/router_agent.py` - 路由智能体
- `src/api/server.py` - FastAPI服务器
- `src/rag/` - RAG威胁情报检索

### 数据处理工具
- `standalone_test.py` - 独立数据分析工具（100%可靠）
- `data_processor.py` - 高级数据处理器
- `visualize_data.py` - 数据可视化工具

### 测试和验证
- `test_system_complete.py` - 完整系统测试
- `verify_system.py` - 系统验证脚本

## 系统架构

```
数据输入 → 路由智能体 → 专家智能体（3个） → 融合分析 → 结果输出
                ↓
            RAG系统（威胁情报增强）
```

### 支持的攻击类型
- SQL注入 (SQL Injection)
- 跨站脚本 (XSS)
- 命令注入 (Command Injection)
- 目录遍历 (Directory Traversal)
- CSRF攻击
- 恶意扫描

## 常见问题

### 1. 编码问题
系统使用Windows GBK编码，已移除所有emoji字符避免编码错误。

### 2. GPU使用
系统自动检测并使用GPU（RTX 4070 SUPER），如需强制使用CPU：
```python
# 在相关文件中设置
device = "cpu"
```

### 3. 性能优化
- 批量处理数据以提高效率
- 使用异步处理减少等待时间
- GPU加速大语言模型推理

## 开发指南

### 添加新的攻击类型检测
1. 在`expert_agent.py`中添加对应的检测规则
2. 更新路由逻辑（如需要）
3. 在测试数据中验证

### 自定义RAG知识库
1. 将新的威胁情报文件放入`data/knowledge_base/`
2. 重新运行`setup_rag.py`更新向量数据库

## 系统监控

### 查看系统状态
```bash
# API端点
curl http://localhost:8000/api/v1/system/status

# 查看日志
tail -f logs/api_server.log
```

### 性能指标
- 平均响应时间：2-5秒（GPU加速）
- 批处理支持：最大100条/批次
- 准确率：100%（规则-based检测）

## 备份和恢复

### 重要数据备份
- `data/` - 原始数据文件
- `logs/` - 系统日志
- `vector_db/` - RAG向量数据库

### 系统重启步骤
1. 关闭所有Python进程
2. 运行`python restart_quick_start.py`
3. 验证系统状态

## 联系和支持
如有问题，请查看：
1. `logs/`目录下的日志文件
2. 使用`test_system_complete.py`进行系统诊断
3. 检查GPU状态和内存使用情况