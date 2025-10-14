# 网络威胁智能分析系统 API 使用文档

## 📋 目录
1. [系统概述](#系统概述)
2. [快速开始](#快速开始)
3. [API接口说明](#api接口说明)
4. [请求格式](#请求格式)
5. [响应格式](#响应格式)
6. [使用示例](#使用示例)
7. [错误处理](#错误处理)
8. [性能优化](#性能优化)

## 系统概述

本系统是基于多智能体协同的网络安全威胁分析平台，通过API提供服务：

- **智能路由**：自动识别威胁类型并分发
- **专家分析**：3个专业领域专家智能体（Web攻击、漏洞利用、非法连接）
- **大模型推理**：集成Qwen2-7B模型进行深度分析
- **RAG增强**：结合威胁情报提供上下文分析
- **GPU加速**：利用RTX 4070显卡实现2-5秒快速响应

## 快速开始

### 1. 启动服务

```bash
# 进入项目目录
cd pj2.0

# 启动API服务（端口8000）
python -m src.api.server --port 8000

# 或使用一键启动脚本
python start_clean_system.py
```

### 2. 验证服务

```bash
# 检查系统状态
curl http://localhost:8000/api/v1/system/status
```

### 3. 第一个API调用

```python
import requests

# 分析SQL注入攻击
url = "http://localhost:8000/api/v1/analyze/alert"
data = {
    "alert_data": {
        "attack_type": "SQL Injection",
        "payload": "SELECT * FROM users WHERE id='1' OR '1'='1",
        "source_ip": "192.168.1.100",
        "target_ip": "10.0.0.5"
    },
    "enable_rag_enhancement": True
}

response = requests.post(url, json=data)
result = response.json()
print(result)
```

## API接口说明

### 基础URL
```
http://localhost:8000/api/v1
```

### 接口列表

| 接口 | 方法 | 描述 | 响应时间 |
|------|------|------|----------|
| `/analyze/alert` | POST | 分析单个安全告警 | 2-5秒 |
| `/analyze/batch` | POST | 批量分析多个告警 | 1-2秒/个 |
| `/system/status` | GET | 查询系统状态 | <100ms |
| `/metrics` | GET | 获取性能指标 | <100ms |
| `/threat-intel/recent` | GET | 查询近期威胁情报 | <500ms |

## 请求格式

### 1. 单个告警分析

**请求URL**: `POST /api/v1/analyze/alert`

**请求体**:
```json
{
  "alert_data": {
    "attack_type": "SQL Injection",
    "payload": "SELECT * FROM users WHERE id='1' OR '1'='1",
    "source_ip": "192.168.1.100",
    "target_ip": "10.0.0.5",
    "attack_stage": "execution",
    "threat_level": "high",
    "protocol": "HTTP"
  },
  "enable_rag_enhancement": true,
  "analysis_options": {
    "max_experts": 3,
    "confidence_threshold": 0.7
  }
}
```

**字段说明**:
- `alert_data`: 告警数据对象
  - `attack_type` (必填): 攻击类型
  - `payload` (必填): 攻击载荷
  - `source_ip` (可选): 源IP地址
  - `target_ip` (可选): 目标IP地址
  - `attack_stage` (可选): 攻击阶段
  - `threat_level` (可选): 威胁等级
  - `protocol` (可选): 协议类型
- `enable_rag_enhancement`: 是否启用RAG威胁情报增强
- `analysis_options`: 分析选项配置

### 2. 批量告警分析

**请求URL**: `POST /api/v1/analyze/batch`

**请求体**:
```json
{
  "alert_list": [
    {
      "attack_type": "SQL Injection",
      "payload": "' OR '1'='1",
      "source_ip": "192.168.1.100"
    },
    {
      "attack_type": "XSS",
      "payload": "<script>alert('XSS')</script>",
      "source_ip": "192.168.1.101"
    }
  ],
  "enable_rag_enhancement": false,
  "max_workers": 4
}
```

## 响应格式

### 成功响应

```json
{
  "success": true,
  "result": {
    "alert_id": "unique-id",
    "timestamp": "2025-01-10T12:00:00Z",
    "routing_analysis": {
      "selected_route": "web_attack",
      "target_agent": "web_attack_expert",
      "confidence": 0.95,
      "analysis": "匹配关键词: sql, select, or"
    },
    "expert_analysis": {
      "attack_type": "SQL Injection",
      "risk_score": 8.5,
      "confidence": 0.92,
      "detailed_analysis": "检测到SQL注入攻击...",
      "attack_technique": "UNION-based SQL Injection",
      "defense_suggestions": [
        "使用参数化查询",
        "实施输入验证",
        "部署WAF"
      ]
    },
    "overall_assessment": {
      "risk_score": 8.5,
      "threat_level": "High",
      "recommended_actions": [
        "立即阻断IP",
        "检查数据库日志",
        "更新安全规则"
      ]
    },
    "processing_chain": [
      {
        "agent": "router",
        "processing_time": 0.1,
        "success": true
      },
      {
        "agent": "web_attack_expert",
        "processing_time": 2.3,
        "success": true
      }
    ]
  },
  "processing_time": 2.5,
  "request_id": "req-123",
  "timestamp": "2025-01-10T12:00:00Z"
}
```

### 错误响应

```json
{
  "success": false,
  "error_message": "Validation failed: missing required field 'payload'",
  "processing_time": 0.01,
  "request_id": "req-456",
  "timestamp": "2025-01-10T12:00:00Z"
}
```

## 使用示例

### Python示例

```python
import requests
import json

class ThreatAnalyzerAPI:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.api_prefix = "/api/v1"

    def analyze_alert(self, alert_data, enable_rag=True):
        """分析单个告警"""
        url = f"{self.base_url}{self.api_prefix}/analyze/alert"

        payload = {
            "alert_data": alert_data,
            "enable_rag_enhancement": enable_rag
        }

        response = requests.post(url, json=payload)
        return response.json()

    def analyze_batch(self, alert_list, max_workers=4):
        """批量分析告警"""
        url = f"{self.base_url}{self.api_prefix}/analyze/batch"

        payload = {
            "alert_list": alert_list,
            "enable_rag_enhancement": False,  # 批量时关闭RAG以提高速度
            "max_workers": max_workers
        }

        response = requests.post(url, json=payload)
        return response.json()

    def get_system_status(self):
        """获取系统状态"""
        url = f"{self.base_url}{self.api_prefix}/system/status"
        response = requests.get(url)
        return response.json()

# 使用示例
if __name__ == "__main__":
    api = ThreatAnalyzerAPI()

    # 1. 检查系统状态
    status = api.get_system_status()
    print("System Status:", json.dumps(status, indent=2))

    # 2. 分析SQL注入
    sql_alert = {
        "attack_type": "SQL Injection",
        "payload": "SELECT * FROM users WHERE id='1' OR '1'='1",
        "source_ip": "192.168.1.100",
        "target_ip": "10.0.0.5"
    }

    result = api.analyze_alert(sql_alert)
    print("\nSQL Injection Analysis:", json.dumps(result, indent=2))

    # 3. 批量分析
    alerts = [
        {"attack_type": "XSS", "payload": "<script>alert(1)</script>", "source_ip": "192.168.1.101"},
        {"attack_type": "Command Injection", "payload": "; cat /etc/passwd", "source_ip": "192.168.1.102"}
    ]

    batch_results = api.analyze_batch(alerts)
    print("\nBatch Analysis Results:", len(batch_results), "alerts processed")
```

### curl示例

```bash
# 1. 系统状态
curl -X GET http://localhost:8000/api/v1/system/status

# 2. 分析单个告警
curl -X POST http://localhost:8000/api/v1/analyze/alert \
  -H "Content-Type: application/json" \
  -d '{
    "alert_data": {
      "attack_type": "SQL Injection",
      "payload": "SELECT * FROM users WHERE id=\"1\" OR \"1\"=\"1",
      "source_ip": "192.168.1.100",
      "target_ip": "10.0.0.5"
    },
    "enable_rag_enhancement": true
  }'

# 3. 批量分析
curl -X POST http://localhost:8000/api/v1/analyze/batch \
  -H "Content-Type: application/json" \
  -d '{
    "alert_list": [
      {
        "attack_type": "SQL Injection",
        "payload": "' OR '1'='1",
        "source_ip": "192.168.1.100"
      },
      {
        "attack_type": "XSS",
        "payload": "<script>alert(1)</script>",
        "source_ip": "192.168.1.101"
      }
    ],
    "max_workers": 2
  }'
```

### JavaScript示例

```javascript
class ThreatAnalyzerAPI {
    constructor(baseUrl = 'http://localhost:8000') {
        this.baseUrl = baseUrl;
        this.apiPrefix = '/api/v1';
    }

    async analyzeAlert(alertData, enableRag = true) {
        const url = `${this.baseUrl}${this.apiPrefix}/analyze/alert`;

        const payload = {
            alert_data: alertData,
            enable_rag_enhancement: enableRag
        };

        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        return await response.json();
    }

    async getSystemStatus() {
        const url = `${this.baseUrl}${this.apiPrefix}/system/status`;
        const response = await fetch(url);
        return await response.json();
    }
}

// 使用示例
const api = new ThreatAnalyzerAPI();

// 获取系统状态
api.getSystemStatus().then(status => {
    console.log('System Status:', status);
});

// 分析告警
const alert = {
    attack_type: 'SQL Injection',
    payload: "SELECT * FROM users WHERE id='1' OR '1'='1",
    source_ip: '192.168.1.100'
};

api.analyzeAlert(alert).then(result => {
    console.log('Analysis Result:', result);
});
```

## 错误处理

### 常见错误码

| 错误码 | 说明 | 解决方案 |
|--------|------|----------|
| 400 | 请求格式错误 | 检查JSON格式和必填字段 |
| 403 | 无权限访问 | 检查API密钥（如配置） |
| 500 | 服务器内部错误 | 查看服务器日志 |
| 503 | 服务不可用 | 系统未初始化或过载 |

### 错误处理示例

```python
import requests
from requests.exceptions import RequestException

def analyze_alert_with_retry(alert_data, max_retries=3):
    url = "http://localhost:8000/api/v1/analyze/alert"

    for attempt in range(max_retries):
        try:
            response = requests.post(
                url,
                json={"alert_data": alert_data},
                timeout=10  # 10秒超时
            )

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                # 限流，等待后重试
                time.sleep(2 ** attempt)
                continue
            else:
                response.raise_for_status()

        except RequestException as e:
            print(f"Attempt {attempt + 1} failed: {e}")
            if attempt == max_retries - 1:
                raise
            time.sleep(1)

    return None
```

## 性能优化

### 1. 批量处理
- 对于多个告警，使用批量接口而非单个请求
- 批量接口支持并行处理，提高效率

### 2. RAG策略
- 单个重要告警：启用RAG增强
- 批量处理：关闭RAG以提高速度
- 可以根据需要动态调整

### 3. 并发控制
- API支持并发请求
- 建议客户端限制并发数（如10个/秒）
- 使用连接池管理HTTP连接

### 4. 缓存策略
```python
# 示例：缓存相似攻击的分析结果
from functools import lru_cache
import hashlib

class CachedAnalyzer:
    def __init__(self, api_client):
        self.api = api_client

    def get_payload_hash(self, payload):
        return hashlib.md5(payload.encode()).hexdigest()

    @lru_cache(maxsize=1000)
    def analyze_similar_alert(self, alert_data):
        # 对载荷进行标准化
        normalized_payload = self.normalize_payload(alert_data['payload'])
        cache_key = self.get_payload_hash(normalized_payload)

        # 先检查缓存
        cached_result = self.get_from_cache(cache_key)
        if cached_result:
            return cached_result

        # 调用API
        result = self.api.analyze_alert(alert_data)
        self.save_to_cache(cache_key, result)
        return result
```

## 监控和日志

### 1. 性能监控
```python
# 获取系统性能指标
def check_performance():
    url = "http://localhost:8000/api/v1/metrics"
    response = requests.get(url)
    metrics = response.json()

    print(f"总请求数: {metrics['metrics']['total_requests']}")
    print(f"成功率: {metrics['metrics']['successful_requests'] / metrics['metrics']['total_requests'] * 100:.1f}%")
    print(f"平均响应时间: {metrics['metrics']['average_response_time']:.3f}s")
```

### 2. 健康检查
```python
def health_check():
    try:
        # 检查API可达性
        response = requests.get("http://localhost:8000/api/v1/system/status", timeout=5)

        if response.status_code == 200:
            data = response.json()
            if data['system_status']['is_initialized']:
                return "系统正常"
            else:
                return "系统未完全初始化"
        else:
            return f"API响应异常: {response.status_code}"
    except:
        return "API不可达"
```

## 故障排除

### 1. 服务无法启动
- 检查端口8000是否被占用
- 确保Python环境正确
- 查看启动日志

### 2. 分析失败
- 检查告警数据格式
- 确保必填字段存在
- 查看服务器错误日志

### 3. 响应慢
- 检查GPU状态
- 考虑关闭RAG增强
- 使用批量接口

### 4. 内存不足
- 减少并发请求数
- 调整批处理大小
- 重启服务释放内存

## 版本信息

- **API版本**: v1.0.0
- **当前更新**: 2025-01-12
- **兼容性**: Python 3.8+, 支持HTTP/1.1

## 支持

如有问题，请查看：
1. 系统日志：`logs/api_server.log`
2. GitHub Issues
3. 技术文档

---

*本文档持续更新中*