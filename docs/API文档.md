# API 文档

## 概述

基于多智能体协同的网络安全威胁智能分析系统提供RESTful API接口，支持威胁分析、批量处理、系统监控等功能。

**基础URL**: `http://localhost:8000/api/v1`

**认证方式**: Bearer Token（可选）

**数据格式**: JSON

**字符编码**: UTF-8

## API 列表

### 1. 威胁分析接口

#### 1.1 分析单个告警

**接口地址**: `POST /api/v1/analyze/alert`

**功能描述**: 对单个告警进行智能分析，识别攻击类型、评估风险等级、提供处置建议。

**请求参数**:

| 参数名 | 类型 | 必填 | 说明 | 示例 |
|--------|------|------|------|------|
| timestamp | string | 否 | 告警时间戳 | "2025-01-10T12:00:00Z" |
| source_ip | string | 是 | 源IP地址 | "192.168.1.100" |
| target_ip | string | 是 | 目标IP地址 | "10.0.0.5" |
| attack_type | string | 推荐 | 攻击类型 | "SQL注入" |
| payload | string | 推荐 | 攻击载荷 | "SELECT * FROM users WHERE id='1' OR '1'='1'" |
| severity | string | 否 | 严重程度 | "High" |
| protocol | string | 否 | 协议类型 | "HTTP" |
| attack_stage | string | 否 | 攻击阶段 | "利用" |
| threat_level | string | 否 | 威胁等级 | "高危" |
| raw_log | string | 否 | 原始日志 | "[2025-01-10] SQL注入攻击..." |
| description | string | 否 | 描述信息 | "检测到SQL注入攻击" |

**请求示例**:
```json
{
  "timestamp": "2025-01-10T12:00:00Z",
  "source_ip": "192.168.1.100",
  "target_ip": "10.0.0.5",
  "attack_type": "SQL注入",
  "payload": "SELECT * FROM users WHERE id='1' OR '1'='1",
  "severity": "High",
  "protocol": "HTTP",
  "description": "检测到来自Web应用的SQL注入攻击尝试"
}
```

**响应示例**:
```json
{
  "success": true,
  "alert_id": "alert_001",
  "timestamp": "2025-01-10T12:00:00Z",
  "processing_time": 0.045,
  "routing_analysis": {
    "selected_route": "web_attack",
    "target_agent": "web_attack_expert",
    "confidence": 0.95,
    "analysis": "匹配关键词: sql, select; 匹配模式: web_attack_pattern_1"
  },
  "expert_analysis": {
    "attack_pattern": "SQL注入",
    "attack_technique": "UNION-based SQL注入",
    "attack_stage": "利用",
    "confidence": 0.92,
    "indicators": [
      "UNION SELECT语句",
      "OR '1'='1 逻辑炸弹"
    ]
  },
  "rag_enhanced": {
    "threat_intel_count": 3,
    "related_cves": ["CVE-2023-1234"],
    "mitigation_techniques": [
      "参数化查询",
      "输入验证"
    ]
  },
  "overall_assessment": {
    "risk_score": 8.5,
    "threat_level": "Critical",
    "attack_success_probability": 0.85,
    "potential_impact": "数据泄露、系统完全控制"
  },
  "recommended_actions": [
    {
      "priority": "Immediate",
      "action": "阻止源IP访问",
      "description": "立即阻止192.168.1.100的访问"
    },
    {
      "priority": "Short-term",
      "action": "部署Web应用防火墙规则",
      "description": "添加SQL注入检测规则"
    },
    {
      "priority": "Long-term",
      "action": "代码审查和重构",
      "description": "修复所有SQL注入漏洞"
    }
  ],
  "iocs": [
    {
      "type": "ip",
      "value": "192.168.1.100",
      "confidence": "high"
    },
    {
      "type": "pattern",
      "value": "UNION SELECT",
      "confidence": "high"
    }
  ],
  "metadata": {
    "model_version": "Qwen2-7B-v2.5",
    "processing_chain": ["router", "web_attack_expert", "rag_enhancer"],
    "cache_hit": false
  }
}
```

**错误响应**:
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "缺少必填字段: source_ip",
    "details": {
      "field": "source_ip",
      "reason": "required"
    }
  },
  "timestamp": "2025-01-10T12:00:00Z"
}
```

#### 1.2 批量分析告警

**接口地址**: `POST /api/v1/analyze/batch`

**功能描述**: 批量分析多个告警，支持并行处理。

**请求参数**:

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| alerts | array | 是 | 告警列表（最多100个） |
| batch_id | string | 否 | 批次ID（自动生成） |
| parallel | boolean | 否 | 是否并行处理（默认true） |
| callback_url | string | 否 | 完成后的回调URL |

**请求示例**:
```json
{
  "alerts": [
    {
      "source_ip": "192.168.1.100",
      "target_ip": "10.0.0.5",
      "attack_type": "SQL注入",
      "payload": "SELECT * FROM users WHERE id='1' OR '1'='1'"
    },
    {
      "source_ip": "192.168.1.101",
      "target_ip": "10.0.0.6",
      "attack_type": "XSS",
      "payload": "<script>alert('XSS')</script>"
    }
  ],
  "parallel": true
}
```

**响应示例**:
```json
{
  "success": true,
  "batch_id": "batch_20250110_001",
  "status": "completed",
  "total_count": 2,
  "processed_count": 2,
  "failed_count": 0,
  "processing_time": 0.123,
  "results": [
    {
      "index": 0,
      "alert_id": "alert_001",
      "success": true,
      "risk_score": 8.5,
      "threat_level": "Critical"
    },
    {
      "index": 1,
      "alert_id": "alert_002",
      "success": true,
      "risk_score": 6.5,
      "threat_level": "High"
    }
  ],
  "summary": {
    "attack_type_distribution": {
      "SQL注入": 1,
      "XSS": 1
    },
    "risk_level_distribution": {
      "Critical": 1,
      "High": 1
    },
    "average_risk_score": 7.5
  }
}
```

### 2. 文件上传分析接口

#### 2.1 上传文件分析

**接口地址**: `POST /api/v1/analyze/file`

**功能描述**: 上传文件（JSON/CSV/LOG/Excel）进行批量分析。

**请求参数**:

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| file | file | 是 | 要分析的文件 |
| file_type | string | 否 | 文件类型（自动检测） |
| batch_size | integer | 否 | 批处理大小（默认50） |
| has_header | boolean | 否 | CSV是否有表头（默认true） |
| delimiter | string | 否 | CSV分隔符（默认,） |

**请求示例**:
```bash
curl -X POST "http://localhost:8000/api/v1/analyze/file" \
  -F "file=@data/attacks.csv" \
  -F "batch_size=100"
```

**响应示例**:
```json
{
  "success": true,
  "file_id": "file_001",
  "filename": "attacks.csv",
  "file_size": 1048576,
  "total_records": 1000,
  "processing_status": "completed",
  "results": [
    {
      "row": 1,
      "success": true,
      "risk_score": 7.5
    }
  ],
  "statistics": {
    "total_processed": 1000,
    "success_count": 950,
    "error_count": 50,
    "processing_time": 12.5
  },
  "download_urls": {
    "json_report": "/api/v1/download/file_001.json",
    "excel_report": "/api/v1/download/file_001.xlsx"
  }
}
```

### 3. 威胁情报接口

#### 3.1 查询威胁情报

**接口地址**: `GET /api/v1/threat-intel/search`

**功能描述**: 根据关键词查询威胁情报。

**请求参数**:

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| query | string | 是 | 查询关键词 |
| type | string | 否 | 情报类型（cve/ioc/attack_pattern） |
| limit | integer | 否 | 返回数量（默认10） |

**请求示例**:
```
GET /api/v1/threat-intel/search?query=SQL注入&type=attack_pattern&limit=5
```

**响应示例**:
```json
{
  "success": true,
  "query": "SQL注入",
  "total": 25,
  "results": [
    {
      "id": "ti_001",
      "title": "SQL注入攻击模式",
      "type": "attack_pattern",
      "severity": "High",
      "description": "通过SQL注入攻击获取敏感数据",
      "indicators": ["UNION SELECT", "OR '1'='1'"],
      "mitigation": ["参数化查询", "输入验证"],
      "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
      "created_at": "2025-01-10T00:00:00Z",
      "updated_at": "2025-01-10T00:00:00Z"
    }
  ]
}
```

#### 3.2 获取最新威胁情报

**接口地址**: `GET /api/v1/threat-intel/recent`

**功能描述**: 获取最近的威胁情报。

**请求参数**:

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| days | integer | 否 | 最近天数（默认7） |
| severity | string | 否 | 严重程度过滤 |
| type | string | 否 | 类型过滤 |

**请求示例**:
```
GET /api/v1/threat-intel/recent?days=7&severity=High
```

### 4. 系统监控接口

#### 4.1 获取系统状态

**接口地址**: `GET /api/v1/system/status`

**功能描述**: 获取系统运行状态。

**响应示例**:
```json
{
  "success": true,
  "timestamp": "2025-01-10T12:00:00Z",
  "system": {
    "status": "healthy",
    "uptime": 86400,
    "version": "1.0.0"
  },
  "agents": {
    "router": {
      "status": "running",
      "load": 0.3,
      "requests_processed": 10000
    },
    "web_attack_expert": {
      "status": "running",
      "model_loaded": true,
      "queue_size": 5
    },
    "vulnerability_expert": {
      "status": "running",
      "model_loaded": true,
      "queue_size": 2
    },
    "illegal_connection_expert": {
      "status": "running",
      "model_loaded": true,
      "queue_size": 1
    }
  },
  "resources": {
    "cpu": {
      "usage": 45.2,
      "cores": 16
    },
    "memory": {
      "total": 34359738368,
      "used": 19327352832,
      "usage": 56.2
    },
    "gpu": {
      "available": true,
      "name": "NVIDIA RTX 4070 SUPER",
      "memory_total": 12884901888,
      "memory_used": 7516192768,
      "utilization": 85.3
    }
  },
  "models": {
    "qwen2_7b": {
      "status": "loaded",
      "device": "cuda",
      "quantization": "8bit"
    }
  }
}
```

#### 4.2 获取性能指标

**接口地址**: `GET /api/v1/metrics`

**功能描述**: 获取系统性能指标。

**请求参数**:

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| start_time | string | 否 | 开始时间 |
| end_time | string | 否 | 结束时间 |
| interval | string | 否 | 时间间隔（1m/5m/1h/1d） |

**响应示例**:
```json
{
  "success": true,
  "time_range": {
    "start": "2025-01-10T00:00:00Z",
    "end": "2025-01-10T12:00:00Z"
  },
  "metrics": {
    "requests": {
      "total": 5000,
      "success": 4950,
      "error": 50,
      "success_rate": 99.0
    },
    "performance": {
      "avg_response_time": 1.8,
      "p50_response_time": 1.5,
      "p95_response_time": 3.2,
      "p99_response_time": 5.0
    },
    "throughput": {
      "requests_per_second": 23.1,
      "alerts_per_minute": 138.6
    },
    "analysis": {
      "total_analyzed": 5000,
      "attack_types": {
        "SQL注入": 1500,
        "XSS": 1200,
        "Command Injection": 800,
        "Directory Traversal": 700,
        "CSRF": 500,
        "Others": 300
      },
      "risk_levels": {
        "Low": 1000,
        "Medium": 2000,
        "High": 1500,
        "Critical": 500
      }
    }
  }
}
```

### 5. 配置管理接口

#### 5.1 获取配置

**接口地址**: `GET /api/v1/config`

**功能描述**: 获取系统配置信息。

**响应示例**:
```json
{
  "success": true,
  "config": {
    "model": {
      "name": "Qwen2-7B-Instruct",
      "device": "cuda",
      "max_length": 2048,
      "temperature": 0.7
    },
    "agents": {
      "router_threshold": 0.5,
      "expert_timeout": 30,
      "max_concurrent": 32
    },
    "rag": {
      "top_k": 5,
      "similarity_threshold": 0.7,
      "knowledge_base_size": 10000
    }
  }
}
```

#### 5.2 更新配置

**接口地址**: `PUT /api/v1/config`

**功能描述**: 更新系统配置（需要管理员权限）。

**请求示例**:
```json
{
  "model": {
    "temperature": 0.8
  },
  "rag": {
    "top_k": 10
  }
}
```

### 6. 报告下载接口

#### 6.1 下载分析报告

**接口地址**: `GET /api/v1/download/{report_id}`

**功能描述**: 下载分析报告（支持JSON/XLSX/PDF格式）。

**请求参数**:

| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| format | string | 否 | 报告格式（json/excel/pdf） |

**请求示例**:
```
GET /api/v1/download/report_001?format=excel
```

### 7. WebSocket接口

#### 7.1 实时分析推送

**接口地址**: `ws://localhost:8000/ws/analysis`

**功能描述**: 通过WebSocket实时接收分析结果。

**连接示例**:
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/analysis');

ws.onopen = function() {
  console.log('WebSocket连接已建立');
};

ws.onmessage = function(event) {
  const data = JSON.parse(event.data);
  console.log('收到分析结果:', data);
};

// 发送分析请求
ws.send(JSON.stringify({
  type: 'analyze',
  data: {
    source_ip: '192.168.1.100',
    attack_type: 'SQL注入',
    payload: "SELECT * FROM users..."
  }
}));
```

## 错误代码说明

| 错误代码 | HTTP状态码 | 说明 |
|---------|-----------|------|
| SUCCESS | 200 | 请求成功 |
| VALIDATION_ERROR | 400 | 请求参数验证失败 |
| UNAUTHORIZED | 401 | 未授权访问 |
| FORBIDDEN | 403 | 禁止访问 |
| NOT_FOUND | 404 | 资源不存在 |
| METHOD_NOT_ALLOWED | 405 | 请求方法不允许 |
| RATE_LIMITED | 429 | 请求频率超限 |
| INTERNAL_ERROR | 500 | 内部服务器错误 |
| SERVICE_UNAVAILABLE | 503 | 服务不可用 |
| MODEL_ERROR | 503 | 模型加载失败 |
| GPU_ERROR | 503 | GPU资源不足 |

## 使用示例

### Python示例

```python
import requests
import json

# 分析单个告警
def analyze_alert(alert_data):
    url = "http://localhost:8000/api/v1/analyze/alert"
    headers = {"Content-Type": "application/json"}

    response = requests.post(url, headers=headers, json=alert_data)

    if response.status_code == 200:
        result = response.json()
        if result["success"]:
            print(f"风险评分: {result['overall_assessment']['risk_score']}")
            print(f"威胁等级: {result['overall_assessment']['threat_level']}")
        else:
            print(f"分析失败: {result['error']['message']}")
    else:
        print(f"请求失败: {response.status_code}")

# 使用示例
alert = {
    "source_ip": "192.168.1.100",
    "target_ip": "10.0.0.5",
    "attack_type": "SQL注入",
    "payload": "SELECT * FROM users WHERE id='1' OR '1'='1",
    "severity": "High"
}

analyze_alert(alert)
```

### JavaScript示例

```javascript
// 批量分析
async function batchAnalyze(alerts) {
    const response = await fetch('http://localhost:8000/api/v1/analyze/batch', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            alerts: alerts,
            parallel: true
        })
    });

    const result = await response.json();

    if (result.success) {
        console.log(`处理了 ${result.processed_count} 个告警`);
        console.log(`平均风险评分: ${result.summary.average_risk_score}`);
    }
}

// 使用示例
const alerts = [
    {
        source_ip: '192.168.1.100',
        attack_type: 'SQL注入',
        payload: "SELECT * FROM users..."
    },
    {
        source_ip: '192.168.1.101',
        attack_type: 'XSS',
        payload: "<script>alert('XSS')</script>"
    }
];

batchAnalyze(alerts);
```

## SDK支持

我们提供多种语言的SDK：

- [Python SDK](https://github.com/your-org/threat-analysis-python)
- [Java SDK](https://github.com/your-org/threat-analysis-java)
- [Go SDK](https://github.com/your-org/threat-analysis-go)
- [JavaScript SDK](https://github.com/your-org/threat-analysis-js)

## 限流说明

- **默认限制**: 每分钟100次请求
- **批量分析**: 每次最多100个告警
- **文件上传**: 单文件最大100MB
- **并发限制**: 每个IP最多32个并发连接

如需提高限额，请联系support@your-org.com

## 更新日志

### v1.0.0 (2025-01-10)
- 初始版本发布
- 支持基础威胁分析功能
- 提供RESTful API接口
- 支持批量处理和文件上传

### 即将发布
- v1.1.0: 支持GraphQL接口
- v1.2.0: 增加异步任务队列
- v2.0.0: 支持多租户架构

---

**技术支持**: api-support@your-org.com
**API文档版本**: v1.0.0
**最后更新**: 2025年1月10日