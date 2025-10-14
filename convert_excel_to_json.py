import pandas as pd
import json
import os
from datetime import datetime

print("开始转换Excel数据为JSON格式...")

# 读取攻击日志V2.xlsx
excel_path1 = 'data/攻击日志V2.xlsx'
attack_logs = []

if os.path.exists(excel_path1):
    print(f"正在读取: {excel_path1}")

    # 读取Excel文件（分批处理）
    df = pd.read_excel(excel_path1)
    total_rows = len(df)
    print(f"文件总行数: {total_rows:,}")

    # 只处理前10000条以避免内存问题
    max_rows = min(10000, total_rows)
    df = df.head(max_rows)

    total_processed = 0
    for _, row in df.iterrows():
            # 解析攻击类型
            alert_name = str(row.get('二级告警名称', ''))
            attack_type = "其他攻击"

            # 根据告警名称分类
            if any(keyword in alert_name for keyword in ['SQL', 'sql', '注入']):
                attack_type = "SQL注入"
            elif any(keyword in alert_name for keyword in ['XSS', '跨站', '脚本', 'script']):
                attack_type = "XSS跨站脚本"
            elif any(keyword in alert_name for keyword in ['命令', 'Command', '执行']):
                attack_type = "命令注入"
            elif any(keyword in alert_name for keyword in ['目录', 'Directory', '遍历', '路径']):
                attack_type = "目录遍历"
            elif any(keyword in alert_name for keyword in ['CSRF', '伪造']):
                attack_type = "CSRF攻击"
            elif any(keyword in alert_name for keyword in ['DNS', '隧道']):
                attack_type = "DNS隧道"
            elif any(keyword in alert_name for keyword in ['暴力', 'Brute', '爆破', '破解']):
                attack_type = "暴力破解"
            elif any(keyword in alert_name for keyword in ['DDoS', '拒绝服务', '分布式']):
                attack_type = "DDoS攻击"
            elif any(keyword in alert_name for keyword in ['扫描', 'Scan', '探测']):
                attack_type = "端口扫描"
            elif any(keyword in alert_name for keyword in ['Web', 'HTTP', '网站']):
                attack_type = "Web攻击"
            elif any(keyword in alert_name for keyword in ['恶意', '木马', '病毒']):
                attack_type = "恶意软件"
            elif any(keyword in alert_name for keyword in ['入侵', '渗透']):
                attack_type = "入侵尝试"

            # 确定威胁等级
            alert_level = str(row.get('告警等级', '中危'))
            if any(word in alert_level for word in ['严重', '紧急', 'critical']):
                threat_level = "critical"
            elif any(word in alert_level for word in ['高危', 'high']):
                threat_level = "high"
            elif any(word in alert_level for word in ['中危', 'medium']):
                threat_level = "medium"
            else:
                threat_level = "low"

            # 提取载荷
            payload = ""
            if pd.notna(row.get('攻击载荷')):
                payload = str(row['攻击载荷'])[:200]
            elif pd.notna(row.get('攻击')):
                payload = str(row['攻击'])[:200]

            # 确定攻击阶段
            attack_stage = "reconnaissance"
            stage = str(row.get('攻击阶段', ''))
            if "执行" in stage:
                attack_stage = "execution"
            elif "渗透" in stage:
                attack_stage = "exploitation"
            elif "安装" in stage:
                attack_stage = "installation"
            elif "命令" in stage:
                attack_stage = "command_and_control"

            attack_data = {
                "id": f"ATT-{len(attack_logs) + 1:08d}",
                "attack_type": attack_type,
                "payload": payload,
                "source_ip": str(row.get('源IP', 'Unknown')),
                "target_ip": str(row.get('目标IP', row.get('目的IP', 'Unknown'))),
                "timestamp": str(row.get('发生时间', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))),
                "threat_level": threat_level,
                "protocol": "HTTP",
                "description": str(row.get('一级告警名称', attack_type)),
                "attack_stage": attack_stage,
                "alert_name": alert_name,
                "data_source": "攻击日志V2.xlsx"
            }
            attack_logs.append(attack_data)
            total_processed += 1

        # 循环处理所有选定的行

    print(f"攻击日志处理完成，共 {len(attack_logs)} 条记录")

# 读取风险信息Excel
excel_path2 = 'data/风险信息_AqDzAqIh_20250319093813.xlsx'
risk_logs = []

if os.path.exists(excel_path2):
    print(f"正在读取: {excel_path2}")

    df2 = pd.read_excel(excel_path2)

    for _, row in df2.iterrows():
        # 解析攻击类型
        request = str(row.get('请求', ''))
        attack_type = "HTTP请求"

        if "SELECT" in request.upper() or "UNION" in request.upper():
            attack_type = "SQL注入"
        elif "SCRIPT" in request.upper():
            attack_type = "XSS跨站脚本"
        elif "../" in request or "ETC/PASSWD" in request:
            attack_type = "目录遍历"
        elif "CMD.EXE" in request.upper() or "CAT /" in request:
            attack_type = "命令注入"

        # 根据响应码确定威胁等级
        status_code = row.get('响应码', 200)
        if status_code in [401, 403]:
            threat_level = "high"
        elif status_code >= 500:
            threat_level = "critical"
        elif status_code == 404:
            threat_level = "low"
        else:
            threat_level = "medium"

        risk_data = {
            "id": f"RISK-{len(risk_logs) + 1:08d}",
            "attack_type": attack_type,
            "payload": request[:200],
            "source_ip": "Unknown",
            "target_ip": f"Status:{status_code}",
            "timestamp": str(row.get('时间', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))),
            "threat_level": threat_level,
            "protocol": str(row.get('协议类型', 'HTTP')),
            "description": str(row.get('事件类型', 'HTTP请求')),
            "attack_stage": "reconnaissance",
            "alert_name": str(row.get('事件类型', 'HTTP请求')),
            "response_code": int(status_code),
            "data_source": "风险信息.xlsx"
        }
        risk_logs.append(risk_data)

    print(f"风险信息处理完成，共 {len(risk_logs)} 条记录")

# 合并所有数据
all_data = attack_logs + risk_logs
print(f"\n总数据量: {len(all_data)} 条记录")

# 生成统计信息
stats = {
    "total_records": len(all_data),
    "data_sources": {
        "攻击日志V2.xlsx": len(attack_logs),
        "风险信息.xlsx": len(risk_logs)
    },
    "attack_types": {},
    "threat_levels": {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    },
    "generated_time": datetime.now().isoformat()
}

# 统计攻击类型
for attack in all_data:
    atype = attack['attack_type']
    stats['attack_types'][atype] = stats['attack_types'].get(atype, 0) + 1
    stats['threat_levels'][attack['threat_level']] += 1

# 保存数据
os.makedirs('data/processed', exist_ok=True)

# 保存完整数据
with open('data/processed/excel_attack_data.json', 'w', encoding='utf-8') as f:
    json.dump(all_data, f, ensure_ascii=False, indent=2)
    print(f"\n完整数据已保存到: data/processed/excel_attack_data.json")

# 保存统计信息
with open('data/processed/excel_data_stats.json', 'w', encoding='utf-8') as f:
    json.dump(stats, f, ensure_ascii=False, indent=2)
    print(f"统计信息已保存到: data/processed/excel_data_stats.json")

# 保存前1000条作为示例数据
with open('data/processed/excel_attack_data_sample.json', 'w', encoding='utf-8') as f:
    json.dump(all_data[:1000], f, ensure_ascii=False, indent=2)
    print(f"示例数据(1000条)已保存到: data/processed/excel_attack_data_sample.json")

# 打印统计信息
print("\n=== 数据统计 ===")
print(f"总记录数: {stats['total_records']:,}")
print(f"\n数据源:")
for source, count in stats['data_sources'].items():
    print(f"  - {source}: {count:,} 条")

print(f"\n攻击类型TOP10:")
sorted_attacks = sorted(stats['attack_types'].items(), key=lambda x: x[1], reverse=True)[:10]
for atype, count in sorted_attacks:
    print(f"  - {atype}: {count:,} 条")

print(f"\n威胁等级分布:")
level_cn = {'critical': '严重', 'high': '高危', 'medium': '中危', 'low': '低危'}
for level, count in stats['threat_levels'].items():
    print(f"  - {level_cn[level]}: {count:,} 条")

print("\n转换完成！")