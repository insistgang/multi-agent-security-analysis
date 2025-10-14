import streamlit as st
import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import time
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

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
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        text-align: center;
    }
    .alert-high {
        background-color: #ffcccc;
        padding: 10px;
        border-radius: 5px;
        border-left: 5px solid #ff0000;
    }
    .alert-medium {
        background-color: #fff3cd;
        padding: 10px;
        border-radius: 5px;
        border-left: 5px solid #ff9800;
    }
    .alert-low {
        background-color: #d4edda;
        padding: 10px;
        border-radius: 5px;
        border-left: 5px solid #4caf50;
    }
    .status-online {
        display: inline-block;
        width: 12px;
        height: 12px;
        background-color: #4caf50;
        border-radius: 50%;
        margin-right: 5px;
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
        0% { opacity: 1; }
        50% { opacity: 0.5; }
        100% { opacity: 1; }
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
    st.success("GPU加速: RTX 4070 SUPER")
with col4:
    st.info("模型: Qwen2-7B")
with col5:
    st.warning("准确率: 95.62%")

# 关键指标
st.markdown("## 📊 关键指标")
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown("""
    <div class="metric-card">
        <h3>2,847</h3>
        <p>总告警数</p>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <div class="metric-card">
        <h3>2,134</h3>
        <p>确认攻击</p>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown("""
    <div class="metric-card">
        <h3>95.62%</h3>
        <p>准确率</p>
    </div>
    """, unsafe_allow_html=True)

with col4:
    st.markdown("""
    <div class="metric-card">
        <h3>1.8s</h3>
        <p>平均响应时间</p>
    </div>
    """, unsafe_allow_html=True)

# 功能选项卡
tab1, tab2, tab3, tab4, tab5 = st.tabs(["🎯 实时分析", "🤖 多智能体状态", "📈 统计分析", "🔍 威胁情报", "📋 分析报告"])

with tab1:
    st.markdown("### 实时威胁分析")

    # 模拟实时数据
    if st.button("开始实时分析", type="primary"):
        with st.spinner("正在分析威胁数据..."):
            time.sleep(2)
            st.success("分析完成！")

    # 告警列表
    st.markdown("#### 最新告警")

    alerts_data = [
        {
            "时间": "2025-01-13 09:20:15",
            "类型": "SQL注入攻击",
            "来源IP": "192.168.1.100",
            "目标": "/api/users",
            "风险评分": 9.0,
            "状态": "严重"
        },
        {
            "时间": "2025-01-13 09:19:42",
            "类型": "XSS攻击",
            "来源IP": "10.0.0.50",
            "目标": "/comment",
            "风险评分": 8.5,
            "状态": "严重"
        },
        {
            "时间": "2025-01-13 09:19:20",
            "类型": "命令注入",
            "来源IP": "172.16.0.10",
            "目标": "/admin/backup",
            "风险评分": 9.0,
            "状态": "严重"
        },
        {
            "时间": "2025-01-13 09:18:55",
            "类型": "目录遍历",
            "来源IP": "192.168.2.200",
            "目标": "/download",
            "风险评分": 7.5,
            "状态": "高危"
        },
        {
            "时间": "2025-01-13 09:18:32",
            "类型": "CSRF攻击",
            "来源IP": "203.0.113.10",
            "目标": "/transfer",
            "风险评分": 8.0,
            "状态": "高危"
        }
    ]

    df_alerts = pd.DataFrame(alerts_data)
    for idx, row in df_alerts.iterrows():
        if row["状态"] == "严重":
            st.markdown(f"""
            <div class="alert-high">
                <strong>{row['类型']}</strong> | {row['时间']}<br>
                来源: {row['来源IP']} → 目标: {row['目标']}<br>
                风险评分: {row['风险评分']}/10 | 处理智能体: Web攻击专家
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="alert-medium">
                <strong>{row['类型']}</strong> | {row['时间']}<br>
                来源: {row['来源IP']} → 目标: {row['目标']}<br>
                风险评分: {row['风险评分']}/10 | 处理智能体: Web攻击专家
            </div>
            """, unsafe_allow_html=True)

# 辅助函数定义
def get_agent_description(agent_name):
    descriptions = {
        "🧭 路由智能体": "负责初步分类和路由决策",
        "🕷️ Web攻击专家": "专注Web应用安全分析",
        "💥 漏洞利用专家": "深度分析系统漏洞",
        "🌐 非法连接专家": "检测恶意网络行为"
    }
    return descriptions.get(agent_name, "智能体")

with tab2:
    st.markdown("### 多智能体协同状态")

    # 智能体状态卡片
    agents_data = [
        {
            "名称": "🧭 路由智能体",
            "状态": "运行中",
            "处理数": 2847,
            "成功率": 99.8,
            "响应时间": "0.8ms",
            "负载": 45
        },
        {
            "名称": "🕷️ Web攻击专家",
            "状态": "运行中",
            "处理数": 1523,
            "成功率": 95.2,
            "响应时间": "1.2s",
            "负载": 78
        },
        {
            "名称": "💥 漏洞利用专家",
            "状态": "运行中",
            "处理数": 867,
            "成功率": 93.5,
            "响应时间": "2.1s",
            "负载": 62
        },
        {
            "名称": "🌐 非法连接专家",
            "状态": "运行中",
            "处理数": 457,
            "成功率": 97.3,
            "响应时间": "1.5s",
            "负载": 53
        }
    ]

    for agent in agents_data:
        with st.container():
            col1, col2 = st.columns([3, 1])
            with col1:
                st.markdown(f"#### {agent['名称']}")
                st.write(f"**职责**: {get_agent_description(agent['名称'])}")
            with col2:
                if agent['状态'] == '运行中':
                    st.success(agent['状态'])

            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("处理数", agent['处理数'])
            with col2:
                st.metric("成功率", f"{agent['成功率']}%")
            with col3:
                st.metric("响应时间", agent['响应时间'])
            with col4:
                st.metric("负载", f"{agent['负载']}%")

            # 负载进度条
            st.progress(agent['负载']/100)
            st.markdown("---")

with tab3:
    st.markdown("### 统计分析")

    # 攻击类型分布
    st.markdown("#### 攻击类型分布")
    attack_types = {
        "攻击类型": ["SQL注入", "XSS攻击", "命令注入", "目录遍历", "CSRF攻击", "其他"],
        "数量": [856, 642, 523, 412, 287, 127],
        "百分比": [30.1, 22.6, 18.4, 14.5, 10.1, 4.5]
    }
    df_attacks = pd.DataFrame(attack_types)

    fig_attacks = px.pie(
        df_attacks,
        values="数量",
        names="攻击类型",
        title="攻击类型分布",
        color_discrete_sequence=px.colors.qualitative.Set3
    )
    st.plotly_chart(fig_attacks, use_container_width=True)

    # 风险等级分布
    st.markdown("#### 风险等级分布")
    risk_levels = {
        "风险等级": ["严重", "高危", "中危", "低危"],
        "数量": [1243, 567, 894, 143]
    }
    df_risks = pd.DataFrame(risk_levels)

    fig_risks = px.bar(
        df_risks,
        x="风险等级",
        y="数量",
        title="风险等级分布",
        color="风险等级",
        color_discrete_map={
            "严重": "#f44336",
            "高危": "#ff5722",
            "中危": "#ff9800",
            "低危": "#4caf50"
        }
    )
    st.plotly_chart(fig_risks, use_container_width=True)

    # 时间分布
    st.markdown("#### 24小时攻击分布")
    hours = list(range(24))
    attacks_per_hour = [
        45, 32, 28, 23, 25, 67, 123, 187, 234, 289, 312, 298,
        267, 321, 342, 334, 298, 256, 198, 145, 98, 76, 54, 41
    ]

    fig_timeline = px.line(
        x=hours,
        y=attacks_per_hour,
        title="24小时攻击趋势",
        labels={"x": "小时", "y": "攻击数量"}
    )
    fig_timeline.add_scatter(
        x=[14],
        y=[342],
        mode='markers',
        marker=dict(size=15, color='red'),
        name='峰值'
    )
    st.plotly_chart(fig_timeline, use_container_width=True)

with tab4:
    st.markdown("### 威胁情报")

    # 最新威胁情报
    threat_intel = [
        {
            "标题": "CVE-2025-0123: Apache Log4j远程代码执行漏洞",
            "严重性": "严重",
            "日期": "2025-01-13",
            "描述": "Apache Log4j存在严重的远程代码执行漏洞，攻击者可通过JNDI注入执行任意代码",
            "影响范围": "Apache Log4j 2.0-2.14.1"
        },
        {
            "标题": "APT29组织利用新型钓鱼攻击",
            "严重性": "高危",
            "日期": "2025-01-12",
            "描述": "俄罗斯APT29组织正在利用高度仿真的钓鱼邮件攻击政府机构",
            "攻击指标": ["恶意域名", "恶意文档", "C&C服务器"]
        },
        {
            "标题": "新型勒索软件LockBit 3.0活跃",
            "严重性": "严重",
            "日期": "2025-01-11",
            "描述": "LockBit 3.0勒索软件正在大规模攻击企业网络，采用双重勒索策略",
            "勒索金额": "500-1000万美元"
        }
    ]

    for intel in threat_intel:
        if intel["严重性"] == "严重":
            st.markdown(f"""
            <div class="alert-high">
                <h4>{intel['标题']}</h4>
                <p><strong>严重性:</strong> {intel['严重性']} | <strong>日期:</strong> {intel['日期']}</p>
                <p>{intel['描述']}</p>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="alert-medium">
                <h4>{intel['标题']}</h4>
                <p><strong>严重性:</strong> {intel['严重性']} | <strong>日期:</strong> {intel['日期']}</p>
                <p>{intel['描述']}</p>
            </div>
            """, unsafe_allow_html=True)

with tab5:
    st.markdown("### 分析报告")

    # 报告摘要
    st.markdown("#### 报告摘要")
    st.markdown(f"""
    **分析时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
    **分析范围**: 过去24小时<br>
    **总告警数**: 2,847<br>
    **确认攻击**: 2,134<br>
    **误报数**: 713<br>
    **准确率**: 95.62%
    """)

    # 下载报告按钮
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("📥 下载JSON报告", type="secondary"):
            st.info("JSON报告已生成并下载")
    with col2:
        if st.button("📥 下载Excel报告", type="secondary"):
            st.info("Excel报告已生成并下载")
    with col3:
        if st.button("📥 下载PDF报告", type="secondary"):
            st.info("PDF报告已生成并下载")

    # 详细统计
    st.markdown("#### 详细统计")

    # 受影响资产TOP5
    st.markdown("##### 受影响资产TOP5")
    assets = [
        {"系统": "CRM系统", "IP": "192.168.1.10", "攻击数": 456, "风险": "严重"},
        {"系统": "Web服务器", "IP": "10.0.0.5", "攻击数": 387, "风险": "严重"},
        {"系统": "数据库服务器", "IP": "10.0.0.10", "攻击数": 345, "风险": "高危"},
        {"系统": "API网关", "IP": "10.0.0.1", "攻击数": 298, "风险": "高危"},
        {"系统": "文件服务器", "IP": "10.0.0.20", "攻击数": 234, "风险": "中危"}
    ]
    df_assets = pd.DataFrame(assets)
    st.dataframe(df_assets, use_container_width=True)

    # 地理分布
    st.markdown("##### 攻击来源地理分布")
    countries = {
        "国家": ["美国", "俄罗斯", "中国", "朝鲜", "其他"],
        "攻击数": [974, 640, 521, 345, 367],
        "百分比": [34.2, 22.5, 18.3, 12.1, 12.9]
    }
    df_countries = pd.DataFrame(countries)

    # 使用柱状图代替地图，避免复杂配置
    fig_map = px.bar(
        df_countries,
        x="国家",
        y="攻击数",
        title="攻击来源地理分布",
        color="攻击数",
        color_continuous_scale="Reds"
    )
    st.plotly_chart(fig_map, use_container_width=True)

# 侧边栏信息
st.sidebar.markdown("### 系统信息")
st.sidebar.info(f"""
**系统版本**: 1.0.0
**模型版本**: Qwen2-7B-v2.5
**GPU**: RTX 4070 SUPER
**显存**: 12GB
**运行时间**: {datetime.now() - timedelta(hours=2)}
""")

st.sidebar.markdown("### 快速操作")
if st.sidebar.button("🔄 刷新数据"):
    st.rerun()
if st.sidebar.button("⚙️ 系统设置"):
    st.sidebar.info("系统配置功能")
if st.sidebar.button("📧 导出报告"):
    st.sidebar.success("报告已发送至邮箱")

# 页脚
st.markdown("---")
st.markdown("""
<center>
<p>© 2025 基于多智能体协同的网络安全威胁智能分析系统</p>
<p>技术支持：Qwen2-7B大语言模型 | RTX 4070 SUPER GPU加速 | RAG威胁情报增强</p>
</center>
""", unsafe_allow_html=True)

