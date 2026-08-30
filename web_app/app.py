#!/usr/bin/env python3
"""
 - Web
StreamlitWeb
"""
import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import time
import json
import re
from datetime import datetime, timedelta
import asyncio
from typing import Dict, List, Any

# 
st.set_page_config(
    page_title="",
    page_icon=":shield:",
    layout="wide",
    initial_sidebar_state="expanded"
)

API_BASE_URL = "http://localhost:8000"

PAGE_OVERVIEW = "System Overview"
PAGE_SINGLE = "Single Alert Analysis"
PAGE_BATCH = "Batch Analysis"
PAGE_STATS = "Statistics"
PAGE_INTEL = "Threat Intelligence"
PAGE_SETTINGS = "Settings"


def _threat_bucket(threat_level: str) -> str:
    level = str(threat_level or "").strip().lower()
    if level in {"critical", "high", "高危", "严重", "高风险"}:
        return "high"
    if level in {"medium", "中危", "中风险"}:
        return "medium"
    if level in {"low", "低危", "低风险"}:
        return "low"
    return "unknown"

# CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 5px solid #1f77b4;
    }
    .success-box {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        border-radius: 0.25rem;
        padding: 1rem;
        margin: 1rem 0;
    }
    .warning-box {
        background-color: #fff3cd;
        border: 1px solid #ffeaa7;
        border-radius: 0.25rem;
        padding: 1rem;
        margin: 1rem 0;
    }
    .danger-box {
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        border-radius: 0.25rem;
        padding: 1rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

def setup_session_state():
    """"""
    if 'analysis_history' not in st.session_state:
        st.session_state.analysis_history = []
    if 'system_status' not in st.session_state:
        st.session_state.system_status = None
    if 'current_analysis' not in st.session_state:
        st.session_state.current_analysis = None

def call_api(endpoint: str, method: str = "GET", data: Dict = None) -> Dict:
    """API - Qwen2-7B"""
    try:
        url = f"{API_BASE_URL}{endpoint}"

        if method == "GET":
            response = requests.get(url, timeout=10)
        elif method == "POST":
            response = requests.post(url, json=data, timeout=300)  # 
        else:
            return {"success": False, "error": "Unsupported HTTP method"}

        if response.status_code == 200:
            result = response.json()
            # success
            if "success" not in result:
                result["success"] = True
            return result
        else:
            return {
                "success": False,
                "error": f"API call failed: {response.status_code}",
                "details": response.text
            }

    except requests.exceptions.Timeout:
        return {"success": False, "error": "Request timeout - Real model inference in progress (60-300 seconds)"}
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"Network request failed: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": f"Unknown error: {str(e)}"}

def render_header():
    """"""
    st.markdown('<h1 class="main-header"> </h1>',
                unsafe_allow_html=True)

    # 
    status_col1, status_col2, status_col3 = st.columns(3)

    with status_col1:
        system_status = call_api("/api/v1/system/status")
        if system_status.get("success"):
            model_loaded = system_status.get("model_loaded", False)
            if model_loaded:
                st.success("🟢 Qwen2-7B")
            else:
                st.warning("🟡 ")
        else:
            st.error(" ")

def render_sidebar():
    """"""
    st.sidebar.title("")

    page = st.sidebar.selectbox(
        "Page",
        [
            PAGE_OVERVIEW,
            PAGE_SINGLE,
            PAGE_BATCH,
            PAGE_STATS,
            PAGE_INTEL,
            PAGE_SETTINGS,
        ]
    )

    st.sidebar.markdown("---")

    # 
    st.sidebar.subheader("")

    # 
    metrics = call_api("/api/v1/metrics")
    if metrics.get("success"):
        metrics_data = metrics["metrics"]

        st.sidebar.metric(
            "",
            f"{metrics_data.get('total_requests', 0):,}"
        )

        success_rate = (
            metrics_data.get('successful_requests', 0) /
            max(metrics_data.get('total_requests', 1), 1) * 100
        )
        st.sidebar.metric("", f"{success_rate:.1f}%")

        avg_time = metrics_data.get('average_response_time', 0)
        st.sidebar.metric("", f"{avg_time:.2f}s")

    return page

def render_system_overview():
    """"""
    st.header(" ")

    # 
    system_status = call_api("/api/v1/system/status")

    if not system_status.get("success"):
        st.error("")
        return

    # 
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        agent_count = system_status["agent_status"]["agents_count"]
        st.metric("", agent_count)

    with col2:
        total_requests = system_status["performance_metrics"].get("total_requests", 0)
        st.metric("", f"{total_requests:,}")

    with col3:
        # APIsuccess_rate
        performance_metrics = system_status["performance_metrics"]
        success_rate = performance_metrics.get("success_rate", 0)
        # success_rate
        try:
            if isinstance(success_rate, str):
                # 
                import re
                numbers = re.findall(r'\d+\.?\d*', str(success_rate))
                if numbers:
                    success_rate_float = float(numbers[0])
                else:
                    success_rate_float = 0.0
            else:
                success_rate_float = float(success_rate)
            # API
            if success_rate_float < 1:
                success_rate_float = success_rate_float * 100
            st.metric("", f"{success_rate_float:.1f}%")
        except (ValueError, TypeError):
            st.metric("", "%")

    with col4:
        avg_time = system_status["performance_metrics"].get("average_response_time", 0.0)
        st.metric("", f"{avg_time:.2f}s")

    # 
    st.subheader("")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### ")
        agent_data = system_status["agent_status"]

        # 
        agent_info = []
        for agent_id, metrics in agent_data["individual_agent_metrics"].items():
            agent_info.append({
                "ID": agent_id,
                "": agent_id.split("_")[0] if "_" in agent_id else agent_id,
                "": metrics.get("total_requests", 0),
                "": f"{metrics.get('success_rate', 0):.1%}",
                "": f"{metrics.get('average_processing_time', 0):.2f}s"
            })

        if agent_info:
            df_agents = pd.DataFrame(agent_info)
            st.dataframe(df_agents, use_container_width=True)

    with col2:
        st.markdown("### RAG")
        rag_data = system_status["rag_status"]

        if rag_data and rag_data.get("status") == "initialized":
            st.success("🟢 RAG")

            threat_retriever_stats = rag_data.get("threat_retriever_stats", {})
            if threat_retriever_stats:
                st.metric("", threat_retriever_stats.get("total_intel_count", 0))
        else:
            st.warning("🟡 RAG")

    # 
    st.subheader("")

    recent_intel = call_api("/api/v1/threat-intel/recent?days=7")
    if recent_intel.get("success") and recent_intel["threat_intel"]:
        intel_df = pd.DataFrame(recent_intel["threat_intel"])

        # 
        display_columns = ["intel_id", "threat_type", "severity", "created_at", "days_ago"]
        if all(col in intel_df.columns for col in display_columns):
            intel_df_display = intel_df[display_columns]
            st.dataframe(intel_df_display, use_container_width=True)
    else:
        st.info("")

def render_single_analysis():
    """"""
    st.header(" ")

    # 
    st.subheader("")

    col1, col2 = st.columns([2, 1])

    with col1:
        # 
        attack_type = st.selectbox(
            "Attack type",
            ["SQL Injection", "XSS", "Web Attack", "Command Injection", "Directory Traversal", "Illegal Connection"]
        )

        attack_stage = st.selectbox(
            "Attack stage",
            ["reconnaissance", "weaponization", "delivery", "exploitation", "installation", "command_and_control", "actions"]
        )

        threat_level = st.selectbox(
            "Threat level",
            ["critical", "high", "medium", "low"]
        )

        protocol = st.selectbox(
            "Protocol",
            ["HTTP", "HTTPS", "DNS", "TCP", "UDP", "OTHER"]
        )

    with col2:
        # IP
        source_ip = st.text_input("Source IP", "192.168.1.100")
        target_ip = st.text_input("Target IP", "10.0.0.1")

        # 
        timestamp = st.text_input(
            "",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

    # 
    payload = st.text_area(
        "Payload",
        height=150,
        placeholder="Paste the alert payload or request snippet"
    )

    # 
    st.subheader("")
    enable_rag = st.checkbox("RAG", value=True)

    # 
    if st.button(" ", type="primary", use_container_width=True):
        if not payload:
            st.warning("")
            return

        # 
        alert_data = {
            "attack_type": attack_type,
            "attack_stage": attack_stage,
            "threat_level": threat_level,
            "protocol": protocol,
            "source_ip": source_ip,
            "target_ip": target_ip,
            "timestamp": timestamp,
            "payload": payload,
            "raw_log": f"[{timestamp}] {protocol} {source_ip} -> {target_ip} {attack_type}: {payload}"
        }

        # 
        with st.spinner("..."):
            # API
            result = call_api("/api/v1/analyze/alert", "POST", {"alert_data": alert_data})

            if result.get("success"):
                st.session_state.current_analysis = result
                st.session_state.analysis_history.append({
                    "timestamp": datetime.now(),
                    "alert_data": alert_data,
                    "result": result
                })
                st.success(" ")
            else:
                st.error(f" : {result.get('error_message')}")

    # 
    if st.session_state.current_analysis:
        render_analysis_result(st.session_state.current_analysis)

def render_analysis_result(analysis_result: Dict):
    """"""
    st.subheader(" ")

    def clean_circular_references(obj):
        """"""
        if isinstance(obj, dict):
            cleaned = {}
            for key, value in obj.items():
                # 
                if 'Circular Reference' in str(value):
                    cleaned[key] = None
                elif isinstance(value, (dict, list)):
                    cleaned[key] = clean_circular_references(value)
                elif hasattr(value, '__dict__'):
                    # 
                    cleaned[key] = str(value) if 'Circular Reference' not in str(value) else None
                else:
                    cleaned[key] = value
            return cleaned
        elif isinstance(obj, list):
            return [clean_circular_references(item) for item in obj]
        else:
            return obj

    # 
    cleaned_analysis = clean_circular_references(analysis_result) if analysis_result else {}

    # 
    print(f"DEBUG: analysis_result type = {type(analysis_result)}")
    print(f"DEBUG: cleaned_analysis type = {type(cleaned_analysis)}")
    print(f"DEBUG: cleaned_analysis value = {cleaned_analysis}")

    # result_dataNone
    if not cleaned_analysis:
        st.error("")
        return

    result_data = cleaned_analysis.get("result", {})
    if result_data is None:
        result_data = {
            "overall_assessment": {},
            "expert_analysis": {},
            "routing_analysis": {},
            "fusion_analysis": {},
            "rag_enhancement": {},
            "overall_assessment": {
                "threat_level": "",
                "recommended_actions": [""]
            }
        }
        st.warning("")

    # 
    overall_assessment = result_data.get("overall_assessment", {})
    if overall_assessment:
        col1, col2, col3 = st.columns(3)

        with col1:
            risk_score = overall_assessment.get("risk_score", 0)
            threat_level = overall_assessment.get("threat_level", "")

            # 
            try:
                # 
                expert_analysis = result_data.get("expert_analysis", {}) or {}
                expert_results = expert_analysis.get("expert_results", []) or []
                if expert_results:
                    expert_risk_score = expert_results[0].get("risk_score", 0)
                    if isinstance(expert_risk_score, (int, float)):
                        risk_score_float = float(expert_risk_score)
                    elif isinstance(expert_risk_score, str):
                        import re as regex_module
                        numbers = regex_module.findall(r'\d+\.?\d*', str(expert_risk_score))
                        risk_score_float = float(numbers[0]) if numbers else 0.0
                    else:
                        risk_score_float = 0.0
                else:
                    # 
                    bucket = _threat_bucket(threat_level)
                    if bucket == "high":
                        risk_score_float = 8.5
                    elif bucket == "medium":
                        risk_score_float = 5.0
                    elif bucket == "low":
                        risk_score_float = 2.0
                    else:
                        # risk_score
                        if isinstance(risk_score, str):
                            import re as regex_module2
                            numbers = regex_module2.findall(r'\d+\.?\d*', str(risk_score))
                            risk_score_float = float(numbers[0]) if numbers else 5.0
                        else:
                            risk_score_float = float(risk_score) if risk_score else 5.0

                st.metric("", f"{risk_score_float:.1f}/10")
            except (ValueError, TypeError):
                # 
                bucket = _threat_bucket(threat_level)
                if bucket == "high":
                    st.metric("Risk score", "8.5/10")
                elif bucket == "medium":
                    st.metric("Risk score", "5.0/10")
                else:
                    st.metric("Risk score", "2.0/10")

        with col2:
            threat_level = overall_assessment.get("threat_level", "")
            bucket = _threat_bucket(threat_level)
            if bucket == "high":
                st.error(f"Threat level: {threat_level or 'high'}")
            elif bucket == "medium":
                st.warning(f"Threat level: {threat_level or 'medium'}")
            else:
                st.success(f"Threat level: {threat_level or 'low'}")

        with col3:
            processing_time = analysis_result.get("processing_time", 0)
            st.metric("", f"{processing_time:.2f}s")

    # 
    routing_analysis = result_data.get("routing_analysis", {}) or {}
    if routing_analysis:
        st.subheader("🧭 ")

        # 
        with st.container():
            col1, col2, col3 = st.columns(3)

            routing_details = routing_analysis.get("routing_details", {})
            selected_route = routing_details.get("selected_route", "web_attack")
            target_agent = routing_details.get("target_agent", "web_attack_expert")
            routing_confidence = routing_analysis.get("routing_confidence", 0)

            with col1:
                st.markdown("###  ")
                route_emoji = {
                    "web_attack": "",
                    "vulnerability_attack": "",
                    "illegal_connection": "",
                    "unknown": ""
                }.get(selected_route, "")

                st.markdown(f"""
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            padding: 20px; border-radius: 10px; color: white; text-align: center;">
                    <div style="font-size: 2em;">{route_emoji}</div>
                    <div style="font-size: 1.2em; font-weight: bold; margin: 10px 0;">
                        {selected_route.replace('_', ' ').title()}
                    </div>
                </div>
                """, unsafe_allow_html=True)

            with col2:
                st.markdown("### 🤖 ")
                agent_emoji = {
                    "web_attack_expert": "",
                    "vulnerability_expert": "",
                    "illegal_connection_expert": ""
                }.get(target_agent, "🤖")

                st.markdown(f"""
                <div style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                            padding: 20px; border-radius: 10px; color: white; text-align: center;">
                    <div style="font-size: 2em;">{agent_emoji}</div>
                    <div style="font-size: 1.1em; font-weight: bold; margin: 10px 0;">
                        {target_agent.replace('_', ' ').title()}
                    </div>
                </div>
                """, unsafe_allow_html=True)

            with col3:
                st.markdown("###  ")
                # 
                try:
                    if isinstance(routing_confidence, str):
                        import re as regex_module
                        numbers = regex_module.findall(r'\d+\.?\d*', str(routing_confidence))
                        if numbers:
                            conf_float = float(numbers[0])
                            if conf_float > 1:
                                conf_float = conf_float / 100
                        else:
                            conf_float = 0.5
                    else:
                        conf_float = float(routing_confidence)
                except:
                    conf_float = 0.5

                # 
                if conf_float >= 0.8:
                    color = "#4CAF50"  # 
                elif conf_float >= 0.6:
                    color = "#FF9800"  # 
                else:
                    color = "#F44336"  # 

                st.markdown(f"""
                <div style="background: linear-gradient(135deg, {color} 0%, #2196F3 100%);
                            padding: 20px; border-radius: 10px; color: white; text-align: center;">
                    <div style="font-size: 2em;"></div>
                    <div style="font-size: 1.5em; font-weight: bold; margin: 10px 0;">
                        {conf_float:.1%}
                    </div>
                </div>
                """, unsafe_allow_html=True)

        # 
        st.markdown("###  ")

        # 
        route_scores = routing_details.get("route_scores", {})
        if route_scores:
            col1, col2 = st.columns([2, 1])

            with col1:
                st.markdown("**:**")
                # 
                valid_scores = {}
                for key, value in route_scores.items():
                    if isinstance(value, (int, float)) and not str(value).startswith('[Circular'):
                        valid_scores[key.replace('_', ' ').title()] = float(value)

                if valid_scores:
                    # 
                    scores_df = pd.DataFrame({
                        '': list(valid_scores.keys()),
                        '': list(valid_scores.values())
                    })

                    fig = px.bar(
                        scores_df,
                        x='',
                        y='',
                        orientation='h',
                        title="",
                        color='',
                        color_continuous_scale='viridis'
                    )
                    fig.update_layout(height=300, margin=dict(l=10, r=10, t=30, b=10))
                    st.plotly_chart(fig, use_container_width=True)

            with col2:
                st.markdown("**:**")
                analysis_text = routing_details.get("analysis", "")
                st.info(analysis_text)

                st.markdown("**:**")
                # 
                if analysis_text:
                    st.success(analysis_text)
                else:
                    st.info("No routing keywords extracted")

    # 
    expert_analysis = result_data.get("expert_analysis", {}) or {}
    if expert_analysis:
        st.subheader("‍ ")

        # 
        expert_results = expert_analysis.get("expert_results", [])
        if expert_results:
            # 
            first_expert = expert_results[0]

            # 
            with st.container():
                col1, col2, col3 = st.columns(3)

                # 
                agent_id = first_expert.get("agent_id", "unknown")
                agent_role = first_expert.get("agent_role", "")
                attack_type = first_expert.get("attack_type", "")
                confidence = first_expert.get("confidence", 0)
                risk_score = first_expert.get("risk_score", 0)
                processing_time = first_expert.get("processing_time", 0)

                # 
                if isinstance(agent_role, dict):
                    role_name = agent_role.get("_name_", "Web")
                else:
                    role_name = str(agent_role) if agent_role != "" else "Web"

                # 
                try:
                    conf_float = float(confidence)
                    if conf_float > 1:
                        conf_float = conf_float / 100
                except:
                    conf_float = 0.5

                # 
                try:
                    risk_float = float(risk_score)
                except:
                    risk_float = 5.0

                with col1:
                    # 
                    expert_emoji = {
                        "WEB_ATTACK_EXPERT": "",
                        "VULNERABILITY_EXPERT": "",
                        "ILLEGAL_CONNECTION_EXPERT": ""
                    }.get(role_name, "‍")

                    st.markdown(f"""
                    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                                padding: 20px; border-radius: 10px; color: white; text-align: center;">
                        <div style="font-size: 2em;">{expert_emoji}</div>
                        <div style="font-size: 1.1em; font-weight: bold; margin: 10px 0;">
                            {role_name.replace('_', ' ').title()}
                        </div>
                        <div style="font-size: 0.9em; opacity: 0.8;">
                            {agent_id}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                with col2:
                    # 
                    attack_emoji = {
                        "SQL": "",
                        "XSS": "",
                        "": "⌨",
                        "": "",
                        "": ""
                    }.get(attack_type, "")

                    st.markdown(f"""
                    <div style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                                padding: 20px; border-radius: 10px; color: white; text-align: center;">
                        <div style="font-size: 2em;">{attack_emoji}</div>
                        <div style="font-size: 1.1em; font-weight: bold; margin: 10px 0;">
                            {attack_type}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                with col3:
                    # 
                    # 
                    if risk_float >= 8:
                        color = "#F44336"  #  - 
                        risk_level = ""
                    elif risk_float >= 5:
                        color = "#FF9800"  #  - 
                        risk_level = ""
                    else:
                        color = "#4CAF50"  #  - 
                        risk_level = ""

                    st.markdown(f"""
                    <div style="background: linear-gradient(135deg, {color} 0%, #2196F3 100%);
                                padding: 20px; border-radius: 10px; color: white; text-align: center;">
                        <div style="font-size: 2em;"></div>
                        <div style="font-size: 1.5em; font-weight: bold; margin: 10px 0;">
                            {risk_float:.1f}/10
                        </div>
                        <div style="font-size: 1em;">
                            {risk_level}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

            # 
            st.markdown("###  ")

            col1, col2 = st.columns([1, 1])

            with col1:
                st.markdown("**:**")
                # 
                st.markdown(f"""
                <div style="background: #f0f2f6; padding: 10px; border-radius: 5px; margin: 10px 0;">
                    <div style="background: linear-gradient(90deg, #4CAF50 {conf_float*100}%, #e0e0e0 {conf_float*100}%);
                                height: 30px; border-radius: 15px; display: flex; align-items: center; justify-content: center;
                                color: {('white' if conf_float > 0.5 else '#666')}; font-weight: bold;">
                        {conf_float:.1%}
                    </div>
                </div>
                """, unsafe_allow_html=True)

                st.markdown("**:**")
                st.info(f"⏱ {processing_time:.3f} ")

            with col2:
                st.markdown("**:**")
                evidence = first_expert.get("evidence", [])
                if evidence:
                    for i, ev in enumerate(evidence[:5], 1):  # 5
                        st.markdown(f"{i}.  {ev}")
                else:
                    st.info("")

            # 
            analysis_text = first_expert.get("analysis", "")
            if analysis_text:
                st.markdown("**:**")
                st.success(analysis_text)

        else:
            st.info("")

    # RAG
    rag_enhancement = result_data.get("rag_enhancement", {}) or {}
    if rag_enhancement:
        st.subheader("🧠 RAG")

        # RAG
        rag_success = rag_enhancement.get("success", False)

        if rag_success:
            threat_intel_enhancement = rag_enhancement.get("threat_intelligence_enhancement", {})

            # 
            threat_context = threat_intel_enhancement.get("threat_context", "")
            if threat_context:
                st.markdown("**:**")
                st.info(threat_context)

            # 
            threat_intel = rag_enhancement.get("threat_intel", [])
            intel_analysis = rag_enhancement.get("intel_analysis", {})

            # 
            if threat_intel:
                st.markdown("** :**")
                for i, intel in enumerate(threat_intel[:3], 1):
                    with st.expander(f"  {i}", expanded=True):
                        col1, col2 = st.columns([3, 1])
                        with col1:
                            st.markdown(f"**:** {intel.get('threat_type', '')}")
                            st.markdown(f"**:** {intel.get('description', '')}")
                            st.markdown(f"**:** {intel.get('severity', '')}")
                        with col2:
                            similarity = intel.get('similarity_score', 0)
                            st.metric("", f"{similarity:.1%}")
                            st.metric("", intel.get('source', ''))
            else:
                # intel
                total_matches = intel_analysis.get("total_matches", 0)
                relevance_score = intel_analysis.get("relevance_score", 0)

                st.markdown("** :**")

                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("", total_matches)
                with col2:
                    # relevance_scorefloat
                    relevance_float = float(relevance_score) if isinstance(relevance_score, (int, float, str)) and str(relevance_score).replace('.', '').replace('-', '').isdigit() else 0.0
                    st.metric("", f"{relevance_float:.1%}")
                with col3:
                    st.metric("", "" if relevance_float < 0.7 else "")

                st.info("No matching threat-intelligence records for this alert.")

        else:
            st.info("No threat intelligence available for this alert.")

        # 
        enhanced_actions = threat_intel_enhancement.get("recommended_actions_enhanced", [])
        if enhanced_actions:
            st.markdown("**:**")
            for action in enhanced_actions:
                st.success(f"• {action}")

    # 
    st.subheader(" ")

    threat_level = overall_assessment.get("threat_level", "")
    actions = overall_assessment.get("recommended_actions") or []
    if actions:
        for i, action in enumerate(actions, 1):
            if _threat_bucket(threat_level) == "high":
                st.error(f"{i}. {action}")
            elif _threat_bucket(threat_level) == "medium":
                st.warning(f"{i}. {action}")
            else:
                st.info(f"{i}. {action}")
    else:
        st.info("No recommended actions returned.")

def render_batch_analysis():
    """"""
    st.header(" ")

    # 
    st.subheader("")
    uploaded_file = st.file_uploader(
        "Excel",
        type=['xlsx'],
        help="Excel"
    )

    if uploaded_file:
        try:
            # 
            df = pd.read_excel(uploaded_file)
            st.success(f"  {len(df)} ")

            # 
            st.subheader("")
            st.dataframe(df.head(), use_container_width=True)

            # 
            st.subheader("")
            col1, col2 = st.columns(2)

            with col1:
                enable_rag = st.checkbox("RAG", value=True)
                max_workers = st.slider("", 1, 10, 4)

            with col2:
                sample_size = st.number_input(
                    "",
                    min_value=1,
                    max_value=len(df),
                    value=min(10, len(df)),
                    help=""
                )

            # 
            if st.button(" ", type="primary"):
                # 
                sample_df = df.head(sample_size)
                alert_list = []

                def _cell(row, *names):
                    for name in names:
                        if name in row and pd.notna(row.get(name)):
                            return str(row.get(name))
                    return ""

                for _, row in sample_df.iterrows():
                    alert_data = {
                        "attack_type": _cell(row, "一级告警类型", "attack_type", "二级告警名称"),
                        "attack_stage": _cell(row, "攻击阶段", "attack_stage"),
                        "threat_level": _cell(row, "威胁等级", "threat_level", "告警等级"),
                        "protocol": _cell(row, "协议", "protocol"),
                        "source_ip": _cell(row, "源IP", "source_ip"),
                        "target_ip": _cell(row, "目标IP", "target_ip"),
                        "payload": _cell(row, "载荷", "攻击载荷", "payload"),
                    }
                    alert_list.append(alert_data)

                # 
                with st.spinner("..."):
                    batch_request = {
                        "alert_list": alert_list,
                        "enable_rag_enhancement": enable_rag,
                        "max_workers": max_workers
                    }

                    result = call_api("/api/v1/analyze/batch", "POST", batch_request)

                    if result.get("success", isinstance(result, list)):
                        st.success(" ")

                        # 
                        successful_analyses = sum(1 for r in result if r.get("success"))
                        total_analyses = len(result)

                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("", total_analyses)
                        with col2:
                            st.metric("", successful_analyses)
                        with col3:
                            st.metric("", f"{successful_analyses/total_analyses:.1%}")

                        # 
                        st.subheader("")

                        # result
                        result_list = result if isinstance(result, list) else []
                        for i, analysis in enumerate(result_list[:5], 1):  # 5
                            with st.expander(f" {i}"):
                                if analysis.get("success"):
                                    st.success(" ")
                                    result_data = analysis.get("result", {})
                                    if result_data:
                                        st.json(result_data.get("overall_assessment", {}))
                                    else:
                                        st.json({"error": "No result data available"})
                                else:
                                    st.error(f" : {analysis.get('error_message')}")
                    else:
                        st.error(f" : {result}")

        except Exception as e:
            st.error(f" : {str(e)}")

def render_statistics():
    """"""
    st.header(" ")

    # 
    metrics = call_api("/api/v1/metrics")

    if not metrics.get("success"):
        st.error("")
        return

    metrics_data = metrics["metrics"]

    # 
    st.subheader("")

    # 
    dates = pd.date_range(end=datetime.now(), periods=24, freq='H')
    response_times = [metrics_data.get('average_response_time', 2) + (i % 5) * 0.5 for i in range(24)]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=dates,
        y=response_times,
        mode='lines+markers',
        name='',
        line=dict(color='#1f77b4')
    ))

    fig.update_layout(
        title="24",
        xaxis_title="",
        yaxis_title=" ()"
    )

    st.plotly_chart(fig, use_container_width=True)

    # 
    st.subheader("")

    # 
    attack_types = ["SQL", "XSS", "Web", "", ""]
    attack_counts = [45, 23, 67, 34, 28]

    fig = px.pie(
        values=attack_counts,
        names=attack_types,
        title=""
    )

    st.plotly_chart(fig, use_container_width=True)

    # 
    st.subheader("")

    col1, col2 = st.columns(2)

    with col1:
        risk_levels = ["", "", ""]
        risk_counts = [23, 89, 45]

        fig = px.bar(
            x=risk_levels,
            y=risk_counts,
            title="",
            color=risk_levels,
            color_discrete_map={
                "": "red",
                "": "orange",
                "": "green"
            }
        )

        st.plotly_chart(fig, use_container_width=True)

    with col2:
        # 
        success_rate = (
            metrics_data.get('successful_requests', 0) /
            max(metrics_data.get('total_requests', 1), 1) * 100
        )

        fig = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = success_rate,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': ""},
            delta = {'reference': 95},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "#1f77b4"},
                'steps': [
                    {'range': [0, 50], 'color': "lightgray"},
                    {'range': [50, 80], 'color': "gray"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))

        st.plotly_chart(fig, use_container_width=True)

def render_threat_intel():
    """"""
    st.header("🧠 ")

    # 
    st.subheader("")

    col1, col2 = st.columns([3, 1])

    with col1:
        search_query = st.text_input(
            "",
            placeholder="..."
        )

    with col2:
        top_k = st.number_input("", min_value=1, max_value=20, value=5)

    if st.button(" "):
        if search_query:
            with st.spinner("..."):
                result = call_api(f"/api/v1/threat-intel/search?query={search_query}&top_k={top_k}")

                if result.get("success"):
                    threat_intel = result.get("threat_intel", [])

                    if threat_intel:
                        st.success(f" {len(threat_intel)} ")

                        for i, intel in enumerate(threat_intel, 1):
                            with st.expander(f"{intel.get('threat_type', '')} - : {intel.get('similarity_score', 0):.1%}"):
                                col1, col2 = st.columns([2, 1])

                                with col1:
                                    st.markdown(f"**:** {intel.get('threat_type', '')}")
                                    st.markdown(f"**:** {intel.get('description', '')}")
                                    st.markdown(f"**:** {intel.get('severity', '')}")
                                    st.markdown(f"**:** {intel.get('source', '')}")

                                with col2:
                                    st.metric("", f"{intel.get('similarity_score', 0):.1%}")
                                    st.metric("", intel.get('severity', ''))

                                # 
                                tags = intel.get('tags', [])
                                if tags:
                                    st.markdown("**:**")
                                    tag_str = " ".join([f"`{tag}`" for tag in tags[:5]])
                                    st.markdown(tag_str)
                    else:
                        st.warning("")
                else:
                    st.error(f": {result.get('error_message')}")
        else:
            st.warning("")

    # 
    st.subheader("")

    days = st.selectbox("", [7, 14, 30], index=0)

    if st.button("", key="refresh_recent"):
        result = call_api(f"/api/v1/threat-intel/recent?days={days}")

        if result.get("success"):
            recent_intel = result.get("threat_intel", [])

            if recent_intel:
                intel_df = pd.DataFrame(recent_intel)

                # 
                display_columns = ["threat_type", "severity", "source", "days_ago"]
                if all(col in intel_df.columns for col in display_columns):
                    intel_df_display = intel_df[display_columns]
                    intel_df_display.columns = ["", "", "", ""]
                    st.dataframe(intel_df_display, use_container_width=True)

                # 
                if len(recent_intel) > 0:
                    threat_counts = intel_df['threat_type'].value_counts()

                    fig = px.bar(
                        x=threat_counts.index,
                        y=threat_counts.values,
                        title=f"{days}"
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info(f"{days}")
        else:
            st.error(f": {result.get('error_message')}")

def render_system_settings():
    """"""
    st.header(" ")

    # 
    st.subheader("")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**API**")
        api_url = st.text_input("API", API_BASE_URL)

        st.markdown("****")
        default_enable_rag = st.checkbox("RAG", value=True)
        default_batch_size = st.number_input("", min_value=1, max_value=100, value=10)

    with col2:
        st.markdown("****")
        max_history_items = st.number_input("", min_value=10, max_value=1000, value=100)
        auto_refresh_interval = st.slider("()", 5, 60, 30)

    # 
    st.subheader("")

    system_status = call_api("/api/v1/system/status")

    if system_status.get("success"):
        status_data = system_status["system_status"]

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("", status_data.get("agents_count", 0))

        with col2:
            st.metric("", status_data.get("experts_count", 0))

        with col3:
            uptime = status_data.get("uptime", 0)
            st.metric("", f"{uptime/3600:.1f}")

    # 
    st.subheader("")

    col1, col2 = st.columns(2)

    with col1:
        if st.button(" ", type="secondary"):
            st.session_state.analysis_history = []
            st.success(" ")

    with col2:
        if st.button(" ", type="secondary"):
            st.session_state.current_analysis = None
            st.session_state.system_status = None
            st.success(" ")

def main():
    """"""
    # 
    setup_session_state()

    # 
    render_header()

    # 
    page = render_sidebar()

    # 
    if page == PAGE_OVERVIEW:
        render_system_overview()
    elif page == PAGE_SINGLE:
        render_single_analysis()
    elif page == PAGE_BATCH:
        render_batch_analysis()
    elif page == PAGE_STATS:
        render_statistics()
    elif page == PAGE_INTEL:
        render_threat_intel()
    elif page == PAGE_SETTINGS:
        render_system_settings()

    # 
    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: #666; padding: 20px;'>"
        "© 2025  - "
        "</div>",
        unsafe_allow_html=True
    )

if __name__ == "__main__":
    main()