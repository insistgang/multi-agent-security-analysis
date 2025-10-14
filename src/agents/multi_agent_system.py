#!/usr/bin/env python3
"""



"""
import time
import asyncio
from typing import Dict, List, Any, Optional, Type
from concurrent.futures import ThreadPoolExecutor
from .base_agent import BaseAgent, AgentRole, AgentResult
from .router_agent import RouterAgent
from .expert_agent import ExpertAgent
from .intelligent_router import EnhancedRouterAgent
from src.analysis.result_fusion import ResultFusionEngine, ExpertResult, FusionResult
# from ..utils.error_handler import (
#     with_circuit_breaker, with_retry, with_fallback,
#     global_error_handler, CircuitBreakerConfig
# )
from loguru import logger

class MultiAgentSystem:
    """"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.agents: Dict[str, BaseAgent] = {}
        self.router: Optional[RouterAgent] = None
        self.enhanced_router: Optional[EnhancedRouterAgent] = None
        self.experts: Dict[AgentRole, ExpertAgent] = {}
        self.result_fusion_engine: Optional[ResultFusionEngine] = None
        self.is_initialized = False
        self.performance_metrics = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'average_response_time': 0.0,
            'agent_utilization': {},
            'routing_accuracy': 0.0,
            'fusion_effectiveness': 0.0
        }

    def initialize(self) -> bool:
        """"""
        try:
            logger.info("...")

            # 
            self.router = RouterAgent("main_router", self.config.get('router', {}))
            if not self.router.initialize():
                logger.error("")
                return False
            self.agents[self.router.agent_id] = self.router

            # 
            # self.enhanced_router = EnhancedRouterAgent(self.config.get('enhanced_router', {}))
            # if not self.enhanced_router.initialize():
            #     logger.warning("")
            # else:
            #     self.agents[self.enhanced_router.agent_id] = self.enhanced_router
            #     logger.info("")
            self.enhanced_router = None

            # 
            # self.result_fusion_engine = ResultFusionEngine(self.config.get('result_fusion', {}))
            # logger.info("")
            self.result_fusion_engine = None

            # 
            expert_configs = {
                AgentRole.WEB_ATTACK_EXPERT: self.config.get('web_expert', {}),
                AgentRole.VULNERABILITY_EXPERT: self.config.get('vulnerability_expert', {}),
                AgentRole.ILLEGAL_CONNECTION_EXPERT: self.config.get('connection_expert', {})
            }

            for role, config in expert_configs.items():
                expert = ExpertAgent(f"{role.value}_001", role, config)
                if expert.initialize():
                    self.experts[role] = expert
                    self.agents[expert.agent_id] = expert
                    logger.info(f" {role.value} ")
                else:
                    logger.error(f" {role.value} ")

            self.is_initialized = True
            logger.info("")

            return True

        except Exception as e:
            logger.error(f": {e}")
            return False

    async def analyze_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """- →→"""
        start_time = time.time()

        try:
            if not self.is_initialized:
                raise RuntimeError("")

            # 
            if self.enhanced_router:
                # 
                routing_result = await self._safe_intelligent_routing(alert_data)
                router_result = AgentResult(
                    agent_id=self.enhanced_router.agent_id,
                    agent_role="enhanced_router",
                    success=True,
                    confidence=routing_result.get('overall_confidence', 0.0),
                    result=routing_result,
                    processing_time=0.1
                )
            else:
                # 
                router_result = await self._safe_basic_routing(alert_data)

            if not router_result.success:
                raise RuntimeError(f": {router_result.error_message}")

            # 
            expert_results = await self._safe_parallel_expert_analysis(alert_data, router_result)

            if not expert_results:
                logger.warning("")
                return self._build_final_result(alert_data, router_result, None)

            # 
            fusion_result = await self._safe_result_fusion(expert_results, alert_data)

            # 
            final_result = self._build_enhanced_final_result(
                alert_data,
                router_result,
                expert_results,
                fusion_result
            )

            # 
            processing_time = time.time() - start_time
            self._update_performance_metrics(True, processing_time)
            await self._safe_update_adaptive_learning(router_result, expert_results, fusion_result)

            logger.info(f": {processing_time:.2f}"
                       f": {router_result.confidence:.3f}, "
                       f": {fusion_result.fusion_confidence:.3f}")

            return final_result

        except Exception as e:
            processing_time = time.time() - start_time
            self._update_performance_metrics(False, processing_time)
            logger.error(f": {e}")

            return {
                'success': False,
                'error_message': str(e),
                'processing_time': processing_time,
                'alert_data': alert_data,
                'fallback_used': False
            }

    def analyze_alert_sync(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """"""
        return asyncio.run(self.analyze_alert(alert_data))

    def batch_analyze(self, alert_list: List[Dict[str, Any]],
                     max_workers: int = 4) -> List[Dict[str, Any]]:
        """"""
        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_alert = {
                executor.submit(self.analyze_alert_sync, alert): alert
                for alert in alert_list
            }

            for future in future_to_alert:
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    alert = future_to_alert[future]
                    error_result = {
                        'success': False,
                        'error_message': str(e),
                        'alert_data': alert
                    }
                    results.append(error_result)

        return results

    async def _parallel_expert_analysis(self, alert_data: Dict[str, Any],
                                    router_result: AgentResult) -> List[AgentResult]:
        """"""
        import asyncio

        # 
        selected_experts = self._select_experts_by_routing(router_result)

        if not selected_experts:
            # 
            selected_experts = list(self.experts.values())

        # 
        expert_tasks = []
        for expert in selected_experts:
            task = asyncio.create_task(
                self._run_expert_analysis_async(expert, alert_data)
            )
            expert_tasks.append(task)

        # 
        expert_results = []
        for task in asyncio.as_completed(expert_tasks):
            try:
                result = await task
                if result.success:
                    expert_results.append(result)
                    logger.debug(f" {result.agent_id} : {result.confidence:.3f}")
                else:
                    logger.warning(f" {result.agent_id} : {result.error_message}")
            except Exception as e:
                logger.error(f": {e}")

        return expert_results

    async def _run_expert_analysis_async(self, expert: ExpertAgent,
                                       alert_data: Dict[str, Any]) -> AgentResult:
        """"""
        # 
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, expert.process, alert_data)

    def _select_experts_by_routing(self, router_result: AgentResult) -> List[ExpertAgent]:
        """"""
        selected_experts = []

        if self.enhanced_router:
            # 
            routing_result = router_result.result
            route_confidences = routing_result.get('route_confidences', [])

            # 2
            if route_confidences:
                # 
                sorted_routes = sorted(route_confidences,
                                     key=lambda x: x['confidence'], reverse=True)

                # 20.2
                top_confidence = sorted_routes[0]['confidence']
                for route_info in sorted_routes[:2]:
                    if route_info['confidence'] >= top_confidence - 0.2:
                        expert = self._get_expert_agent(route_info['route'])
                        if expert and expert not in selected_experts:
                            selected_experts.append(expert)

        else:
            # 
            selected_route = router_result.result.get('selected_route')
            expert = self._get_expert_agent(selected_route)
            if expert:
                selected_experts.append(expert)

        return selected_experts

    def _fuse_expert_results(self, expert_results: List[AgentResult],
                           alert_data: Dict[str, Any]) -> FusionResult:
        """"""
        if not self.result_fusion_engine:
            # 
            if expert_results:
                result = expert_results[0]
                return FusionResult(
                    final_attack_type=result.result.get('attack_type', 'unknown'),
                    final_confidence=result.confidence,
                    final_risk_score=result.result.get('risk_score', 5.0),
                    consensus_level=1.0 if len(expert_results) == 1 else 0.5,
                    conflict_resolution="single_expert",
                    contributing_experts=[result.agent_id],
                    fusion_confidence=result.confidence,
                    reasoning_summary="",
                    weighted_analysis=result.result
                )
            else:
                return FusionResult(
                    final_attack_type="unknown",
                    final_confidence=0.0,
                    final_risk_score=0.0,
                    consensus_level=0.0,
                    conflict_resolution="no_experts",
                    contributing_experts=[],
                    fusion_confidence=0.0,
                    reasoning_summary="",
                    weighted_analysis={}
                )

        # AgentResultExpertResult
        expert_result_objects = []
        for agent_result in expert_results:
            expert_result = ExpertResult(
                expert_id=agent_result.agent_id,
                expert_role=agent_result.agent_role,
                attack_type=agent_result.result.get('attack_type', 'unknown'),
                confidence=agent_result.confidence,
                risk_score=agent_result.result.get('risk_score', 5.0),
                processing_time=agent_result.processing_time,
                analysis_details=agent_result.result.get('analysis', ''),
                evidence=agent_result.result.get('evidence', []),
                timestamp=time.time()
            )
            expert_result_objects.append(expert_result)

        # 
        return self.result_fusion_engine.fuse_results(expert_result_objects)

    async def _safe_intelligent_routing(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """"""
        try:
            return await asyncio.get_event_loop().run_in_executor(
                None, self.enhanced_router.route_alert, alert_data
            )
        except Exception as e:
            logger.error(f": {e}")
            # 
            return {
                'route_confidences': [
                    {'route': 'web_attack', 'confidence': 0.5}
                ],
                'overall_confidence': 0.5,
                'routing_details': {'error': str(e)}
            }

    async def _safe_basic_routing(self, alert_data: Dict[str, Any]) -> AgentResult:
        """"""
        try:
            return await asyncio.get_event_loop().run_in_executor(
                None, self.router.process, alert_data
            )
        except Exception as e:
            logger.error(f": {e}")
            return AgentResult(
                agent_id="fallback_router",
                agent_role="router",
                success=False,
                confidence=0.0,
                result={'error': str(e)},
                processing_time=0.1
            )

    async def _safe_parallel_expert_analysis(self, alert_data: Dict[str, Any],
                                           router_result: AgentResult) -> List[AgentResult]:
        """"""
        try:
            return await self._parallel_expert_analysis(alert_data, router_result)
        except Exception as e:
            logger.error(f": {e}")
            # 
            return []

    async def _safe_result_fusion(self, expert_results: List[AgentResult],
                                alert_data: Dict[str, Any]) -> FusionResult:
        """"""
        try:
            return self._fuse_expert_results(expert_results, alert_data)
        except Exception as e:
            logger.error(f": {e}")
            # 
            if expert_results:
                result = expert_results[0]
                return FusionResult(
                    final_attack_type=result.result.get('attack_type', 'unknown'),
                    final_confidence=result.confidence * 0.5,  # 
                    final_risk_score=result.result.get('risk_score', 5.0),
                    consensus_level=0.5,
                    conflict_resolution="fallback",
                    contributing_experts=[result.agent_id],
                    fusion_confidence=result.confidence * 0.5,
                    reasoning_summary=f": {str(e)}",
                    weighted_analysis=result.result
                )
            else:
                return FusionResult(
                    final_attack_type="unknown",
                    final_confidence=0.0,
                    final_risk_score=5.0,
                    consensus_level=0.0,
                    conflict_resolution="no_results",
                    contributing_experts=[],
                    fusion_confidence=0.0,
                    reasoning_summary="",
                    weighted_analysis={}
                )

    async def _safe_update_adaptive_learning(self, router_result: AgentResult,
                                           expert_results: List[AgentResult],
                                           fusion_result: FusionResult):
        """"""
        try:
            await asyncio.get_event_loop().run_in_executor(
                None, self._update_adaptive_learning, router_result, expert_results, fusion_result
            )
        except Exception as e:
            logger.error(f": {e}")

    def _update_adaptive_learning(self, router_result: AgentResult,
                                expert_results: List[AgentResult],
                                fusion_result: FusionResult):
        """"""
        try:
            # 
            if self.enhanced_router:
                self.enhanced_router.update_routing_accuracy(router_result, fusion_result)

            # 
            if self.result_fusion_engine and expert_results:
                expert_result_objects = []
                for agent_result in expert_results:
                    expert_result = ExpertResult(
                        expert_id=agent_result.agent_id,
                        expert_role=agent_result.agent_role,
                        attack_type=agent_result.result.get('attack_type', 'unknown'),
                        confidence=agent_result.confidence,
                        risk_score=agent_result.result.get('risk_score', 5.0),
                        processing_time=agent_result.processing_time,
                        analysis_details=agent_result.result.get('analysis', ''),
                        evidence=agent_result.result.get('evidence', []),
                        timestamp=time.time()
                    )
                    expert_result_objects.append(expert_result)

                # ""
                actual_outcome = fusion_result.final_attack_type
                self.result_fusion_engine.update_feedback(
                    expert_result_objects,
                    fusion_result,
                    actual_outcome,
                    fusion_result.final_confidence
                )

        except Exception as e:
            logger.error(f": {e}")

    def _build_fallback_result(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """"""
        logger.warning("")

        # 
        payload = alert_data.get('payload', '').lower()
        raw_log = alert_data.get('raw_log', '').lower()

        risk_score = 5.0  # 
        attack_type = 'unknown'
        threat_level = ''

        if any(keyword in payload or keyword in raw_log for keyword in [
            'union select', 'or 1=1', 'drop table', 'insert into'
        ]):
            attack_type = 'sql_injection'
            risk_score = 8.0
            threat_level = ''
        elif any(keyword in payload or keyword in raw_log for keyword in [
            '<script', 'javascript:', 'onerror=', 'onload='
        ]):
            attack_type = 'xss'
            risk_score = 7.0
            threat_level = ''
        elif any(keyword in payload or keyword in raw_log for keyword in [
            'wget', 'curl', 'nc ', 'netcat', 'powershell'
        ]):
            attack_type = 'command_injection'
            risk_score = 9.0
            threat_level = ''

        return {
            'success': True,
            'alert_id': alert_data.get('alert_id', 'unknown'),
            'timestamp': time.time(),
            'routing_analysis': {
                'router_id': 'fallback_router',
                'selected_routes': [attack_type],
                'routing_confidence': 0.5,
                'routing_details': {'mode': 'fallback'}
            },
            'expert_analysis': {
                'total_experts': 0,
                'successful_experts': 0,
                'expert_results': []
            },
            'fusion_analysis': {
                'final_attack_type': attack_type,
                'final_confidence': 0.5,
                'final_risk_score': risk_score,
                'consensus_level': 0.5,
                'conflict_resolution': 'fallback',
                'contributing_experts': [],
                'reasoning_summary': ''
            },
            'overall_assessment': {
                'risk_score': risk_score,
                'threat_level': threat_level,
                'recommended_actions': self._generate_fallback_actions(attack_type, risk_score)
            },
            'processing_chain': [
                {
                    'stage': 'fallback_mode',
                    'agent': 'fallback_system',
                    'processing_time': 0.1,
                    'success': True,
                    'confidence': 0.5
                }
            ],
            'fallback_used': True
        }

    def _generate_fallback_actions(self, attack_type: str, risk_score: float) -> List[str]:
        """"""
        if risk_score >= 8.0:
            return [
                'IP',
                '',
                ''
            ]
        elif risk_score >= 6.0:
            return [
                '',
                '',
                ''
            ]
        else:
            return [
                '',
                ''
            ]

    def _build_enhanced_final_result(self, alert_data: Dict[str, Any],
                                   router_result: AgentResult,
                                   expert_results: List[AgentResult],
                                   fusion_result: FusionResult) -> Dict[str, Any]:
        """"""
        final_result = {
            'success': True,
            'alert_id': alert_data.get('alert_id', 'unknown'),
            'timestamp': time.time(),
            'routing_analysis': {
                'router_id': router_result.agent_id,
                'selected_routes': [
                    route_info.get('route', 'unknown')
                    for route_info in router_result.result.get('route_confidences', [])
                ],
                'routing_confidence': router_result.confidence,
                'routing_details': router_result.result
            },
            'expert_analysis': {
                'total_experts': len(expert_results),
                'successful_experts': len([r for r in expert_results if r.success]),
                'expert_results': []
            },
            'fusion_analysis': {
                'final_attack_type': fusion_result.final_attack_type,
                'final_confidence': fusion_result.final_confidence,
                'final_risk_score': fusion_result.final_risk_score,
                'consensus_level': fusion_result.consensus_level,
                'conflict_resolution': fusion_result.conflict_resolution,
                'contributing_experts': fusion_result.contributing_experts,
                'reasoning_summary': fusion_result.reasoning_summary
            },
            'overall_assessment': {
                'risk_score': fusion_result.final_risk_score,
                'threat_level': self._determine_threat_level(fusion_result.final_risk_score),
                'recommended_actions': self._generate_recommended_actions(fusion_result)
            },
            'processing_chain': []
        }

        # 
        for expert_result in expert_results:
            if expert_result.success:
                final_result['expert_analysis']['expert_results'].append({
                    'agent_id': expert_result.agent_id,
                    'agent_role': expert_result.agent_role,
                    'confidence': expert_result.confidence,
                    'risk_score': expert_result.result.get('risk_score', 5.0),
                    'attack_type': expert_result.result.get('attack_type', 'unknown'),
                    'processing_time': expert_result.processing_time,
                    'analysis': expert_result.result.get('analysis', ''),
                    'evidence': expert_result.result.get('evidence', [])
                })

        # 
        final_result['processing_chain'].extend([
            {
                'stage': 'intelligent_routing',
                'agent': router_result.agent_id,
                'processing_time': router_result.processing_time,
                'success': router_result.success,
                'confidence': router_result.confidence
            }
        ])

        for i, expert_result in enumerate(expert_results):
            final_result['processing_chain'].append({
                'stage': f'expert_analysis_{i+1}',
                'agent': expert_result.agent_id,
                'processing_time': expert_result.processing_time,
                'success': expert_result.success,
                'confidence': expert_result.confidence if expert_result.success else 0.0
            })

        final_result['processing_chain'].append({
            'stage': 'result_fusion',
            'agent': 'fusion_engine',
            'processing_time': 0.05,  # 
            'success': True,
            'confidence': fusion_result.fusion_confidence
        })

        return final_result

    def _determine_threat_level(self, risk_score: float) -> str:
        """"""
        if risk_score >= 8.0:
            return ''
        elif risk_score >= 6.0:
            return ''
        elif risk_score >= 4.0:
            return ''
        else:
            return ''

    def _generate_recommended_actions(self, fusion_result: FusionResult) -> List[str]:
        """"""
        risk_score = fusion_result.final_risk_score
        confidence = fusion_result.final_confidence
        attack_type = fusion_result.final_attack_type

        actions = []

        # 
        if risk_score >= 8.0 and confidence > 0.7:
            actions.extend([
                'IP',
                '',
                '',
                ''
            ])
        elif risk_score >= 6.0:
            actions.extend([
                '',
                '',
                '',
                ''
            ])
        elif risk_score >= 4.0:
            actions.extend([
                '',
                '',
                '',
                ''
            ])
        else:
            actions.extend([
                '',
                '',
                ''
            ])

        # 
        if 'sql' in attack_type.lower():
            actions.extend(['', 'Web'])
        elif 'xss' in attack_type.lower():
            actions.extend(['Web', ''])
        elif 'command' in attack_type.lower() or 'rce' in attack_type.lower():
            actions.extend(['', '', ''])
        elif 'scan' in attack_type.lower():
            actions.extend(['', ''])

        return actions

    def _get_expert_agent(self, route: str) -> Optional[ExpertAgent]:
        """"""
        route_mapping = {
            'web_attack': AgentRole.WEB_ATTACK_EXPERT,
            'vulnerability_attack': AgentRole.VULNERABILITY_EXPERT,
            'illegal_connection': AgentRole.ILLEGAL_CONNECTION_EXPERT
        }

        expert_role = route_mapping.get(route)
        return self.experts.get(expert_role) if expert_role else None

    def _build_final_result(self, alert_data: Dict[str, Any],
                          router_result: AgentResult,
                          expert_result: Optional[AgentResult]) -> Dict[str, Any]:
        """"""
        final_result = {
            'success': True,
            'alert_id': alert_data.get('alert_id', 'unknown'),
            'timestamp': time.time(),
            'routing_analysis': {
                'selected_route': router_result.result.get('selected_route'),
                'target_agent': router_result.result.get('target_agent'),
                'confidence': router_result.confidence,
                'analysis': router_result.result.get('analysis')
            },
            'expert_analysis': None,
            'overall_assessment': {
                'risk_score': 5.0,
                'threat_level': 'unknown',
                'recommended_actions': []
            },
            'processing_chain': []
        }

        # 
        if expert_result and expert_result.success:
            final_result['expert_analysis'] = {
                'agent_id': expert_result.agent_id,
                'agent_role': expert_result.agent_role.value,
                'confidence': expert_result.confidence,
                'result': expert_result.result,
                'processing_time': expert_result.processing_time
            }

            # 
            self._update_overall_assessment(final_result, expert_result.result)

        # 
        final_result['processing_chain'].extend([
            {
                'agent': 'router',
                'processing_time': router_result.processing_time,
                'success': router_result.success
            }
        ])

        if expert_result:
            final_result['processing_chain'].append({
                'agent': expert_result.agent_role.value,
                'processing_time': expert_result.processing_time,
                'success': expert_result.success
            })

        return final_result

    def _update_overall_assessment(self, final_result: Dict[str, Any],
                                 expert_result: Dict[str, Any]):
        """"""
        risk_score = expert_result.get('risk_score', 5.0)
        false_positive_prob = expert_result.get('false_positive_probability', 0.5)

        final_result['overall_assessment']['risk_score'] = risk_score

        # 
        if risk_score >= 8.0:
            threat_level = ''
        elif risk_score >= 6.0:
            threat_level = ''
        else:
            threat_level = ''

        final_result['overall_assessment']['threat_level'] = threat_level

        # 
        recommended_actions = []

        if risk_score >= 8.0 and false_positive_prob < 0.3:
            recommended_actions.extend([
                'IP',
                '',
                ''
            ])
        elif risk_score >= 6.0:
            recommended_actions.extend([
                '',
                '',
                ''
            ])
        else:
            recommended_actions.extend([
                '',
                '',
                ''
            ])

        final_result['overall_assessment']['recommended_actions'] = recommended_actions

    def _update_performance_metrics(self, success: bool, processing_time: float):
        """"""
        self.performance_metrics['total_requests'] += 1

        if success:
            self.performance_metrics['successful_requests'] += 1
        else:
            self.performance_metrics['failed_requests'] += 1

        # 
        total = self.performance_metrics['total_requests']
        current_avg = self.performance_metrics['average_response_time']
        self.performance_metrics['average_response_time'] = (
            (current_avg * (total - 1) + processing_time) / total
        )

        # 
        if total % 10 == 0:  # 10
            self._update_intelligent_metrics()

    def _update_intelligent_metrics(self):
        """"""
        try:
            # 
            if self.enhanced_router:
                routing_stats = self.enhanced_router.get_routing_statistics()
                if routing_stats:
                    self.performance_metrics['routing_accuracy'] = routing_stats.get('accuracy', 0.0)

            # 
            if self.result_fusion_engine:
                fusion_stats = self.result_fusion_engine.get_fusion_statistics()
                if fusion_stats and 'weight_manager_stats' in fusion_stats:
                    weight_stats = fusion_stats['weight_manager_stats']
                    if 'expert_weights' in weight_stats:
                        # 
                        weights = list(weight_stats['expert_weights'].values())
                        if weights:
                            import statistics
                            weight_variance = statistics.variance(weights)
                            #  = 1 - 
                            self.performance_metrics['fusion_effectiveness'] = max(0.0, 1.0 - weight_variance)

        except Exception as e:
            logger.error(f": {e}")

    def get_system_status(self) -> Dict[str, Any]:
        """"""
        return {
            'is_initialized': self.is_initialized,
            'agents_count': len(self.agents),
            'experts_count': len(self.experts),
            'available_experts': [role.value for role in self.experts.keys()],
            'performance_metrics': self.performance_metrics,
            'individual_agent_metrics': {
                agent_id: agent.get_metrics()
                for agent_id, agent in self.agents.items()
            }
        }

    def health_check(self) -> Dict[str, Any]:
        """"""
        health_status = {
            'overall_health': 'healthy',
            'router_status': 'unknown',
            'experts_status': {},
            'issues': []
        }

        # 
        if self.router and self.router.is_initialized:
            health_status['router_status'] = 'healthy'
        else:
            health_status['router_status'] = 'unhealthy'
            health_status['overall_health'] = 'degraded'
            health_status['issues'].append('')

        # 
        for role, expert in self.experts.items():
            if expert and expert.is_initialized:
                health_status['experts_status'][role.value] = 'healthy'
            else:
                health_status['experts_status'][role.value] = 'unhealthy'
                health_status['overall_health'] = 'degraded'
                health_status['issues'].append(f' {role.value} ')

        return health_status

    def shutdown(self):
        """"""
        logger.info("...")

        # 
        for agent_id, agent in self.agents.items():
            try:
                if hasattr(agent, 'cleanup'):
                    agent.cleanup()
                logger.info(f" {agent_id} ")
            except Exception as e:
                logger.error(f" {agent_id} : {e}")

        self.agents.clear()
        self.experts.clear()
        self.is_initialized = False

        logger.info("")