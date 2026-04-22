#!/usr/bin/env python3
"""
Intune Policy Analyzer - Web GUI con Streamlit
Applicazione web per analizzare le policies Microsoft Intune,
definendo ottimizzazioni, standard e suggerimenti da applicare.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


# ============================================================================
# CORE BUSINESS LOGIC
# ============================================================================

class SeverityLevel(Enum):
    CRITICAL = "CRITICA"
    HIGH = "ALTA"
    MEDIUM = "MEDIA"
    LOW = "BASSA"
    INFO = "INFORMATIVA"

    def get_color(self):
        colors = {
            "CRITICA": "#dc3545",
            "ALTA": "#fd7e14",
            "MEDIA": "#ffc107",
            "BASSA": "#17a2b8",
            "INFORMATIVA": "#6c757d"
        }
        return colors.get(self.value, "#000000")


class PolicyCategory(Enum):
    COMPLIANCE = "Compliance"
    CONFIGURATION = "Configurazione"
    SECURITY = "Sicurezza"
    UPDATE = "Aggiornamenti"
    ENDPOINT_PROTECTION = "Protezione Endpoint"
    APP_PROTECTION = "Protezione App"
    DEVICE_RESTRICTION = "Restrizioni Device"
    CERTIFICATE = "Certificati"
    WIFI = "Wi-Fi"
    VPN = "VPN"
    EMAIL = "Email"
    OTHER = "Altro"


@dataclass
class Recommendation:
    id: str
    title: str
    description: str
    severity: SeverityLevel
    category: PolicyCategory
    current_value: Any
    recommended_value: Any
    impact: str
    remediation_steps: List[str]
    reference_links: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'category': self.category.value,
            'current_value': self.current_value,
            'recommended_value': self.recommended_value,
            'impact': self.impact,
            'remediation_steps': self.remediation_steps,
            'reference_links': self.reference_links
        }


@dataclass
class PolicyAnalysis:
    policy_id: str
    policy_name: str
    policy_type: str
    category: PolicyCategory
    is_compliant: bool
    issues_found: int
    recommendations: List[Recommendation] = field(default_factory=list)
    score: float = 0.0
    last_modified: Optional[str] = None
    assignment_count: int = 0

    def to_dict(self):
        return {
            'policy_id': self.policy_id,
            'policy_name': self.policy_name,
            'policy_type': self.policy_type,
            'category': self.category.value,
            'is_compliant': self.is_compliant,
            'issues_found': self.issues_found,
            'recommendations': [r.to_dict() for r in self.recommendations],
            'score': self.score,
            'last_modified': self.last_modified,
            'assignment_count': self.assignment_count
        }


@dataclass
class AnalysisReport:
    report_id: str
    generated_at: str
    total_policies: int
    compliant_policies: int
    non_compliant_policies: int
    overall_score: float
    policy_analyses: List[PolicyAnalysis] = field(default_factory=list)
    summary_by_category: Dict[str, Dict] = field(default_factory=dict)
    top_recommendations: List[Recommendation] = field(default_factory=list)

    def to_dict(self):
        return {
            'report_id': self.report_id,
            'generated_at': self.generated_at,
            'total_policies': self.total_policies,
            'compliant_policies': self.compliant_policies,
            'non_compliant_policies': self.non_compliant_policies,
            'overall_score': self.overall_score,
            'policy_analyses': [p.to_dict() for p in self.policy_analyses],
            'summary_by_category': self.summary_by_category,
            'top_recommendations': [r.to_dict() for r in self.top_recommendations]
        }


class IntunePolicyStandards:
    COMPLIANCE_STANDARDS = {
        "password_required": {"recommended": True, "severity": SeverityLevel.CRITICAL, "description": "La password deve essere obbligatoria"},
        "password_min_length": {"recommended": 6, "minimum": 4, "severity": SeverityLevel.HIGH, "description": "Lunghezza minima 6 caratteri"},
        "password_expiration_days": {"recommended": 90, "maximum": 180, "severity": SeverityLevel.MEDIUM, "description": "Scadenza ogni 90 giorni"},
        "encryption_required": {"recommended": True, "severity": SeverityLevel.CRITICAL, "description": "Crittografia obbligatoria"},
        "jailbreak_detection": {"recommended": True, "severity": SeverityLevel.HIGH, "description": "Rilevamento jailbreak attivo"},
    }

    SECURITY_STANDARDS = {
        "firewall_enabled": {"recommended": True, "severity": SeverityLevel.CRITICAL, "description": "Firewall sempre attivo"},
        "defender_real_time_protection": {"recommended": True, "severity": SeverityLevel.CRITICAL, "description": "Defender real-time attivo"},
        "bitlocker_enabled": {"recommended": True, "severity": SeverityLevel.CRITICAL, "description": "BitLocker abilitato"},
        "smart_screen_enabled": {"recommended": True, "severity": SeverityLevel.HIGH, "description": "SmartScreen abilitato"},
        "usb_restriction": {"recommended": "Block or Audit", "severity": SeverityLevel.MEDIUM, "description": "Limita USB"},
    }

    UPDATE_STANDARDS = {
        "update_deferral_days": {"recommended": 0, "maximum": 30, "severity": SeverityLevel.MEDIUM, "description": "Nessun ritardo critico"},
        "update_deadline_days": {"recommended": 7, "maximum": 14, "severity": SeverityLevel.HIGH, "description": "Deadline 7 giorni"},
        "active_hours": {"recommended": "8:00-18:00", "severity": SeverityLevel.LOW, "description": "Orari attivi configurati"},
    }

    APP_PROTECTION_STANDARDS = {
        "pin_required": {"recommended": True, "severity": SeverityLevel.HIGH, "description": "PIN per app protette"},
        "data_transfer_restriction": {"recommended": "Managed apps only", "severity": SeverityLevel.HIGH, "description": "Trasferimento solo app gestite"},
        "save_copy_restriction": {"recommended": "Block", "severity": SeverityLevel.MEDIUM, "description": "Blocca salvataggio copie"},
        "offline_access_limit": {"recommended": 30, "severity": SeverityLevel.MEDIUM, "description": "Limite offline 30 giorni"},
    }

    @classmethod
    def get_all_standards(cls) -> Dict[str, Dict]:
        return {
            "Compliance": cls.COMPLIANCE_STANDARDS,
            "Sicurezza": cls.SECURITY_STANDARDS,
            "Aggiornamenti": cls.UPDATE_STANDARDS,
            "Protezione App": cls.APP_PROTECTION_STANDARDS
        }


class IntunePolicyAnalyzer:
    def __init__(self):
        self.standards = IntunePolicyStandards()
        self.recommendation_counter = 0

    def analyze_policy(self, policy_data: Dict) -> PolicyAnalysis:
        policy_name = policy_data.get('name', 'Unknown')
        policy_type = policy_data.get('type', 'Unknown')
        category_str = policy_data.get('category', 'Altro')
        
        try:
            category = PolicyCategory(category_str)
        except ValueError:
            category = PolicyCategory.OTHER

        recommendations = []
        issues_found = 0
        score = 100.0

        if category == PolicyCategory.COMPLIANCE:
            recommendations, issues_found = self._analyze_compliance(policy_data)
        elif category in [PolicyCategory.SECURITY, PolicyCategory.ENDPOINT_PROTECTION]:
            recommendations, issues_found = self._analyze_security(policy_data)
        elif category == PolicyCategory.UPDATE:
            recommendations, issues_found = self._analyze_updates(policy_data)
        elif category == PolicyCategory.APP_PROTECTION:
            recommendations, issues_found = self._analyze_app_protection(policy_data)

        if issues_found > 0:
            score = max(0, 100 - (issues_found * 10))

        is_compliant = len(recommendations) == 0 or all(
            r.severity in [SeverityLevel.LOW, SeverityLevel.INFO] 
            for r in recommendations
        )

        return PolicyAnalysis(
            policy_id=policy_data.get('id', f'POL-{self.recommendation_counter}'),
            policy_name=policy_name,
            policy_type=policy_type,
            category=category,
            is_compliant=is_compliant,
            issues_found=issues_found,
            recommendations=recommendations,
            score=score,
            last_modified=policy_data.get('lastModified', None),
            assignment_count=policy_data.get('assignmentCount', 0)
        )

    def _create_recommendation(self, title: str, description: str, severity: SeverityLevel,
                               category: PolicyCategory, current: Any, recommended: Any,
                               impact: str, steps: List[str], links: List[str] = None) -> Recommendation:
        self.recommendation_counter += 1
        return Recommendation(
            id=f"REC-{self.recommendation_counter:04d}",
            title=title,
            description=description,
            severity=severity,
            category=category,
            current_value=current,
            recommended_value=recommended,
            impact=impact,
            remediation_steps=steps,
            reference_links=links or []
        )

    def _analyze_compliance(self, policy_data: Dict) -> Tuple[List[Recommendation], int]:
        recommendations = []
        issues = 0
        category = PolicyCategory.COMPLIANCE
        settings = policy_data.get('settings', {})

        if not settings.get('password_required', True):
            rec = self._create_recommendation(
                "Password Obbligatoria", "La password non è richiesta sui device",
                SeverityLevel.CRITICAL, category, "Non richiesta", "Obbligatoria",
                "Alto rischio di accesso non autorizzato",
                ["Apri Intune Admin Center", "Vai su Devices > Compliance policies", 
                 "Modifica la policy", "Abilita 'Password required'", "Salva e assegna"],
                ["https://docs.microsoft.com/en-us/mem/intune/protect/compliance-policy-create-windows"]
            )
            recommendations.append(rec)
            issues += 1

        pwd_length = settings.get('password_min_length', 6)
        if pwd_length < 6:
            rec = self._create_recommendation(
                "Lunghezza Password", f"Lunghezza minima: {pwd_length} caratteri",
                SeverityLevel.HIGH, category, f"{pwd_length} caratteri", "6+ caratteri",
                "Password deboli facilmente violabili",
                ["Modifica la policy", "Imposta lunghezza minima a 6+", "Considera 8+ per alta sicurezza"]
            )
            recommendations.append(rec)
            issues += 1

        if not settings.get('encryption_required', True):
            rec = self._create_recommendation(
                "Crittografia Dispositivo", "La crittografia non è obbligatoria",
                SeverityLevel.CRITICAL, category, "Non richiesta", "Obbligatoria (BitLocker)",
                "Dati sensibili esposti in caso di furto",
                ["Abilita BitLocker", "Configura recovery key backup", "Verifica TPM"]
            )
            recommendations.append(rec)
            issues += 1

        return recommendations, issues

    def _analyze_security(self, policy_data: Dict) -> Tuple[List[Recommendation], int]:
        recommendations = []
        issues = 0
        category = PolicyCategory.SECURITY
        settings = policy_data.get('settings', {})

        if not settings.get('firewall_enabled', True):
            rec = self._create_recommendation(
                "Firewall Attivo", "Il firewall non è abilitato",
                SeverityLevel.CRITICAL, category, "Disabilitato", "Abilitato",
                "Esposizione a attacchi di rete",
                ["Crea policy Endpoint Protection", "Abilita Windows Firewall", "Configura regole"]
            )
            recommendations.append(rec)
            issues += 1

        if not settings.get('defender_real_time', True):
            rec = self._create_recommendation(
                "Defender Real-Time", "Protezione real-time Defender disabilitata",
                SeverityLevel.CRITICAL, category, "Disabilitata", "Abilitata",
                "Mancata rilevazione malware",
                ["Policy Endpoint Protection", "Abilita real-time protection", "Cloud protection"]
            )
            recommendations.append(rec)
            issues += 1

        if not settings.get('smartscreen_enabled', True):
            rec = self._create_recommendation(
                "SmartScreen", "SmartScreen non abilitato",
                SeverityLevel.HIGH, category, "Disabilitato", "Abilitato",
                "Rischio phishing e malware",
                ["Device Configuration", "Windows Components > SmartScreen", "Enable"]
            )
            recommendations.append(rec)
            issues += 1

        return recommendations, issues

    def _analyze_updates(self, policy_data: Dict) -> Tuple[List[Recommendation], int]:
        recommendations = []
        issues = 0
        category = PolicyCategory.UPDATE
        settings = policy_data.get('settings', {})

        deferral = settings.get('deferral_days', 0)
        if deferral > 30:
            rec = self._create_recommendation(
                "Ritardo Aggiornamenti", f"Ritardo: {deferral} giorni",
                SeverityLevel.MEDIUM, category, f"{deferral} giorni", "0-30 giorni",
                "Vulnerabilità non patchate",
                ["Windows Update for Business", "Riduci deferral a 0-15", "Usa rings"]
            )
            recommendations.append(rec)
            issues += 1

        deadline = settings.get('deadline_days', 14)
        if deadline > 14:
            rec = self._create_recommendation(
                "Deadline Installazione", f"Deadline: {deadline} giorni",
                SeverityLevel.MEDIUM, category, f"{deadline} giorni", "7-14 giorni",
                "Dispositivi non aggiornati",
                ["Configura deadline stringenti", "7 giorni per critical", "Notifica utenti"]
            )
            recommendations.append(rec)
            issues += 1

        return recommendations, issues

    def _analyze_app_protection(self, policy_data: Dict) -> Tuple[List[Recommendation], int]:
        recommendations = []
        issues = 0
        category = PolicyCategory.APP_PROTECTION
        settings = policy_data.get('settings', {})

        if not settings.get('pin_required', True):
            rec = self._create_recommendation(
                "PIN per App", "PIN non richiesto per app protette",
                SeverityLevel.HIGH, category, "Non richiesto", "Obbligatorio",
                "Accesso non autorizzato a dati",
                ["App Protection Policies", "Access Requirements > PIN", "Require PIN"]
            )
            recommendations.append(rec)
            issues += 1

        transfer_policy = settings.get('data_transfer', 'allow')
        if transfer_policy == 'allow':
            rec = self._create_recommendation(
                "Trasferimento Dati", "Trasferimento illimitato consentito",
                SeverityLevel.HIGH, category, "Libero", "Solo app gestite",
                "Data leakage verso app personali",
                ["Data Protection settings", "Restrict to managed apps", "Configura eccezioni"]
            )
            recommendations.append(rec)
            issues += 1

        return recommendations, issues

    def analyze_all_policies(self, policies: List[Dict]) -> AnalysisReport:
        analyses = []
        compliant = 0
        non_compliant = 0
        all_recommendations = []

        for policy in policies:
            analysis = self.analyze_policy(policy)
            analyses.append(analysis)
            
            if analysis.is_compliant:
                compliant += 1
            else:
                non_compliant += 1
            
            all_recommendations.extend(analysis.recommendations)

        total_score = sum(a.score for a in analyses)
        overall_score = total_score / len(analyses) if analyses else 0

        summary = {}
        categories = set(a.category for a in analyses)
        for cat in categories:
            cat_policies = [a for a in analyses if a.category == cat]
            avg_score = sum(p.score for p in cat_policies) / len(cat_policies) if cat_policies else 0
            summary[cat.value] = {
                'count': len(cat_policies),
                'avg_score': round(avg_score, 2),
                'compliant': sum(1 for p in cat_policies if p.is_compliant)
            }

        severity_order = {
            SeverityLevel.CRITICAL: 0, SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2, SeverityLevel.LOW: 3, SeverityLevel.INFO: 4
        }
        sorted_recs = sorted(all_recommendations, key=lambda x: severity_order.get(x.severity, 5))
        top_recs = sorted_recs[:20]

        return AnalysisReport(
            report_id=f"RPT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            generated_at=datetime.now().isoformat(),
            total_policies=len(policies),
            compliant_policies=compliant,
            non_compliant_policies=non_compliant,
            overall_score=round(overall_score, 2),
            policy_analyses=analyses,
            summary_by_category=summary,
            top_recommendations=top_recs
        )


# ============================================================================
# STREAMLIT WEB GUI
# ============================================================================

def init_session_state():
    if 'analyzer' not in st.session_state:
        st.session_state.analyzer = IntunePolicyAnalyzer()
    if 'policies_data' not in st.session_state:
        st.session_state.policies_data = []
    if 'current_report' not in st.session_state:
        st.session_state.current_report = None
    if 'analyzed' not in st.session_state:
        st.session_state.analyzed = False


def load_demo_data():
    return [
        {"id": "POL-001", "name": "Baseline Compliance Policy", "type": "Compliance", "category": "Compliance",
         "lastModified": "2024-01-15T10:30:00Z", "assignmentCount": 150,
         "settings": {"password_required": False, "password_min_length": 4, "encryption_required": False, "jailbreak_detection": True}},
        {"id": "POL-002", "name": "Windows Security Baseline", "type": "Endpoint Protection", "category": "Sicurezza",
         "lastModified": "2024-01-10T14:20:00Z", "assignmentCount": 200,
         "settings": {"firewall_enabled": True, "defender_real_time": False, "smartscreen_enabled": False, "bitlocker_enabled": True}},
        {"id": "POL-003", "name": "Windows Update Policy", "type": "Update", "category": "Aggiornamenti",
         "lastModified": "2024-01-12T09:00:00Z", "assignmentCount": 180,
         "settings": {"deferral_days": 45, "deadline_days": 21, "active_hours": "8:00-18:00"}},
        {"id": "POL-004", "name": "App Protection - Office", "type": "App Protection", "category": "Protezione App",
         "lastModified": "2024-01-08T16:45:00Z", "assignmentCount": 300,
         "settings": {"pin_required": False, "data_transfer": "allow", "save_copy_restriction": "allow", "offline_access_limit": 90}},
        {"id": "POL-005", "name": "Device Restrictions", "type": "Device Restriction", "category": "Restrizioni Device",
         "lastModified": "2024-01-05T11:15:00Z", "assignmentCount": 120,
         "settings": {"usb_restriction": "allow", "camera_blocked": False, "screen_capture_blocked": True}},
        {"id": "POL-006", "name": "Advanced Compliance Policy", "type": "Compliance", "category": "Compliance",
         "lastModified": "2024-01-18T08:00:00Z", "assignmentCount": 75,
         "settings": {"password_required": True, "password_min_length": 8, "encryption_required": True, "jailbreak_detection": True}},
        {"id": "POL-007", "name": "Defender ATP Configuration", "type": "Endpoint Protection", "category": "Sicurezza",
         "lastModified": "2024-01-20T12:30:00Z", "assignmentCount": 250,
         "settings": {"firewall_enabled": True, "defender_real_time": True, "smartscreen_enabled": True}},
        {"id": "POL-008", "name": "Monthly Update Ring", "type": "Update", "category": "Aggiornamenti",
         "lastModified": "2024-01-22T15:45:00Z", "assignmentCount": 160,
         "settings": {"deferral_days": 15, "deadline_days": 7, "active_hours": "7:00-19:00"}}
    ]


def render_dashboard(report: AnalysisReport):
    st.header("📊 Dashboard")
    
    # Metriche principali
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Policies", report.total_policies)
    with col2:
        st.metric("✅ Compliant", report.compliant_policies, delta=None)
    with col3:
        st.metric("⚠️ Non-Compliant", report.non_compliant_policies, delta=None)
    with col4:
        st.metric("📈 Overall Score", f"{report.overall_score:.1f}/100")
    
    # Progress bar punteggio
    st.subheader("Punteggio Complessivo")
    progress_col = st.columns([3, 1])[0]
    with progress_col:
        st.progress(report.overall_score / 100)
        st.caption(f"{report.overall_score:.1f}%")
    
    # Grafici
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📊 Performance per Categoria")
        if report.summary_by_category:
            df_cat = pd.DataFrame([
                {"Categoria": cat, "Score": data['avg_score'], "Policies": data['count']}
                for cat, data in report.summary_by_category.items()
            ])
            fig = px.bar(df_cat, x='Categoria', y='Score', color='Score',
                        color_continuous_scale=['#d13438', '#ffc107', '#107c10'],
                        range_y=[0, 100])
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("📋 Stato Compliance")
        df_status = pd.DataFrame({
            'Stato': ['Compliant', 'Non-Compliant'],
            'Count': [report.compliant_policies, report.non_compliant_policies]
        })
        fig = px.pie(df_status, values='Count', names='Stato',
                    color='Stato', color_discrete_map={'Compliant': '#107c10', 'Non-Compliant': '#d13438'})
        st.plotly_chart(fig, use_container_width=True)
    
    # Severità raccomandazioni
    st.subheader("💡 Raccomandazioni per Severità")
    severity_counts = {}
    for rec in report.top_recommendations:
        sev = rec.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    if severity_counts:
        df_sev = pd.DataFrame({
            'Severità': list(severity_counts.keys()),
            'Count': list(severity_counts.values())
        })
        df_sev = df_sev.sort_values('Count', ascending=False)
        fig = px.bar(df_sev, x='Severità', y='Count', color='Severità',
                    color_discrete_sequence=['#dc3545', '#fd7e14', '#ffc107', '#17a2b8', '#6c757d'])
        st.plotly_chart(fig, use_container_width=True)


def render_policies_table(report: AnalysisReport):
    st.header("📋 Policies Analizzate")
    
    # Filtri
    col1, col2 = st.columns(2)
    with col1:
        search = st.text_input("🔍 Cerca", placeholder="Nome o ID policy...")
    with col2:
        categories = ["Tutte"] + list(set(a.category.value for a in report.policy_analyses))
        filter_cat = st.selectbox("Categoria", categories)
    
    # Filtra dati
    filtered = report.policy_analyses
    if search:
        filtered = [a for a in filtered if search.lower() in a.policy_name.lower() or search.lower() in a.policy_id.lower()]
    if filter_cat != "Tutte":
        filtered = [a for a in filtered if a.category.value == filter_cat]
    
    # Tabella
    df = pd.DataFrame([{
        'ID': a.policy_id,
        'Policy': a.policy_name,
        'Tipo': a.policy_type,
        'Categoria': a.category.value,
        'Stato': '✅ Compliant' if a.is_compliant else '⚠️ Non-Compliant',
        'Score': f"{a.score:.1f}",
        'Issues': a.issues_found,
        'Devices': a.assignment_count
    } for a in filtered])
    
    st.dataframe(df, use_container_width=True, hide_index=True)
    
    # Dettagli policy selezionata
    st.subheader("Dettagli Policy")
    policy_names = [a.policy_name for a in report.policy_analyses]
    selected = st.selectbox("Seleziona policy", policy_names)
    
    if selected:
        analysis = next((a for a in report.policy_analyses if a.policy_name == selected), None)
        if analysis:
            st.markdown(f"**ID:** {analysis.policy_id}")
            st.markdown(f"**Tipo:** {analysis.policy_type}")
            st.markdown(f"**Categoria:** {analysis.category.value}")
            st.markdown(f"**Stato:** {'✅ Compliant' if analysis.is_compliant else '⚠️ Non-Compliant'}")
            st.markdown(f"**Score:** {analysis.score:.1f}/100")
            st.markdown(f"**Issues:** {analysis.issues_found}")
            st.markdown(f"**Devices:** {analysis.assignment_count}")
            
            if analysis.recommendations:
                st.markdown("**Raccomandazioni:**")
                for rec in analysis.recommendations:
                    with st.expander(f"[{rec.severity.value}] {rec.title}"):
                        st.write(f"**Descrizione:** {rec.description}")
                        st.write(f"**Attuale:** {rec.current_value}")
                        st.write(f"**Raccomandato:** {rec.recommended_value}")
                        st.write(f"**Impatto:** {rec.impact}")
                        st.write("**Steps:**")
                        for i, step in enumerate(rec.remediation_steps, 1):
                            st.write(f"{i}. {step}")


def render_recommendations(report: AnalysisReport):
    st.header("💡 Raccomandazioni")
    
    # Filtro severità
    severity_filter = st.multiselect(
        "Filtra per severità",
        options=[s.value for s in SeverityLevel],
        default=[s.value for s in SeverityLevel]
    )
    
    # Filtra
    filtered = [r for r in report.top_recommendations if r.severity.value in severity_filter]
    
    # Ordina per severità
    severity_order = {"CRITICA": 0, "ALTA": 1, "MEDIA": 2, "BASSA": 3, "INFORMATIVA": 4}
    filtered.sort(key=lambda x: severity_order.get(x.severity.value, 5))
    
    # Mostra
    for rec in filtered:
        color_map = {
            "CRITICA": "red", "ALTA": "orange", "MEDIA": "yellow",
            "BASSA": "blue", "INFORMATIVA": "gray"
        }
        color = color_map.get(rec.severity.value, "gray")
        
        with st.container():
            st.markdown(f"### <span style='color:{color}'>[{rec.severity.value}] {rec.title}</span>", unsafe_allow_html=True)
            st.markdown(f"**Categoria:** {rec.category.value}")
            st.markdown(f"**Descrizione:** {rec.description}")
            
            col1, col2 = st.columns(2)
            with col1:
                st.info(f"**Attuale:** {rec.current_value}")
            with col2:
                st.success(f"**Raccomandato:** {rec.recommended_value}")
            
            st.warning(f"**Impatto:** {rec.impact}")
            
            with st.expander("📝 Steps di Remediation"):
                for i, step in enumerate(rec.remediation_steps, 1):
                    st.write(f"{i}. {step}")
            
            if rec.reference_links:
                st.markdown("**Riferimenti:**")
                for link in rec.reference_links:
                    st.markdown(f"- {link}")
            
            st.divider()
    
    # Export
    if st.button("📥 Esporta Raccomandazioni (CSV)"):
        df = pd.DataFrame([{
            'ID': r.id,
            'Titolo': r.title,
            'Severità': r.severity.value,
            'Categoria': r.category.value,
            'Attuale': r.current_value,
            'Raccomandato': r.recommended_value,
            'Impatto': r.impact
        } for r in filtered])
        
        csv = df.to_csv(index=False, encoding='utf-8-sig')
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name=f"raccomandazioni_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )


def render_standards():
    st.header("📖 Standard & Best Practices")
    
    standards = IntunePolicyStandards.get_all_standards()
    
    for category, items in standards.items():
        with st.expander(f"📌 {category}", expanded=False):
            df = pd.DataFrame([{
                'Parametro': param,
                'Valore Raccomandato': str(info.get('recommended', 'N/A')),
                'Severità': info.get('severity', SeverityLevel.INFO).value,
                'Descrizione': info.get('description', '')
            } for param, info in items.items()])
            st.dataframe(df, use_container_width=True, hide_index=True)


def render_json_viewer():
    st.header("📄 Carica JSON Policies")
    
    col1, col2 = st.columns(2)
    
    with col1:
        uploaded_file = st.file_uploader("Carica file JSON", type=['json'])
        
        if uploaded_file:
            try:
                st.session_state.policies_data = json.load(uploaded_file)
                st.success(f"✅ Caricate {len(st.session_state.policies_data)} policies!")
            except Exception as e:
                st.error(f"❌ Errore: {str(e)}")
    
    with col2:
        if st.button("🎯 Carica Dati Demo"):
            st.session_state.policies_data = load_demo_data()
            st.success(f"✅ Caricati {len(st.session_state.policies_data)} dati demo!")
    
    # Mostra anteprima
    if st.session_state.policies_data:
        st.subheader("Anteprima Policies")
        df = pd.DataFrame([{
            'ID': p.get('id', 'N/A'),
            'Nome': p.get('name', 'N/A'),
            'Tipo': p.get('type', 'N/A'),
            'Categoria': p.get('category', 'N/A'),
            'Devices': p.get('assignmentCount', 0)
        } for p in st.session_state.policies_data])
        st.dataframe(df, use_container_width=True, hide_index=True)
    
    # Pulsante analisi
    if st.session_state.policies_data:
        st.divider()
        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            if st.button("▶️ Avvia Analisi", type="primary", use_container_width=True):
                with st.spinner("Analisi in corso..."):
                    st.session_state.current_report = st.session_state.analyzer.analyze_all_policies(
                        st.session_state.policies_data
                    )
                    st.session_state.analyzed = True
                    st.rerun()
        with col2:
            if st.button("🔄 Reset", use_container_width=True):
                st.session_state.policies_data = []
                st.session_state.current_report = None
                st.session_state.analyzed = False
                st.rerun()


def export_report(report: AnalysisReport):
    st.header("💾 Esporta Report")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📥 Download JSON"):
            json_data = json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
            st.download_button(
                label="Download JSON",
                data=json_data,
                file_name=f"intune_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    
    with col2:
        if st.button("📥 Download HTML"):
            html_content = generate_html_report(report)
            st.download_button(
                label="Download HTML",
                data=html_content,
                file_name=f"intune_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                mime="text/html"
            )


def generate_html_report(report: AnalysisReport) -> str:
    return f"""<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <title>Intune Policy Analysis Report</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }}
        h1 {{ color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }}
        .metrics {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 30px 0; }}
        .metric {{ background: linear-gradient(135deg, #0078d4, #005a9e); color: white; padding: 20px; border-radius: 8px; text-align: center; }}
        .metric-value {{ font-size: 36px; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #0078d4; color: white; }}
        .compliant {{ color: #107c10; }}
        .non-compliant {{ color: #d13438; }}
        .recommendation {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 10px 0; }}
        .critical {{ background: #f8d7da; border-color: #d13438; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Intune Policy Analysis Report</h1>
        <p><strong>Generated:</strong> {datetime.fromisoformat(report.generated_at).strftime('%d/%m/%Y %H:%M:%S')}</p>
        <div class="metrics">
            <div class="metric"><div class="metric-value">{report.total_policies}</div><div>Total Policies</div></div>
            <div class="metric" style="background: linear-gradient(135deg, #107c10, #0c5e0c);"><div class="metric-value">{report.compliant_policies}</div><div>Compliant</div></div>
            <div class="metric" style="background: linear-gradient(135deg, #d13438, #9e2a2a);"><div class="metric-value">{report.non_compliant_policies}</div><div>Non-Compliant</div></div>
            <div class="metric" style="background: linear-gradient(135deg, #666, #333);"><div class="metric-value">{report.overall_score:.1f}</div><div>Overall Score</div></div>
        </div>
        <h2>📋 Policies</h2>
        <table><thead><tr><th>Policy</th><th>Type</th><th>Category</th><th>Status</th><th>Score</th><th>Issues</th></tr></thead><tbody>
""" + "".join([f"<tr><td>{a.policy_name}</td><td>{a.policy_type}</td><td>{a.category.value}</td><td class=\"{'compliant' if a.is_compliant else 'non-compliant'}\">{'✅' if a.is_compliant else '⚠️'}</td><td>{a.score:.1f}</td><td>{a.issues_found}</td></tr>" for a in report.policy_analyses]) + """
        </tbody></table>
        <h2>💡 Recommendations</h2>
""" + "".join([f"<div class=\"recommendation {'critical' if r.severity == SeverityLevel.CRITICAL else ''}\"><h3>[{r.severity.value}] {r.title}</h3><p>{r.description}</p><p><strong>Impact:</strong> {r.impact}</p></div>" for r in report.top_recommendations]) + """
    </div>
</body>
</html>"""


def main():
    st.set_page_config(
        page_title="Intune Policy Analyzer",
        page_icon="🔍",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # CSS personalizzato
    st.markdown("""
    <style>
    .main > div {padding-top: 2rem;}
    h1 {color: #0078d4;}
    h2 {color: #005a9e;}
    </style>
    """, unsafe_allow_html=True)
    
    init_session_state()
    
    # Sidebar
    with st.sidebar:
        st.image("https://img.icons8.com/color/96/microsoft-intune.png", width=80)
        st.title("Intune Analyzer")
        st.markdown("---")
        
        menu = st.radio(
            "Navigazione",
            ["🏠 Home", "📊 Dashboard", "📋 Policies", "💡 Raccomandazioni", "📖 Standard", "💾 Export"],
            index=0
        )
        
        st.markdown("---")
        st.markdown("### Status")
        if st.session_state.analyzed:
            st.success("✅ Analisi completata")
            st.info(f"📊 {st.session_state.current_report.total_policies if st.session_state.current_report else 0} policies")
        else:
            st.warning("⏳ In attesa di analisi")
        
        st.markdown("---")
        st.markdown("### Info")
        st.markdown("""
        **Version:** 2.0  
        **Framework:** Streamlit  
        **License:** MIT
        """)
    
    # Main content
    if menu == "🏠 Home":
        st.title("🔍 Intune Policy Analyzer")
        st.subheader("Analisi, Ottimizzazione e Standard per Microsoft Intune")
        
        st.markdown("""
        ### Benvenuto!
        
        Questa applicazione ti permette di:
        - 📊 **Analizzare** le policies implementate sui device in Intune
        - 🔍 **Identificare** criticità e aree di miglioramento
        - 💡 **Ottenere** raccomandazioni basate su best practices Microsoft
        - 📖 **Consultare** standard e linee guida
        - 💾 **Esportare** report dettagliati in JSON e HTML
        
        ### Come iniziare
        
        1. Vai alla sezione **Home** e carica un file JSON con le tue policies
        2. Oppure usa i **Dati Demo** per provare l'applicazione
        3. Clicca su **Avvia Analisi**
        4. Consulta i risultati nelle sezioni **Dashboard**, **Policies** e **Raccomandazioni**
        """)
        
        render_json_viewer()
        
    elif menu == "📊 Dashboard":
        if st.session_state.analyzed and st.session_state.current_report:
            render_dashboard(st.session_state.current_report)
        else:
            st.warning("⚠️ Nessuna analisi effettuata. Vai su Home per caricare le policies.")
            render_json_viewer()
            
    elif menu == "📋 Policies":
        if st.session_state.analyzed and st.session_state.current_report:
            render_policies_table(st.session_state.current_report)
        else:
            st.warning("⚠️ Nessuna analisi effettuata.")
            
    elif menu == "💡 Raccomandazioni":
        if st.session_state.analyzed and st.session_state.current_report:
            render_recommendations(st.session_state.current_report)
        else:
            st.warning("⚠️ Nessuna analisi effettuata.")
            
    elif menu == "📖 Standard":
        render_standards()
        
    elif menu == "💾 Export":
        if st.session_state.analyzed and st.session_state.current_report:
            export_report(st.session_state.current_report)
        else:
            st.warning("⚠️ Nessuna analisi da esportare.")


if __name__ == "__main__":
    main()
