#!/usr/bin/env python3
"""
Intune Policy Analyzer - GUI Application
Applicazione con interfaccia grafica per analizzare le policies Microsoft Intune,
definendo ottimizzazioni, standard e suggerimenti da applicare.
"""

import json
import os
import sys
import webbrowser
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, Menu
import threading
import queue


# ============================================================================
# CORE BUSINESS LOGIC (mantenuta dalla versione precedente)
# ============================================================================

class SeverityLevel(Enum):
    """Livelli di severità per le raccomandazioni."""
    CRITICAL = "CRITICA"
    HIGH = "ALTA"
    MEDIUM = "MEDIA"
    LOW = "BASSA"
    INFO = "INFORMATIVA"

    def get_color(self):
        """Restituisce il colore associato al livello di severità."""
        colors = {
            "CRITICA": "#dc3545",
            "ALTA": "#fd7e14",
            "MEDIA": "#ffc107",
            "BASSA": "#17a2b8",
            "INFORMATIVA": "#6c757d"
        }
        return colors.get(self.value, "#000000")


class PolicyCategory(Enum):
    """Categorie di policies Intune."""
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
    """Rappresenta una raccomandazione per l'ottimizzazione."""
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
        """Converte la raccomandazione in dizionario."""
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
    """Risultato dell'analisi di una policy."""
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
        """Converte l'analisi in dizionario."""
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
    """Report completo dell'analisi."""
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
        """Converte il report in dizionario."""
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
    """Definisce gli standard e le best practices per le policies Intune."""

    COMPLIANCE_STANDARDS = {
        "password_required": {
            "recommended": True,
            "severity": SeverityLevel.CRITICAL,
            "description": "La password deve essere obbligatoria su tutti i device"
        },
        "password_min_length": {
            "recommended": 6,
            "minimum": 4,
            "severity": SeverityLevel.HIGH,
            "description": "Lunghezza minima password: 6 caratteri"
        },
        "password_expiration_days": {
            "recommended": 90,
            "maximum": 180,
            "severity": SeverityLevel.MEDIUM,
            "description": "Scadenza password ogni 90 giorni"
        },
        "encryption_required": {
            "recommended": True,
            "severity": SeverityLevel.CRITICAL,
            "description": "Crittografia del dispositivo obbligatoria"
        },
        "jailbreak_detection": {
            "recommended": True,
            "severity": SeverityLevel.HIGH,
            "description": "Rilevamento jailbreak/root attivo"
        },
        "os_minimum_version": {
            "recommended": "Latest - 2 versions",
            "severity": SeverityLevel.MEDIUM,
            "description": "Versione OS minima supportata"
        }
    }

    SECURITY_STANDARDS = {
        "firewall_enabled": {
            "recommended": True,
            "severity": SeverityLevel.CRITICAL,
            "description": "Firewall sempre attivo"
        },
        "defender_real_time_protection": {
            "recommended": True,
            "severity": SeverityLevel.CRITICAL,
            "description": "Protezione in tempo reale Defender attiva"
        },
        "bitlocker_enabled": {
            "recommended": True,
            "severity": SeverityLevel.CRITICAL,
            "description": "BitLocker abilitato su tutti i device"
        },
        "smart_screen_enabled": {
            "recommended": True,
            "severity": SeverityLevel.HIGH,
            "description": "SmartScreen per proteggere da malware"
        },
        "usb_restriction": {
            "recommended": "Block or Audit",
            "severity": SeverityLevel.MEDIUM,
            "description": "Limitare uso dispositivi USB"
        }
    }

    UPDATE_STANDARDS = {
        "update_deferral_days": {
            "recommended": 0,
            "maximum": 30,
            "severity": SeverityLevel.MEDIUM,
            "description": "Nessun ritardo negli aggiornamenti critici"
        },
        "update_deadline_days": {
            "recommended": 7,
            "maximum": 14,
            "severity": SeverityLevel.HIGH,
            "description": "Deadline installazione: 7 giorni"
        },
        "active_hours": {
            "recommended": "8:00-18:00",
            "severity": SeverityLevel.LOW,
            "description": "Orari attivi configurati correttamente"
        }
    }

    APP_PROTECTION_STANDARDS = {
        "pin_required": {
            "recommended": True,
            "severity": SeverityLevel.HIGH,
            "description": "PIN richiesto per app protette"
        },
        "data_transfer_restriction": {
            "recommended": "Managed apps only",
            "severity": SeverityLevel.HIGH,
            "description": "Trasferimento dati solo tra app gestite"
        },
        "save_copy_restriction": {
            "recommended": "Block",
            "severity": SeverityLevel.MEDIUM,
            "description": "Blocco salvataggio copie non autorizzate"
        },
        "offline_access_limit": {
            "recommended": 30,
            "severity": SeverityLevel.MEDIUM,
            "description": "Limite accesso offline: 30 giorni"
        }
    }

    @classmethod
    def get_all_standards(cls) -> Dict[str, Dict]:
        """Restituisce tutti gli standard."""
        return {
            "Compliance": cls.COMPLIANCE_STANDARDS,
            "Sicurezza": cls.SECURITY_STANDARDS,
            "Aggiornamenti": cls.UPDATE_STANDARDS,
            "Protezione App": cls.APP_PROTECTION_STANDARDS
        }


class IntunePolicyAnalyzer:
    """Motore di analisi delle policies Intune."""

    def __init__(self):
        self.standards = IntunePolicyStandards()
        self.recommendation_counter = 0

    def analyze_policy(self, policy_data: Dict) -> PolicyAnalysis:
        """Analizza una singola policy."""
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

        # Analizza in base alla categoria
        if category == PolicyCategory.COMPLIANCE:
            recommendations, issues_found = self._analyze_compliance(policy_data)
        elif category in [PolicyCategory.SECURITY, PolicyCategory.ENDPOINT_PROTECTION]:
            recommendations, issues_found = self._analyze_security(policy_data)
        elif category == PolicyCategory.UPDATE:
            recommendations, issues_found = self._analyze_updates(policy_data)
        elif category == PolicyCategory.APP_PROTECTION:
            recommendations, issues_found = self._analyze_app_protection(policy_data)

        # Calcola punteggio
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
        """Crea una nuova raccomandazione."""
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
        """Analizza compliance policies."""
        recommendations = []
        issues = 0
        category = PolicyCategory.COMPLIANCE

        settings = policy_data.get('settings', {})

        # Password required
        if not settings.get('password_required', True):
            rec = self._create_recommendation(
                "Password Obbligatoria",
                "La password non è richiesta sui device",
                SeverityLevel.CRITICAL,
                category,
                "Non richiesta",
                "Obbligatoria",
                "Alto rischio di accesso non autorizzato",
                [
                    "Apri Intune Admin Center",
                    "Vai su Devices > Compliance policies",
                    "Modifica la policy",
                    "Abilita 'Password required'",
                    "Salva e assegna ai gruppi target"
                ],
                ["https://docs.microsoft.com/en-us/mem/intune/protect/compliance-policy-create-windows"]
            )
            recommendations.append(rec)
            issues += 1

        # Password length
        pwd_length = settings.get('password_min_length', 6)
        if pwd_length < 6:
            rec = self._create_recommendation(
                "Lunghezza Password",
                f"Lunghezza minima password: {pwd_length} caratteri",
                SeverityLevel.HIGH,
                category,
                f"{pwd_length} caratteri",
                "6+ caratteri",
                "Password deboli facilmente violabili",
                [
                    "Modifica la policy di compliance",
                    "Imposta lunghezza minima a 6 o più",
                    "Considera 8+ per ambienti ad alta sicurezza"
                ]
            )
            recommendations.append(rec)
            issues += 1

        # Encryption
        if not settings.get('encryption_required', True):
            rec = self._create_recommendation(
                "Crittografia Dispositivo",
                "La crittografia non è obbligatoria",
                SeverityLevel.CRITICAL,
                category,
                "Non richiesta",
                "Obbligatoria (BitLocker)",
                "Dati sensibili esposti in caso di furto",
                [
                    "Abilita BitLocker tramite policy",
                    "Configura recovery key backup in Azure AD",
                    "Verifica compatibilità hardware TPM"
                ]
            )
            recommendations.append(rec)
            issues += 1

        return recommendations, issues

    def _analyze_security(self, policy_data: Dict) -> Tuple[List[Recommendation], int]:
        """Analizza security/endpoint protection policies."""
        recommendations = []
        issues = 0
        category = policy_data.get('category', 'Sicurezza')
        try:
            category = PolicyCategory(category)
        except:
            category = PolicyCategory.SECURITY

        settings = policy_data.get('settings', {})

        # Firewall
        if not settings.get('firewall_enabled', True):
            rec = self._create_recommendation(
                "Firewall Attivo",
                "Il firewall non è abilitato",
                SeverityLevel.CRITICAL,
                category,
                "Disabilitato",
                "Abilitato",
                "Esposizione a attacchi di rete",
                [
                    "Crea policy Endpoint Protection",
                    "Abilita Windows Firewall",
                    "Configura regole in/out appropriate"
                ]
            )
            recommendations.append(rec)
            issues += 1

        # Defender
        if not settings.get('defender_real_time', True):
            rec = self._create_recommendation(
                "Defender Real-Time",
                "Protezione real-time Defender disabilitata",
                SeverityLevel.CRITICAL,
                category,
                "Disabilitata",
                "Abilitata",
                "Mancata rilevazione malware in tempo reale",
                [
                    "Policy Endpoint Protection > Windows Security Experience",
                    "Abilita real-time protection",
                    "Configura cloud-delivered protection"
                ]
            )
            recommendations.append(rec)
            issues += 1

        # SmartScreen
        if not settings.get('smartscreen_enabled', True):
            rec = self._create_recommendation(
                "SmartScreen",
                "SmartScreen non abilitato",
                SeverityLevel.HIGH,
                category,
                "Disabilitato",
                "Abilitato",
                "Rischio phishing e malware download",
                [
                    "Device Configuration > Administrative Templates",
                    "Windows Components > SmartScreen",
                    "Enable SmartScreen Explorer"
                ]
            )
            recommendations.append(rec)
            issues += 1

        return recommendations, issues

    def _analyze_updates(self, policy_data: Dict) -> Tuple[List[Recommendation], int]:
        """Analizza update policies."""
        recommendations = []
        issues = 0
        category = PolicyCategory.UPDATE

        settings = policy_data.get('settings', {})

        # Deferral days
        deferral = settings.get('deferral_days', 0)
        if deferral > 30:
            rec = self._create_recommendation(
                "Ritardo Aggiornamenti",
                f"Ritardo aggiornamenti: {deferral} giorni",
                SeverityLevel.MEDIUM,
                category,
                f"{deferral} giorni",
                "0-30 giorni",
                "Vulnerabilità di sicurezza non patchate tempestivamente",
                [
                    "Windows Update for Business policy",
                    "Riduci deferral days a 0-15",
                    "Usa rings di deployment per testing"
                ]
            )
            recommendations.append(rec)
            issues += 1

        # Deadline
        deadline = settings.get('deadline_days', 14)
        if deadline > 14:
            rec = self._create_recommendation(
                "Deadline Installazione",
                f"Deadline installazione: {deadline} giorni",
                SeverityLevel.MEDIUM,
                category,
                f"{deadline} giorni",
                "7-14 giorni",
                "Dispositivi non aggiornati per periodi prolungati",
                [
                    "Configura deadline più stringenti",
                    "Imposta 7 giorni per aggiornamenti critici",
                    "Notifica utenti prima della deadline"
                ]
            )
            recommendations.append(rec)
            issues += 1

        return recommendations, issues

    def _analyze_app_protection(self, policy_data: Dict) -> Tuple[List[Recommendation], int]:
        """Analizza app protection policies."""
        recommendations = []
        issues = 0
        category = PolicyCategory.APP_PROTECTION

        settings = policy_data.get('settings', {})

        # PIN required
        if not settings.get('pin_required', True):
            rec = self._create_recommendation(
                "PIN per App",
                "PIN non richiesto per app protette",
                SeverityLevel.HIGH,
                category,
                "Non richiesto",
                "Obbligatorio",
                "Accesso non autorizzato a dati aziendali",
                [
                    "App Protection Policies",
                    "Access Requirements > PIN",
                    "Require PIN for access",
                    "Imposta complessità adeguata"
                ]
            )
            recommendations.append(rec)
            issues += 1

        # Data transfer
        transfer_policy = settings.get('data_transfer', 'allow')
        if transfer_policy == 'allow':
            rec = self._create_recommendation(
                "Trasferimento Dati",
                "Trasferimento dati illimitato consentito",
                SeverityLevel.HIGH,
                category,
                "Libero",
                "Solo app gestite",
                "Data leakage verso app personali",
                [
                    "Data Protection settings",
                    "Restrict data transfer to managed apps",
                    "Configura eccezioni se necessarie"
                ]
            )
            recommendations.append(rec)
            issues += 1

        return recommendations, issues

    def analyze_all_policies(self, policies: List[Dict]) -> AnalysisReport:
        """Analizza tutte le policies e genera report."""
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

        # Calcola punteggio complessivo
        total_score = sum(a.score for a in analyses)
        overall_score = total_score / len(analyses) if analyses else 0

        # Summary per categoria
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

        # Top recommendations (ordinata per severità)
        severity_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4
        }
        sorted_recs = sorted(all_recommendations, 
                            key=lambda x: severity_order.get(x.severity, 5))
        top_recs = sorted_recs[:20]  # Top 20

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
# GUI APPLICATION
# ============================================================================

class IntuneAnalyzerGUI:
    """Interfaccia grafica per Intune Policy Analyzer."""

    def __init__(self, root):
        self.root = root
        self.root.title("Intune Policy Analyzer - Analisi Policies e Ottimizzazioni")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 700)

        # Imposta stile
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configura colori e font
        self.colors = {
            'bg': '#f5f5f5',
            'primary': '#0078d4',
            'success': '#107c10',
            'warning': '#ffaa44',
            'danger': '#d13438',
            'text': '#323130',
            'border': '#e1dfdd'
        }

        self.root.configure(bg=self.colors['bg'])

        # Inizializza analyzer
        self.analyzer = IntunePolicyAnalyzer()
        self.current_report: Optional[AnalysisReport] = None
        self.policies_data: List[Dict] = []

        # Coda per comunicazione thread
        self.task_queue = queue.Queue()

        # Crea UI
        self._create_menu()
        self._create_ui()

        # Status bar
        self.status_var = tk.StringVar(value="Pronto - Carica policies da file JSON o usa dati demo")
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def _create_menu(self):
        """Crea la barra dei menu."""
        menubar = Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Carica JSON Policies...", command=self._load_policies_file, accelerator="Ctrl+O")
        file_menu.add_command(label="Carica Dati Demo", command=self._load_demo_data)
        file_menu.add_separator()
        file_menu.add_command(label="Esporta Report JSON...", command=self._export_json, accelerator="Ctrl+S")
        file_menu.add_command(label="Esporta Report HTML...", command=self._export_html, accelerator="Ctrl+H")
        file_menu.add_separator()
        file_menu.add_command(label="Esci", command=self.root.quit, accelerator="Ctrl+Q")

        # Analisi menu
        analysis_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Analisi", menu=analysis_menu)
        analysis_menu.add_command(label="Avvia Analisi", command=self._run_analysis, accelerator="F5")
        analysis_menu.add_command(label="Reset", command=self._reset_analysis)

        # Visualizza menu
        view_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Visualizza", menu=view_menu)
        view_menu.add_command(label="Dashboard", command=self._show_dashboard)
        view_menu.add_command(label="Standard e Best Practices", command=self._show_standards)
        view_menu.add_command(label="Informazioni", command=self._show_about)

        # Help menu
        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="?", menu=help_menu)
        help_menu.add_command(label="Documentazione", command=self._open_docs)
        help_menu.add_command(label="Informazioni su...", command=self._show_about)

        # Bindings tastiera
        self.root.bind('<Control-o>', lambda e: self._load_policies_file())
        self.root.bind('<Control-s>', lambda e: self._export_json())
        self.root.bind('<Control-h>', lambda e: self._export_html())
        self.root.bind('<F5>', lambda e: self._run_analysis())

    def _create_ui(self):
        """Crea l'interfaccia utente principale."""
        # Panoramico container
        main_container = ttk.Frame(self.root, padding="10")
        main_container.pack(fill=tk.BOTH, expand=True)

        # Header
        header_frame = ttk.Frame(main_container)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        title_label = ttk.Label(
            header_frame,
            text="🔍 Intune Policy Analyzer",
            font=('Segoe UI', 20, 'bold'),
            foreground=self.colors['primary']
        )
        title_label.pack(side=tk.LEFT)

        subtitle_label = ttk.Label(
            header_frame,
            text="Analisi, Ottimizzazione e Standard per Microsoft Intune",
            font=('Segoe UI', 10),
            foreground='#666'
        )
        subtitle_label.pack(side=tk.LEFT, padx=(10, 0), pady=(8, 0))

        # Pulsanti azione rapida
        btn_frame = ttk.Frame(header_frame)
        btn_frame.pack(side=tk.RIGHT)

        self.load_btn = ttk.Button(
            btn_frame,
            text="📁 Carica Policies",
            command=self._load_policies_file,
            width=15
        )
        self.load_btn.pack(side=tk.LEFT, padx=5)

        self.analyze_btn = ttk.Button(
            btn_frame,
            text="▶️ Avvia Analisi",
            command=self._run_analysis,
            width=15,
            style='Accent.TButton'
        )
        self.analyze_btn.pack(side=tk.LEFT, padx=5)

        self.export_btn = ttk.Button(
            btn_frame,
            text="💾 Esporta Report",
            command=self._export_html,
            width=15,
            state=tk.DISABLED
        )
        self.export_btn.pack(side=tk.LEFT, padx=5)

        # Notebook per tab
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Tab 1: Dashboard
        self.dashboard_tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.dashboard_tab, text="📊 Dashboard")
        self._create_dashboard_tab()

        # Tab 2: Policies Analizzate
        self.policies_tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.policies_tab, text="📋 Policies")
        self._create_policies_tab()

        # Tab 3: Raccomandazioni
        self.recommendations_tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.recommendations_tab, text="💡 Raccomandazioni")
        self._create_recommendations_tab()

        # Tab 4: Standard
        self.standards_tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.standards_tab, text="📖 Standard & Best Practices")
        self._create_standards_tab()

        # Tab 5: Log
        self.log_tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.log_tab, text="📝 Log Analisi")
        self._create_log_tab()

    def _create_dashboard_tab(self):
        """Crea la tab dashboard."""
        # Frame per metriche
        metrics_frame = ttk.LabelFrame(self.dashboard_tab, text="Metriche Principali", padding="15")
        metrics_frame.pack(fill=tk.X, pady=(0, 10))

        # Griglia metriche
        self.metrics = {}
        metric_configs = [
            ("Total Policies", "total_policies", "📋"),
            ("Compliant", "compliant", "✅", self.colors['success']),
            ("Non-Compliant", "non_compliant", "⚠️", self.colors['danger']),
            ("Overall Score", "score", "📈", self.colors['primary']),
            ("Critical Issues", "critical", "🔴", self.colors['danger']),
            ("Recommendations", "recommendations", "💡", self.colors['warning'])
        ]

        for i, config in enumerate(metric_configs):
            label_text = config[0]
            attr_name = config[1]
            icon = config[2]
            color = config[3] if len(config) > 3 else self.colors['text']

            frame = ttk.Frame(metrics_frame)
            frame.grid(row=i // 3, column=i % 3, padx=20, pady=10, sticky='nsew')

            icon_label = ttk.Label(frame, text=icon, font=('Segoe UI', 24))
            icon_label.pack()

            value_label = ttk.Label(
                frame,
                text="-",
                font=('Segoe UI', 28, 'bold'),
                foreground=color
            )
            value_label.pack()

            name_label = ttk.Label(
                frame,
                text=label_text,
                font=('Segoe UI', 10),
                foreground='#666'
            )
            name_label.pack()

            self.metrics[attr_name] = value_label

        metrics_frame.grid_columnconfigure(0, weight=1)
        metrics_frame.grid_columnconfigure(1, weight=1)
        metrics_frame.grid_columnconfigure(2, weight=1)

        # Progress bar punteggio
        score_frame = ttk.LabelFrame(self.dashboard_tab, text="Punteggio Complessivo", padding="15")
        score_frame.pack(fill=tk.X, pady=(0, 10))

        self.score_progress = ttk.Progressbar(
            score_frame,
            orient=tk.HORIZONTAL,
            length=600,
            mode='determinate'
        )
        self.score_progress.pack(pady=10)

        self.score_label = ttk.Label(
            score_frame,
            text="Punteggio: 0/100",
            font=('Segoe UI', 14, 'bold')
        )
        self.score_label.pack()

        # Grafico categorie (simulato con barre)
        chart_frame = ttk.LabelFrame(self.dashboard_tab, text="Performance per Categoria", padding="15")
        chart_frame.pack(fill=tk.BOTH, expand=True)

        self.chart_canvas = tk.Canvas(chart_frame, height=200, bg='white')
        self.chart_canvas.pack(fill=tk.BOTH, expand=True)

    def _create_policies_tab(self):
        """Crea la tab delle policies."""
        # Toolbar
        toolbar = ttk.Frame(self.policies_tab)
        toolbar.pack(fill=tk.X, pady=(0, 10))

        filter_label = ttk.Label(toolbar, text="Filtra:")
        filter_label.pack(side=tk.LEFT, padx=(0, 5))

        self.filter_var = tk.StringVar()
        self.filter_var.trace('w', self._filter_policies)
        filter_entry = ttk.Entry(toolbar, textvariable=self.filter_var, width=30)
        filter_entry.pack(side=tk.LEFT, padx=(0, 10))

        category_label = ttk.Label(toolbar, text="Categoria:")
        category_label.pack(side=tk.LEFT, padx=(0, 5))

        self.category_filter = ttk.Combobox(
            toolbar,
            values=["Tutte"] + [c.value for c in PolicyCategory],
            state="readonly",
            width=20
        )
        self.category_filter.set("Tutte")
        self.category_filter.bind('<<ComboboxSelected>>', self._filter_policies)
        self.category_filter.pack(side=tk.LEFT)

        # Treeview
        tree_frame = ttk.Frame(self.policies_tab)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("ID", "Nome", "Tipo", "Categoria", "Stato", "Score", "Issues")
        self.policies_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=20)

        for col in columns:
            self.policies_tree.heading(col, text=col)
            self.policies_tree.column(col, width=100 if col != "Nome" else 250)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.policies_tree.yview)
        self.policies_tree.configure(yscrollcommand=scrollbar.set)

        self.policies_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind doppio click
        self.policies_tree.bind('<Double-1>', self._show_policy_details)

        # Pannello dettagli
        details_frame = ttk.LabelFrame(self.policies_tab, text="Dettagli Policy", padding="10")
        details_frame.pack(fill=tk.X, pady=(10, 0))

        self.policy_details = scrolledtext.ScrolledText(
            details_frame,
            height=6,
            wrap=tk.WORD,
            font=('Consolas', 9)
        )
        self.policy_details.pack(fill=tk.BOTH, expand=True)

    def _create_recommendations_tab(self):
        """Crea la tab delle raccomandazioni."""
        # Toolbar
        toolbar = ttk.Frame(self.recommendations_tab)
        toolbar.pack(fill=tk.X, pady=(0, 10))

        severity_label = ttk.Label(toolbar, text="Severità:")
        severity_label.pack(side=tk.LEFT, padx=(0, 5))

        self.severity_filter = ttk.Combobox(
            toolbar,
            values=["Tutte"] + [s.value for s in SeverityLevel],
            state="readonly",
            width=15
        )
        self.severity_filter.set("Tutte")
        self.severity_filter.bind('<<ComboboxSelected>>', self._filter_recommendations)
        self.severity_filter.pack(side=tk.LEFT)

        export_btn = ttk.Button(
            toolbar,
            text="Esporta Raccomandazioni",
            command=self._export_recommendations
        )
        export_btn.pack(side=tk.RIGHT)

        # Treeview
        tree_frame = ttk.Frame(self.recommendations_tab)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("ID", "Titolo", "Severità", "Categoria", "Impatto")
        self.recs_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=18)

        column_widths = [80, 300, 100, 150, 200]
        for col, width in zip(columns, column_widths):
            self.recs_tree.heading(col, text=col)
            self.recs_tree.column(col, width=width)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.recs_tree.yview)
        self.recs_tree.configure(yscrollcommand=scrollbar.set)

        self.recs_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind selezione
        self.recs_tree.bind('<<TreeviewSelect>>', self._show_recommendation_details)

        # Pannello dettagli
        details_frame = ttk.LabelFrame(self.recommendations_tab, text="Dettagli Raccomandazione", padding="10")
        details_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        self.rec_details = scrolledtext.ScrolledText(
            details_frame,
            height=10,
            wrap=tk.WORD,
            font=('Consolas', 9)
        )
        self.rec_details.pack(fill=tk.BOTH, expand=True)

    def _create_standards_tab(self):
        """Crea la tab degli standard."""
        # Notebook interno per categorie
        standards_notebook = ttk.Notebook(self.standards_tab)
        standards_notebook.pack(fill=tk.BOTH, expand=True)

        standards = IntunePolicyStandards.get_all_standards()

        for category, items in standards.items():
            frame = ttk.Frame(standards_notebook, padding="10")
            standards_notebook.add(frame, text=category)

            # Treeview
            columns = ("Parametro", "Valore Raccomandato", "Severità", "Descrizione")
            tree = ttk.Treeview(frame, columns=columns, show='headings', height=20)

            for col in columns:
                tree.heading(col, text=col)
                tree.column(col, width=150 if col != "Descrizione" else 300)

            for param, info in items.items():
                severity = info.get('severity', SeverityLevel.INFO)
                tree.insert('', tk.END, values=(
                    param,
                    str(info.get('recommended', 'N/A')),
                    severity.value,
                    info.get('description', '')
                ))

            tree.pack(fill=tk.BOTH, expand=True)

    def _create_log_tab(self):
        """Crea la tab dei log."""
        self.log_text = scrolledtext.ScrolledText(
            self.log_tab,
            wrap=tk.WORD,
            font=('Consolas', 10)
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Pulsanti
        btn_frame = ttk.Frame(self.log_tab)
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        clear_btn = ttk.Button(btn_frame, text="Pulisci Log", command=self._clear_log)
        clear_btn.pack(side=tk.LEFT)

        save_btn = ttk.Button(btn_frame, text="Salva Log", command=self._save_log)
        save_btn.pack(side=tk.RIGHT)

    def _log_message(self, message: str, level: str = "INFO"):
        """Aggiunge un messaggio al log."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted = f"[{timestamp}] [{level}] {message}\n"
        self.log_text.insert(tk.END, formatted)
        self.log_text.see(tk.END)

    def _clear_log(self):
        """Pulisce il log."""
        self.log_text.delete(1.0, tk.END)

    def _save_log(self):
        """Salva il log su file."""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            with open(filename, 'w') as f:
                f.write(self.log_text.get(1.0, tk.END))
            messagebox.showinfo("Successo", "Log salvato correttamente!")

    def _load_policies_file(self):
        """Carica policies da file JSON."""
        filename = filedialog.askopenfilename(
            title="Seleziona file JSON policies",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    self.policies_data = json.load(f)
                
                count = len(self.policies_data)
                self.status_var.set(f"Caricate {count} policies da {filename}")
                self._log_message(f"Caricate {count} policies da file: {filename}")
                messagebox.showinfo("Successo", f"Caricate {count} policies!\nOra avvia l'analisi.")
                
            except Exception as e:
                messagebox.showerror("Errore", f"Errore nel caricamento: {str(e)}")
                self._log_message(f"Errore caricamento file: {str(e)}", "ERROR")

    def _load_demo_data(self):
        """Carica dati demo per test."""
        self.policies_data = [
            {
                "id": "POL-001",
                "name": "Baseline Compliance Policy",
                "type": "Compliance",
                "category": "Compliance",
                "lastModified": "2024-01-15T10:30:00Z",
                "assignmentCount": 150,
                "settings": {
                    "password_required": False,
                    "password_min_length": 4,
                    "encryption_required": False,
                    "jailbreak_detection": True
                }
            },
            {
                "id": "POL-002",
                "name": "Windows Security Baseline",
                "type": "Endpoint Protection",
                "category": "Sicurezza",
                "lastModified": "2024-01-10T14:20:00Z",
                "assignmentCount": 200,
                "settings": {
                    "firewall_enabled": True,
                    "defender_real_time": False,
                    "smartscreen_enabled": False,
                    "bitlocker_enabled": True
                }
            },
            {
                "id": "POL-003",
                "name": "Windows Update Policy",
                "type": "Update",
                "category": "Aggiornamenti",
                "lastModified": "2024-01-12T09:00:00Z",
                "assignmentCount": 180,
                "settings": {
                    "deferral_days": 45,
                    "deadline_days": 21,
                    "active_hours": "8:00-18:00"
                }
            },
            {
                "id": "POL-004",
                "name": "App Protection - Office",
                "type": "App Protection",
                "category": "Protezione App",
                "lastModified": "2024-01-08T16:45:00Z",
                "assignmentCount": 300,
                "settings": {
                    "pin_required": False,
                    "data_transfer": "allow",
                    "save_copy_restriction": "allow",
                    "offline_access_limit": 90
                }
            },
            {
                "id": "POL-005",
                "name": "Device Restrictions",
                "type": "Device Restriction",
                "category": "Restrizioni Device",
                "lastModified": "2024-01-05T11:15:00Z",
                "assignmentCount": 120,
                "settings": {
                    "usb_restriction": "allow",
                    "camera_blocked": False,
                    "screen_capture_blocked": True
                }
            }
        ]
        
        self.status_var.set(f"Caricati {len(self.policies_data)} dati demo")
        self._log_message("Caricati dati demo per testing")
        messagebox.showinfo("Demo", "Dati demo caricati!\nClicca 'Avvia Analisi' per procedere.")

    def _run_analysis(self):
        """Avvia l'analisi in background."""
        if not self.policies_data:
            messagebox.showwarning("Attenzione", "Nessuna policy caricata!\nUsa 'Carica Policies' o 'Dati Demo'.")
            return

        self.analyze_btn.config(state=tk.DISABLED)
        self.status_var.set("Analisi in corso...")
        self._log_message("Avvio analisi policies...")

        # Esegui in thread separato
        thread = threading.Thread(target=self._analysis_worker)
        thread.daemon = True
        thread.start()

        # Controlla completamento
        self.root.after(100, self._check_analysis_complete)

    def _analysis_worker(self):
        """Worker per analisi in background."""
        try:
            self.current_report = self.analyzer.analyze_all_policies(self.policies_data)
            self.task_queue.put(('success', None))
        except Exception as e:
            self.task_queue.put(('error', str(e)))

    def _check_analysis_complete(self):
        """Controlla se l'analisi è completata."""
        try:
            while True:
                status, data = self.task_queue.get_nowait()
                
                if status == 'success':
                    self._on_analysis_complete()
                elif status == 'error':
                    messagebox.showerror("Errore", f"Analisi fallita: {data}")
                    self._log_message(f"Errore analisi: {data}", "ERROR")
                    self.analyze_btn.config(state=tk.NORMAL)
                    self.status_var.set("Analisi fallita")
                    
                break
        except queue.Empty:
            self.root.after(100, self._check_analysis_complete)

    def _on_analysis_complete(self):
        """Callback quando analisi è completata."""
        if self.current_report:
            self._update_dashboard()
            self._populate_policies_tree()
            self._populate_recommendations_tree()
            
            self.export_btn.config(state=tk.NORMAL)
            self.analyze_btn.config(state=tk.NORMAL)
            
            critical_count = sum(
                1 for r in self.current_report.top_recommendations 
                if r.severity == SeverityLevel.CRITICAL
            )
            
            self.status_var.set(
                f"Analisi completata! {self.current_report.total_policies} policies, "
                f"{critical_count} critiche"
            )
            self._log_message(
                f"Analisi completata: {self.current_report.total_policies} policies, "
                f"score: {self.current_report.overall_score}/100"
            )

    def _update_dashboard(self):
        """Aggiorna dashboard con risultati."""
        if not self.current_report:
            return

        # Metriche
        self.metrics['total_policies'].config(text=str(self.current_report.total_policies))
        self.metrics['compliant'].config(
            text=str(self.current_report.compliant_policies),
            foreground=self.colors['success']
        )
        self.metrics['non_compliant'].config(
            text=str(self.current_report.non_compliant_policies),
            foreground=self.colors['danger']
        )
        self.metrics['score'].config(
            text=f"{self.current_report.overall_score:.1f}",
            foreground=self.colors['primary']
        )

        critical_count = sum(
            1 for r in self.current_report.top_recommendations 
            if r.severity == SeverityLevel.CRITICAL
        )
        self.metrics['critical'].config(text=str(critical_count))
        self.metrics['recommendations'].config(text=str(len(self.current_report.top_recommendations)))

        # Progress bar
        score = self.current_report.overall_score
        self.score_progress['value'] = score
        self.score_label.config(text=f"Punteggio: {score:.1f}/100")

        # Colora progress bar
        if score >= 80:
            color = self.colors['success']
        elif score >= 60:
            color = self.colors['warning']
        else:
            color = self.colors['danger']
        
        # Grafico categorie
        self._update_category_chart()

    def _update_category_chart(self):
        """Aggiorna grafico a barre per categorie."""
        self.chart_canvas.delete("all")
        
        if not self.current_report:
            return

        summary = self.current_report.summary_by_category
        if not summary:
            return

        categories = list(summary.keys())
        scores = [summary[cat]['avg_score'] for cat in categories]

        # Dimensioni
        width = self.chart_canvas.winfo_width()
        height = self.chart_canvas.winfo_height()
        
        if width < 10 or height < 10:
            return

        bar_width = (width - 100) / len(categories) - 10
        max_height = height - 60

        # Disegna barre
        for i, (cat, score) in enumerate(zip(categories, scores)):
            x1 = 50 + i * (bar_width + 10)
            x2 = x1 + bar_width
            bar_height = (score / 100) * max_height
            y1 = height - 40 - bar_height
            y2 = height - 40

            # Colore in base al punteggio
            if score >= 80:
                color = "#107c10"
            elif score >= 60:
                color = "#ffaa44"
            else:
                color = "#d13438"

            self.chart_canvas.create_rectangle(x1, y1, x2, y2, fill=color, outline='')
            
            # Etichetta
            self.chart_canvas.create_text(
                x1 + bar_width/2, y1 - 10,
                text=f"{score:.0f}",
                font=('Segoe UI', 10, 'bold')
            )
            self.chart_canvas.create_text(
                x1 + bar_width/2, height - 20,
                text=cat[:15],
                font=('Segoe UI', 8),
                angle=45
            )

    def _populate_policies_tree(self):
        """Popola treeview delle policies."""
        # Pulisci
        for item in self.policies_tree.get_children():
            self.policies_tree.delete(item)

        if not self.current_report:
            return

        # Aggiungi
        for analysis in self.current_report.policy_analyses:
            status = "✅ Compliant" if analysis.is_compliant else "⚠️ Non-Compliant"
            status_color = "green" if analysis.is_compliant else "red"
            
            self.policies_tree.insert('', tk.END, iid=analysis.policy_id, values=(
                analysis.policy_id,
                analysis.policy_name,
                analysis.policy_type,
                analysis.category.value,
                status,
                f"{analysis.score:.1f}",
                analysis.issues_found
            ), tags=(status_color,))

        # Configura tag colori
        self.policies_tree.tag_configure('green', foreground='green')
        self.policies_tree.tag_configure('red', foreground='red')

        self._filter_policies()

    def _populate_recommendations_tree(self):
        """Popola treeview delle raccomandazioni."""
        # Pulisci
        for item in self.recs_tree.get_children():
            self.recs_tree.delete(item)

        if not self.current_report:
            return

        # Aggiungi
        for rec in self.current_report.top_recommendations:
            self.recs_tree.insert('', tk.END, iid=rec.id, values=(
                rec.id,
                rec.title[:40],
                rec.severity.value,
                rec.category.value,
                rec.impact[:30]
            ), tags=(rec.severity.value,))

        # Colori per severità
        for severity in SeverityLevel:
            self.recs_tree.tag_configure(
                severity.value,
                foreground=severity.get_color()
            )

        self._filter_recommendations()

    def _filter_policies(self, event=None):
        """Filtra policies in base a ricerca e categoria."""
        search_term = self.filter_var.get().lower()
        category = self.category_filter.get()

        for item in self.policies_tree.get_children():
            values = self.policies_tree.item(item, 'values')
            
            match_search = (
                search_term in values[1].lower() or  # Nome
                search_term in values[0].lower() or  # ID
                search_term in values[3].lower()     # Categoria
            )
            
            match_category = (category == "Tutte" or values[3] == category)

            if match_search and match_category:
                self.policies_tree.item(item, tags=())
            else:
                self.policies_tree.item(item, tags=('hidden',))

        self.policies_tree.tag_configure('hidden', foreground='gray')

    def _filter_recommendations(self, event=None):
        """Filtra raccomandazioni per severità."""
        severity = self.severity_filter.get()

        for item in self.recs_tree.get_children():
            values = self.recs_tree.item(item, 'values')
            
            if severity == "Tutte" or values[2] == severity:
                self.recs_tree.item(item, tags=())
            else:
                self.recs_tree.item(item, tags=('hidden',))

        self.recs_tree.tag_configure('hidden', foreground='gray')

    def _show_policy_details(self, event):
        """Mostra dettagli policy selezionata."""
        selection = self.policies_tree.selection()
        if not selection:
            return

        policy_id = selection[0]
        
        if not self.current_report:
            return

        analysis = next(
            (a for a in self.current_report.policy_analyses if a.policy_id == policy_id),
            None
        )

        if analysis:
            details = f"""
POLICY: {analysis.policy_name}
ID: {analysis.policy_id}
TIPO: {analysis.policy_type}
CATEGORIA: {analysis.category.value}
STATO: {'Compliant' if analysis.is_compliant else 'Non-Compliant'}
SCORE: {analysis.score:.1f}/100
ISSUES: {analysis.issues_found}
ASSEGNATA A: {analysis.assignment_count} devices
ULTIMA MODIFICA: {analysis.last_modified or 'N/A'}

{'='*60}
RACCOMANDAZIONI:
"""
            if analysis.recommendations:
                for rec in analysis.recommendations:
                    details += f"\n• [{rec.severity.value}] {rec.title}"
                    details += f"\n  Attuale: {rec.current_value}"
                    details += f"\n  Raccomandato: {rec.recommended_value}"
                    details += f"\n  Impatto: {rec.impact}\n"
            else:
                details += "\nNessuna raccomandazione critica."

            self.policy_details.delete(1.0, tk.END)
            self.policy_details.insert(tk.END, details)

    def _show_recommendation_details(self, event):
        """Mostra dettagli raccomandazione selezionata."""
        selection = self.recs_tree.selection()
        if not selection:
            return

        rec_id = selection[0]
        
        if not self.current_report:
            return

        rec = next(
            (r for r in self.current_report.top_recommendations if r.id == rec_id),
            None
        )

        if rec:
            details = f"""
RACCOMANDAZIONE: {rec.title}
ID: {rec.id}
SEVERITÀ: {rec.severity.value}
CATEGORIA: {rec.category.value}

DESCRIZIONE:
{rec.description}

VALORE ATTUALE: {rec.current_value}
VALORE RACCOMANDATO: {rec.recommended_value}

IMPATTO:
{rec.impact}

STEPS REMEDIATION:
"""
            for i, step in enumerate(rec.remediation_steps, 1):
                details += f"{i}. {step}\n"

            if rec.reference_links:
                details += "\nRIFERIMENTI:\n"
                for link in rec.reference_links:
                    details += f"• {link}\n"

            self.rec_details.delete(1.0, tk.END)
            self.rec_details.insert(tk.END, details)

    def _export_json(self):
        """Esporta report in JSON."""
        if not self.current_report:
            messagebox.showwarning("Attenzione", "Nessun report da esportare!")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"intune_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )

        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self.current_report.to_dict(), f, indent=2, ensure_ascii=False)
                
                messagebox.showinfo("Successo", f"Report JSON salvato in:\n{filename}")
                self._log_message(f"Report JSON esportato: {filename}")
            except Exception as e:
                messagebox.showerror("Errore", f"Errore nell'esportazione: {str(e)}")

    def _export_html(self):
        """Esporta report in HTML."""
        if not self.current_report:
            messagebox.showwarning("Attenzione", "Nessun report da esportare!")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            initialfile=f"intune_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )

        if filename:
            try:
                html_content = self._generate_html_report()
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                
                messagebox.showinfo("Successo", f"Report HTML salvato in:\n{filename}")
                self._log_message(f"Report HTML esportato: {filename}")
                
                # Chiedi se aprire
                if messagebox.askyesno("Apri report", "Vuoi aprire il report nel browser?"):
                    webbrowser.open(f'file://{os.path.abspath(filename)}')
                    
            except Exception as e:
                messagebox.showerror("Errore", f"Errore nell'esportazione: {str(e)}")

    def _generate_html_report(self) -> str:
        """Genera report HTML."""
        report = self.current_report
        
        html = f"""<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Intune Policy Analysis Report</title>
    <style>
        :root {{
            --primary: #0078d4;
            --success: #107c10;
            --warning: #ffaa44;
            --danger: #d13438;
            --bg: #f5f5f5;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: var(--bg);
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: var(--primary);
            border-bottom: 3px solid var(--primary);
            padding-bottom: 10px;
        }}
        .metrics {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .metric-card {{
            background: linear-gradient(135deg, var(--primary), #005a9e);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .metric-value {{
            font-size: 36px;
            font-weight: bold;
        }}
        .metric-label {{
            font-size: 14px;
            opacity: 0.9;
        }}
        .score-bar {{
            background: #e0e0e0;
            border-radius: 10px;
            height: 30px;
            overflow: hidden;
            margin: 20px 0;
        }}
        .score-fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--danger), var(--warning), var(--success));
            transition: width 0.5s;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: var(--primary);
            color: white;
        }}
        tr:hover {{
            background: #f5f5f5;
        }}
        .severity-CRITICA {{ color: var(--danger); font-weight: bold; }}
        .severity-ALTA {{ color: #d9531e; font-weight: bold; }}
        .severity-MEDIA {{ color: var(--warning); }}
        .severity-BASSA {{ color: #17a2b8; }}
        .severity-INFORMATIVA {{ color: #6c757d; }}
        .compliant {{ color: var(--success); }}
        .non-compliant {{ color: var(--danger); }}
        .section {{
            margin: 40px 0;
        }}
        .recommendation {{
            background: #fff3cd;
            border-left: 4px solid var(--warning);
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }}
        .recommendation.critical {{
            background: #f8d7da;
            border-color: var(--danger);
        }}
        footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Intune Policy Analysis Report</h1>
        <p><strong>Generated:</strong> {datetime.fromisoformat(report.generated_at).strftime('%d/%m/%Y %H:%M:%S')}</p>
        <p><strong>Report ID:</strong> {report.report_id}</p>

        <div class="metrics">
            <div class="metric-card">
                <div class="metric-value">{report.total_policies}</div>
                <div class="metric-label">Total Policies</div>
            </div>
            <div class="metric-card" style="background: linear-gradient(135deg, var(--success), #0c5e0c);">
                <div class="metric-value">{report.compliant_policies}</div>
                <div class="metric-label">Compliant</div>
            </div>
            <div class="metric-card" style="background: linear-gradient(135deg, var(--danger), #9e2a2a);">
                <div class="metric-value">{report.non_compliant_policies}</div>
                <div class="metric-label">Non-Compliant</div>
            </div>
            <div class="metric-card" style="background: linear-gradient(135deg, #666, #333);">
                <div class="metric-value">{report.overall_score:.1f}</div>
                <div class="metric-label">Overall Score</div>
            </div>
        </div>

        <div class="section">
            <h2>📊 Overall Score</h2>
            <div class="score-bar">
                <div class="score-fill" style="width: {report.overall_score}%;"></div>
            </div>
            <p style="text-align: center; font-size: 18px;"><strong>{report.overall_score:.1f}/100</strong></p>
        </div>

        <div class="section">
            <h2>📋 Policies Analysis</h2>
            <table>
                <thead>
                    <tr>
                        <th>Policy Name</th>
                        <th>Type</th>
                        <th>Category</th>
                        <th>Status</th>
                        <th>Score</th>
                        <th>Issues</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        for analysis in report.policy_analyses:
            status_class = "compliant" if analysis.is_compliant else "non-compliant"
            status_icon = "✅" if analysis.is_compliant else "⚠️"
            html += f"""
                    <tr>
                        <td><strong>{analysis.policy_name}</strong></td>
                        <td>{analysis.policy_type}</td>
                        <td>{analysis.category.value}</td>
                        <td class="{status_class}">{status_icon} {'Compliant' if analysis.is_compliant else 'Non-Compliant'}</td>
                        <td>{analysis.score:.1f}</td>
                        <td>{analysis.issues_found}</td>
                    </tr>
"""
        
        html += """
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>💡 Top Recommendations</h2>
"""
        
        for rec in report.top_recommendations:
            severity_class = "critical" if rec.severity == SeverityLevel.CRITICAL else ""
            html += f"""
            <div class="recommendation {severity_class}">
                <h3>[{rec.severity.value}] {rec.title}</h3>
                <p><strong>Description:</strong> {rec.description}</p>
                <p><strong>Current:</strong> {rec.current_value} → <strong>Recommended:</strong> {rec.recommended_value}</p>
                <p><strong>Impact:</strong> {rec.impact}</p>
                <p><strong>Remediation Steps:</strong></p>
                <ol>
"""
                for step in rec.remediation_steps:
                    html += f"                    <li>{step}</li>\n"
                html += """
                </ol>
            </div>
"""
        
        html += f"""
        </div>

        <div class="section">
            <h2>📖 Category Summary</h2>
            <table>
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>Policies</th>
                        <th>Compliant</th>
                        <th>Avg Score</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        for cat, data in report.summary_by_category.items():
            html += f"""
                    <tr>
                        <td><strong>{cat}</strong></td>
                        <td>{data['count']}</td>
                        <td>{data['compliant']}</td>
                        <td>{data['avg_score']:.1f}</td>
                    </tr>
"""
        
        html += f"""
                </tbody>
            </table>
        </div>

        <footer>
            <p>Intune Policy Analyzer - Generated on {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
            <p>Best Practices based on Microsoft Guidelines</p>
        </footer>
    </div>
</body>
</html>
"""
        
        return html

    def _export_recommendations(self):
        """Esporta solo le raccomandazioni."""
        if not self.current_report:
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"recommendations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )

        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("ID,Titolo,Severità,Categoria,Attuale,Raccomandato,Impatto\n")
                    for rec in self.current_report.top_recommendations:
                        f.write(f'"{rec.id}","{rec.title}","{rec.severity.value}",'
                               f'"{rec.category.value}","{rec.current_value}",'
                               f'"{rec.recommended_value}","{rec.impact}"\n')
                
                messagebox.showinfo("Successo", f"Raccomandazioni esportate in:\n{filename}")
            except Exception as e:
                messagebox.showerror("Errore", f"Errore: {str(e)}")

    def _show_dashboard(self):
        """Mostra tab dashboard."""
        self.notebook.select(0)

    def _show_standards(self):
        """Mostra tab standard."""
        self.notebook.select(3)

    def _show_about(self):
        """Mostra informazioni."""
        about_text = """
Intune Policy Analyzer v2.0

Applicazione per l'analisi delle policies 
Microsoft Intune con interfaccia grafica.

Funzionalità:
• Analisi automatica policies
• Rilevamento criticità
• Raccomandazioni basate su best practices
• Report JSON e HTML
• Standard preconfigurati

Sviluppato con Python e Tkinter

© 2024 - Tutti i diritti riservati
        """
        messagebox.showinfo("Informazioni", about_text)

    def _open_docs(self):
        """Apre documentazione online."""
        webbrowser.open("https://docs.microsoft.com/en-us/mem/intune/")


def main():
    """Funzione principale."""
    root = tk.Tk()
    
    # Imposta icona (se disponibile)
    try:
        root.iconbitmap('icon.ico')
    except:
        pass
    
    app = IntuneAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
