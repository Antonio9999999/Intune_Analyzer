#!/usr/bin/env python3
"""
Intune Policy Analyzer
Applicazione per analizzare le policies implementate sui Device in Microsoft Intune,
definendo ottimizzazioni, standard e suggerimenti da applicare.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum


class SeverityLevel(Enum):
    """Livelli di severità per le raccomandazioni."""
    CRITICAL = "CRITICA"
    HIGH = "ALTA"
    MEDIUM = "MEDIA"
    LOW = "BASSA"
    INFO = "INFORMATIVA"


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


class IntunePolicyStandards:
    """
    Definisce gli standard e le best practices per le policies Intune.
    """
    
    # Standard per Compliance Policies
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
            "description": "Lunghezza minima password: almeno 6 caratteri"
        },
        "password_expiration_days": {
            "recommended": 90,
            "maximum": 180,
            "severity": SeverityLevel.MEDIUM,
            "description": "Scadenza password: massimo 90 giorni"
        },
        "encryption_required": {
            "recommended": True,
            "severity": SeverityLevel.CRITICAL,
            "description": "Crittografia del dispositivo deve essere abilitata"
        },
        "jailbreak_detection": {
            "recommended": True,
            "severity": SeverityLevel.CRITICAL,
            "description": "Rilevamento jailbreak/root deve essere attivo"
        },
        "os_minimum_version": {
            "recommended": "latest_minus_2",
            "severity": SeverityLevel.HIGH,
            "description": "Versione OS minima: non più vecchia di 2 versioni major"
        },
        "threat_agent_required": {
            "recommended": True,
            "severity": SeverityLevel.HIGH,
            "description": "Agente di protezione dalle minacce richiesto"
        },
        "secure_boot": {
            "recommended": True,
            "severity": SeverityLevel.MEDIUM,
            "description": "Secure Boot deve essere abilitato"
        }
    }
    
    # Standard per Configuration Profiles - Security
    SECURITY_CONFIG_STANDARDS = {
        "bitlocker_enabled": {
            "recommended": True,
            "severity": SeverityLevel.CRITICAL,
            "description": "BitLocker deve essere abilitato su Windows"
        },
        "filevault_enabled": {
            "recommended": True,
            "severity": SeverityLevel.CRITICAL,
            "description": "FileVault deve essere abilitato su macOS"
        },
        "firewall_enabled": {
            "recommended": True,
            "severity": SeverityLevel.CRITICAL,
            "description": "Firewall deve essere sempre attivo"
        },
        "smart_screen_enabled": {
            "recommended": True,
            "severity": SeverityLevel.HIGH,
            "description": "Microsoft SmartScreen deve essere abilitato"
        },
        "defender_real_time_protection": {
            "recommended": True,
            "severity": SeverityLevel.CRITICAL,
            "description": "Protezione in tempo reale Defender deve essere attiva"
        },
        "defender_cloud_protection": {
            "recommended": True,
            "severity": SeverityLevel.HIGH,
            "description": "Protezione cloud Defender deve essere abilitata"
        },
        "automatic_sample_submission": {
            "recommended": True,
            "severity": SeverityLevel.MEDIUM,
            "description": "Invio automatico campioni a Microsoft consigliato"
        },
        "usb_restriction": {
            "recommended": "read_only",
            "severity": SeverityLevel.MEDIUM,
            "description": "Limitare l'uso di dispositivi USB rimovibili"
        },
        "bluetooth_restriction": {
            "recommended": False,
            "severity": SeverityLevel.LOW,
            "description": "Valutare la disabilitazione di Bluetooth se non necessario"
        },
        "camera_restriction": {
            "recommended": False,
            "severity": SeverityLevel.LOW,
            "description": "Valutare la disabilitazione della camera in ambienti sensibili"
        }
    }
    
    # Standard per Windows Update
    UPDATE_STANDARDS = {
        "update_ring_active": {
            "recommended": True,
            "severity": SeverityLevel.HIGH,
            "description": "Almeno un ring di aggiornamento deve essere configurato"
        },
        "deferral_days_quality": {
            "recommended": 0,
            "maximum": 7,
            "severity": SeverityLevel.MEDIUM,
            "description": "Ritardo aggiornamenti quality: massimo 7 giorni"
        },
        "deferral_days_feature": {
            "recommended": 30,
            "maximum": 90,
            "severity": SeverityLevel.MEDIUM,
            "description": "Ritardo aggiornamenti feature: 30-90 giorni per testing"
        },
        "active_hours_start": {
            "recommended": "08:00",
            "severity": SeverityLevel.LOW,
            "description": "Orario inizio ore lavorative configurato correttamente"
        },
        "active_hours_end": {
            "recommended": "18:00",
            "severity": SeverityLevel.LOW,
            "description": "Orario fine ore lavorative configurato correttamente"
        },
        "deadline_days_quality": {
            "recommended": 7,
            "maximum": 14,
            "severity": SeverityLevel.HIGH,
            "description": "Deadline aggiornamenti quality: massimo 14 giorni"
        },
        "deadline_days_feature": {
            "recommended": 30,
            "maximum": 60,
            "severity": SeverityLevel.HIGH,
            "description": "Deadline aggiornamenti feature: massimo 60 giorni"
        },
        "auto_restart_notification": {
            "recommended": True,
            "severity": SeverityLevel.MEDIUM,
            "description": "Notifica di riavvio automatico deve essere abilitata"
        }
    }
    
    # Standard per Device Restrictions
    DEVICE_RESTRICTION_STANDARDS = {
        "account_modification_blocked": {
            "recommended": True,
            "severity": SeverityLevel.MEDIUM,
            "description": "Bloccare modifica account locali non amministrativi"
        },
        "app_install_from_unknown_sources": {
            "recommended": False,
            "severity": SeverityLevel.HIGH,
            "description": "Bloccare installazione app da fonti sconosciute"
        },
        "developer_mode_blocked": {
            "recommended": True,
            "severity": SeverityLevel.HIGH,
            "description": "Modalità sviluppatore dovrebbe essere bloccata"
        },
        "screen_capture_blocked": {
            "recommended": False,
            "severity": SeverityLevel.LOW,
            "description": "Valutare blocco screenshot in ambienti sensibili"
        },
        "cortana_blocked": {
            "recommended": True,
            "severity": SeverityLevel.MEDIUM,
            "description": "Cortana dovrebbe essere disabilitata per privacy"
        },
        "consumer_apps_blocked": {
            "recommended": True,
            "severity": SeverityLevel.LOW,
            "description": "Bloccare app consumer (Xbox, Store giochi, etc.)"
        }
    }
    
    # Standard per App Protection Policies
    APP_PROTECTION_STANDARDS = {
        "pin_required": {
            "recommended": True,
            "severity": SeverityLevel.HIGH,
            "description": "PIN richiesto per accedere alle app protette"
        },
        "pin_min_length": {
            "recommended": 4,
            "minimum": 4,
            "severity": SeverityLevel.MEDIUM,
            "description": "Lunghezza minima PIN: 4 caratteri"
        },
        "data_transfer_restricted": {
            "recommended": True,
            "severity": SeverityLevel.HIGH,
            "description": "Limitare trasferimento dati tra app"
        },
        "save_copy_blocked": {
            "recommended": True,
            "severity": SeverityLevel.HIGH,
            "description": "Bloccare salvataggio copie dei dati aziendali"
        },
        "print_blocked": {
            "recommended": False,
            "severity": SeverityLevel.LOW,
            "description": "Valutare blocco stampa per dati sensibili"
        },
        "offline_grace_period": {
            "recommended": 720,  # minuti (12 ore)
            "maximum": 1440,
            "severity": SeverityLevel.MEDIUM,
            "description": "Periodo di grazia offline: massimo 24 ore"
        }
    }

    @classmethod
    def get_all_standards(cls) -> Dict[str, Dict]:
        """Restituisce tutti gli standard organizzati per categoria."""
        return {
            "compliance": cls.COMPLIANCE_STANDARDS,
            "security_config": cls.SECURITY_CONFIG_STANDARDS,
            "updates": cls.UPDATE_STANDARDS,
            "device_restrictions": cls.DEVICE_RESTRICTION_STANDARDS,
            "app_protection": cls.APP_PROTECTION_STANDARDS
        }


class IntunePolicyAnalyzer:
    """
    Classe principale per l'analisi delle policies Intune.
    """
    
    def __init__(self, tenant_id: Optional[str] = None, client_id: Optional[str] = None):
        """
        Inizializza l'analizzatore.
        
        Args:
            tenant_id: Azure AD Tenant ID
            client_id: Azure AD Client ID (Application ID)
        """
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.standards = IntunePolicyStandards()
        self.policies_data: Dict[str, Any] = {}
        self.analysis_results: Optional[AnalysisReport] = None
        
    def load_policies_from_file(self, file_path: str) -> bool:
        """
        Carica i dati delle policies da un file JSON.
        
        Args:
            file_path: Percorso del file JSON contenente le policies
            
        Returns:
            True se il caricamento è riuscito, False altrimenti
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                self.policies_data = json.load(f)
            return True
        except FileNotFoundError:
            print(f"Errore: File non trovato: {file_path}")
            return False
        except json.JSONDecodeError as e:
            print(f"Errore: JSON non valido: {e}")
            return False
    
    def load_policies_from_dict(self, policies: Dict[str, Any]) -> None:
        """
        Carica i dati delle policies da un dizionario.
        
        Args:
            policies: Dizionario contenente le policies
        """
        self.policies_data = policies
    
    def _categorize_policy(self, policy_type: str, policy_data: Dict) -> PolicyCategory:
        """Determina la categoria di una policy basandosi sul tipo e sui dati."""
        type_lower = policy_type.lower()
        
        if 'compliance' in type_lower:
            return PolicyCategory.COMPLIANCE
        elif 'configuration' in type_lower or 'settings' in type_lower:
            # Analizza le impostazioni per determinare la sottocategoria
            settings = policy_data.get('settings', [])
            for setting in settings:
                setting_str = str(setting).lower()
                if any(kw in setting_str for kw in ['firewall', 'defender', 'bitlocker', 'encryption']):
                    return PolicyCategory.ENDPOINT_PROTECTION
                elif any(kw in setting_str for kw in ['update', 'windows update']):
                    return PolicyCategory.UPDATE
                elif any(kw in setting_str for kw in ['wifi', 'wireless']):
                    return PolicyCategory.WIFI
                elif any(kw in setting_str for kw in ['vpn']):
                    return PolicyCategory.VPN
                elif any(kw in setting_str for kw in ['email', 'exchange']):
                    return PolicyCategory.EMAIL
                elif any(kw in setting_str for kw in ['certificate', 'cert']):
                    return PolicyCategory.CERTIFICATE
            return PolicyCategory.CONFIGURATION
        elif 'protection' in type_lower and 'app' in type_lower:
            return PolicyCategory.APP_PROTECTION
        elif 'restriction' in type_lower or 'baseline' in type_lower:
            return PolicyCategory.DEVICE_RESTRICTION
        elif 'security' in type_lower:
            return PolicyCategory.SECURITY
        else:
            return PolicyCategory.OTHER
    
    def _analyze_compliance_policy(self, policy: Dict) -> PolicyAnalysis:
        """Analizza una compliance policy."""
        recommendations = []
        issues_count = 0
        score = 100.0
        
        policy_settings = policy.get('settings', {})
        
        # Controlla password required
        if not policy_settings.get('password_required', True):
            issues_count += 1
            score -= 20
            std = self.standards.COMPLIANCE_STANDARDS['password_required']
            recommendations.append(Recommendation(
                id=f"COMP_{policy.get('id', 'unknown')}_PWD_REQ",
                title="Password non obbligatoria",
                description=std['description'],
                severity=std['severity'],
                category=PolicyCategory.COMPLIANCE,
                current_value=False,
                recommended_value=True,
                impact="I dispositivi possono essere accessibili senza password, aumentando il rischio di accesso non autorizzato.",
                remediation_steps=[
                    "Aprire Microsoft Endpoint Manager",
                    "Navigare su Dispositivi > Criteri di conformità",
                    "Selezionare la policy",
                    "Abilitare l'impostazione 'Password richiesta'",
                    "Salvare e assegnare la policy"
                ],
                reference_links=[
                    "https://docs.microsoft.com/en-us/mem/intune/protect/compliance-policy-create-windows"
                ]
            ))
        
        # Controlla lunghezza password
        pwd_length = policy_settings.get('password_minimum_length', 0)
        std_pwd_len = self.standards.COMPLIANCE_STANDARDS['password_min_length']
        if pwd_length < std_pwd_len['minimum']:
            issues_count += 1
            score -= 15
            recommendations.append(Recommendation(
                id=f"COMP_{policy.get('id', 'unknown')}_PWD_LEN",
                title="Lunghezza password insufficiente",
                description=std_pwd_len['description'],
                severity=std_pwd_len['severity'],
                category=PolicyCategory.COMPLIANCE,
                current_value=pwd_length,
                recommended_value=std_pwd_len['recommended'],
                impact="Password corte sono più vulnerabili ad attacchi brute-force.",
                remediation_steps=[
                    "Aumentare la lunghezza minima della password a almeno 6 caratteri",
                    "Considerare l'uso di passphrase per maggiore sicurezza"
                ]
            ))
        
        # Controlla encryption
        if not policy_settings.get('require_encryption', True):
            issues_count += 1
            score -= 20
            std = self.standards.COMPLIANCE_STANDARDS['encryption_required']
            recommendations.append(Recommendation(
                id=f"COMP_{policy.get('id', 'unknown')}_ENC",
                title="Crittografia non richiesta",
                description=std['description'],
                severity=std['severity'],
                category=PolicyCategory.COMPLIANCE,
                current_value=False,
                recommended_value=True,
                impact="I dati sui dispositivi potrebbero essere accessibili se il dispositivo viene perso o rubato.",
                remediation_steps=[
                    "Abilitare il requisito di crittografia nella policy di conformità",
                    "Verificare che BitLocker/FileVault siano configurati"
                ]
            ))
        
        # Controlla jailbreak detection
        if not policy_settings.get('jailbroken_orRooted_device_blocked', True):
            issues_count += 1
            score -= 15
            std = self.standards.COMPLIANCE_STANDARDS['jailbreak_detection']
            recommendations.append(Recommendation(
                id=f"COMP_{policy.get('id', 'unknown')}_JB",
                title="Rilevamento jailbreak/root disabilitato",
                description=std['description'],
                severity=std['severity'],
                category=PolicyCategory.COMPLIANCE,
                current_value=False,
                recommended_value=True,
                impact="Dispositivi compromessi potrebbero accedere alle risorse aziendali.",
                remediation_steps=[
                    "Abilitare il blocco per dispositivi jailbroken/rootati",
                    "Configurare azioni correttive per dispositivi non conformi"
                ]
            ))
        
        return PolicyAnalysis(
            policy_id=policy.get('id', 'unknown'),
            policy_name=policy.get('displayName', policy.get('name', 'Unknown')),
            policy_type='CompliancePolicy',
            category=PolicyCategory.COMPLIANCE,
            is_compliant=(issues_count == 0),
            issues_found=issues_count,
            recommendations=recommendations,
            score=max(0, score),
            last_modified=policy.get('lastModifiedDateTime'),
            assignment_count=len(policy.get('assignments', []))
        )
    
    def _analyze_security_config(self, policy: Dict) -> PolicyAnalysis:
        """Analizza una configuration profile di sicurezza."""
        recommendations = []
        issues_count = 0
        score = 100.0
        
        settings = policy.get('settings', [])
        settings_dict = {}
        
        # Converte le impostazioni in un dizionario per easier lookup
        for setting in settings:
            if isinstance(setting, dict):
                key = setting.get('id', str(setting))
                value = setting.get('value', setting.get('settingValue'))
                settings_dict[key] = value
        
        settings_str = str(settings).lower()
        
        # Controlla firewall
        if 'firewall' in settings_str:
            if 'disable' in settings_str or 'false' in settings_str:
                issues_count += 1
                score -= 20
                std = self.standards.SECURITY_CONFIG_STANDARDS['firewall_enabled']
                recommendations.append(Recommendation(
                    id=f"SEC_{policy.get('id', 'unknown')}_FW",
                    title="Firewall potenzialmente disabilitato",
                    description=std['description'],
                    severity=std['severity'],
                    category=PolicyCategory.ENDPOINT_PROTECTION,
                    current_value="Possibilmente disabilitato",
                    recommended_value="Abilitato",
                    impact="Senza firewall, il dispositivo è vulnerabile ad attacchi di rete.",
                    remediation_steps=[
                        "Verificare le impostazioni del firewall nella configuration profile",
                        "Assicurarsi che il firewall sia abilitato per tutti i profili di rete",
                        "Configurare regole appropriate per il traffico in entrata/uscita"
                    ]
                ))
        
        # Controlla Defender real-time protection
        if 'defender' in settings_str or 'antimalware' in settings_str:
            if 'real.time' in settings_str and ('disable' in settings_str or 'false' in settings_str):
                issues_count += 1
                score -= 25
                std = self.standards.SECURITY_CONFIG_STANDARDS['defender_real_time_protection']
                recommendations.append(Recommendation(
                    id=f"SEC_{policy.get('id', 'unknown')}_DEF_RTP",
                    title="Protezione in tempo reale Defender disabilitata",
                    description=std['description'],
                    severity=std['severity'],
                    category=PolicyCategory.ENDPOINT_PROTECTION,
                    current_value="Disabilitato",
                    recommended_value="Abilitato",
                    impact="Il dispositivo non è protetto contro minacce in tempo reale.",
                    remediation_steps=[
                        "Abilitare la protezione in tempo reale di Microsoft Defender",
                        "Verificare che non ci siano esclusioni eccessive",
                        "Monitorare lo stato di protezione tramite portale Intune"
                    ]
                ))
        
        # Controlla BitLocker
        if 'bitlocker' in settings_str:
            if 'disable' in settings_str or 'false' in settings_str:
                issues_count += 1
                score -= 20
                std = self.standards.SECURITY_CONFIG_STANDARDS['bitlocker_enabled']
                recommendations.append(Recommendation(
                    id=f"SEC_{policy.get('id', 'unknown')}_BL",
                    title="BitLocker potenzialmente disabilitato",
                    description=std['description'],
                    severity=std['severity'],
                    category=PolicyCategory.ENDPOINT_PROTECTION,
                    current_value="Possibilmente disabilitato",
                    recommended_value="Abilitato",
                    impact="I dati sul disco potrebbero essere accessibili se il dispositivo viene rubato.",
                    remediation_steps=[
                        "Abilitare BitLocker con crittografia XTS-AES 128 o 256 bit",
                        "Configurare il recupero della chiave in Azure AD",
                        "Richiedere autenticazione all'avvio"
                    ]
                ))
        
        # Controlla SmartScreen
        if 'smartscreen' in settings_str:
            if 'disable' in settings_str or 'false' in settings_str:
                issues_count += 1
                score -= 15
                std = self.standards.SECURITY_CONFIG_STANDARDS['smart_screen_enabled']
                recommendations.append(Recommendation(
                    id=f"SEC_{policy.get('id', 'unknown')}_SS",
                    title="SmartScreen disabilitato",
                    description=std['description'],
                    severity=std['severity'],
                    category=PolicyCategory.ENDPOINT_PROTECTION,
                    current_value="Disabilitato",
                    recommended_value="Abilitato",
                    impact="Maggiore rischio di phishing e download di malware.",
                    remediation_steps=[
                        "Abilitare Microsoft SmartScreen per Explorer e Edge",
                        "Configurare il comportamento come 'Warn and prevent bypass'"
                    ]
                ))
        
        return PolicyAnalysis(
            policy_id=policy.get('id', 'unknown'),
            policy_name=policy.get('displayName', policy.get('name', 'Unknown')),
            policy_type=policy.get('@odata.type', 'ConfigurationProfile'),
            category=PolicyCategory.ENDPOINT_PROTECTION,
            is_compliant=(issues_count == 0),
            issues_found=issues_count,
            recommendations=recommendations,
            score=max(0, score),
            last_modified=policy.get('lastModifiedDateTime'),
            assignment_count=len(policy.get('assignments', []))
        )
    
    def _analyze_update_policy(self, policy: Dict) -> PolicyAnalysis:
        """Analizza una policy di Windows Update."""
        recommendations = []
        issues_count = 0
        score = 100.0
        
        settings = policy.get('settings', [])
        settings_str = str(settings).lower()
        
        # Controlla deferral days
        if 'deferral' in settings_str:
            # Cerca valori numerici nelle impostazioni
            import re
            numbers = re.findall(r'\d+', settings_str)
            if numbers:
                max_deferral = max(int(n) for n in numbers if int(n) > 7)
                if max_deferral > 30:
                    issues_count += 1
                    score -= 15
                    std = self.standards.UPDATE_STANDARDS['deferral_days_feature']
                    recommendations.append(Recommendation(
                        id=f"UPD_{policy.get('id', 'unknown')}_DEF",
                        title="Giorni di rinvio aggiornamenti eccessivi",
                        description=std['description'],
                        severity=std['severity'],
                        category=PolicyCategory.UPDATE,
                        current_value=f"{max_deferral} giorni",
                        recommended_value=f"{std['recommended']} giorni",
                        impact="Ritardi eccessivi nell'applicazione degli aggiornamenti aumentano la superficie di attacco.",
                        remediation_steps=[
                            "Ridurre i giorni di deferral per gli aggiornamenti feature a 30-90 giorni",
                            "Ridurre i giorni di deferral per gli aggiornamenti quality a 0-7 giorni",
                            "Implementare anelli di aggiornamento per testing graduale"
                        ]
                    ))
        
        # Controlla deadline
        if 'deadline' in settings_str:
            import re
            numbers = re.findall(r'\d+', settings_str)
            if numbers:
                max_deadline = max(int(n) for n in numbers if int(n) > 14)
                if max_deadline > 60:
                    issues_count += 1
                    score -= 15
                    std = self.standards.UPDATE_STANDARDS['deadline_days_feature']
                    recommendations.append(Recommendation(
                        id=f"UPD_{policy.get('id', 'unknown')}_DEAD",
                        title="Deadline aggiornamenti troppo lunghe",
                        description=std['description'],
                        severity=std['severity'],
                        category=PolicyCategory.UPDATE,
                        current_value=f"{max_deadline} giorni",
                        recommended_value=f"{std['recommended']} giorni",
                        impact="Tempo eccessivo prima dell'applicazione forzata degli aggiornamenti.",
                        remediation_steps=[
                            "Impostare deadline di 7 giorni per aggiornamenti quality",
                            "Impostare deadline di 30 giorni per aggiornamenti feature",
                            "Configurare notifiche appropriate per gli utenti"
                        ]
                    ))
        
        return PolicyAnalysis(
            policy_id=policy.get('id', 'unknown'),
            policy_name=policy.get('displayName', policy.get('name', 'Unknown')),
            policy_type=policy.get('@odata.type', 'UpdateRing'),
            category=PolicyCategory.UPDATE,
            is_compliant=(issues_count == 0),
            issues_found=issues_count,
            recommendations=recommendations,
            score=max(0, score),
            last_modified=policy.get('lastModifiedDateTime'),
            assignment_count=len(policy.get('assignments', []))
        )
    
    def _analyze_app_protection_policy(self, policy: Dict) -> PolicyAnalysis:
        """Analizza una app protection policy."""
        recommendations = []
        issues_count = 0
        score = 100.0
        
        settings = policy.get('settings', {})
        
        # Controlla PIN required
        if not settings.get('pin_required', True):
            issues_count += 1
            score -= 20
            std = self.standards.APP_PROTECTION_STANDARDS['pin_required']
            recommendations.append(Recommendation(
                id=f"APP_{policy.get('id', 'unknown')}_PIN",
                title="PIN non richiesto per app protette",
                description=std['description'],
                severity=std['severity'],
                category=PolicyCategory.APP_PROTECTION,
                current_value=False,
                recommended_value=True,
                impact="Accesso non autorizzato alle app aziendali se il dispositivo è sbloccato.",
                remediation_steps=[
                    "Abilitare il requisito PIN per le app protette",
                    "Configurare timeout PIN appropriato",
                    "Considerare biometrici come alternativa"
                ]
            ))
        
        # Controlla data transfer restrictions
        if not settings.get('data_transfer_blocked', False):
            issues_count += 1
            score -= 15
            std = self.standards.APP_PROTECTION_STANDARDS['data_transfer_restricted']
            recommendations.append(Recommendation(
                id=f"APP_{policy.get('id', 'unknown')}_DATA",
                title="Trasferimento dati non limitato",
                description=std['description'],
                severity=std['severity'],
                category=PolicyCategory.APP_PROTECTION,
                current_value="Non limitato",
                recommended_value="Limitato alle app gestite",
                impact="I dati aziendali potrebbero essere copiati in app personali non sicure.",
                remediation_steps=[
                    "Limitare il trasferimento dati alle sole app gestite",
                    "Configurare eccezioni per app approvate",
                    "Educare gli utenti sulle policy di trasferimento dati"
                ]
            ))
        
        # Controlla save copy
        if not settings.get('save_copy_blocked', False):
            issues_count += 1
            score -= 15
            std = self.standards.APP_PROTECTION_STANDARDS['save_copy_blocked']
            recommendations.append(Recommendation(
                id=f"APP_{policy.get('id', 'unknown')}_SAVE",
                title="Salvataggio copie non bloccato",
                description=std['description'],
                severity=std['severity'],
                category=PolicyCategory.APP_PROTECTION,
                current_value="Permesso",
                recommended_value="Bloccato",
                impact="Gli utenti possono salvare copie locali di dati aziendali sensibili.",
                remediation_steps=[
                    "Bloccare il salvataggio di copie dei dati aziendali",
                    "Permettere il salvataggio solo in posizioni approvate (OneDrive, SharePoint)",
                    "Configurare policy di retention appropriate"
                ]
            ))
        
        return PolicyAnalysis(
            policy_id=policy.get('id', 'unknown'),
            policy_name=policy.get('displayName', policy.get('name', 'Unknown')),
            policy_type=policy.get('@odata.type', 'AppProtectionPolicy'),
            category=PolicyCategory.APP_PROTECTION,
            is_compliant=(issues_count == 0),
            issues_found=issues_count,
            recommendations=recommendations,
            score=max(0, score),
            last_modified=policy.get('lastModifiedDateTime'),
            assignment_count=len(policy.get('assignments', []))
        )
    
    def analyze_policy(self, policy: Dict) -> PolicyAnalysis:
        """
        Analizza una singola policy e restituisce i risultati.
        
        Args:
            policy: Dizionario contenente i dati della policy
            
        Returns:
            PolicyAnalysis con i risultati dell'analisi
        """
        policy_type = policy.get('@odata.type', policy.get('type', 'Unknown'))
        category = self._categorize_policy(policy_type, policy)
        
        # Delega l'analisi specifica in base alla categoria
        if category == PolicyCategory.COMPLIANCE:
            return self._analyze_compliance_policy(policy)
        elif category in [PolicyCategory.ENDPOINT_PROTECTION, PolicyCategory.SECURITY]:
            return self._analyze_security_config(policy)
        elif category == PolicyCategory.UPDATE:
            return self._analyze_update_policy(policy)
        elif category == PolicyCategory.APP_PROTECTION:
            return self._analyze_app_protection_policy(policy)
        else:
            # Analisi generica per altre categorie
            return PolicyAnalysis(
                policy_id=policy.get('id', 'unknown'),
                policy_name=policy.get('displayName', policy.get('name', 'Unknown')),
                policy_type=policy_type,
                category=category,
                is_compliant=True,
                issues_found=0,
                recommendations=[],
                score=100.0,
                last_modified=policy.get('lastModifiedDateTime'),
                assignment_count=len(policy.get('assignments', []))
            )
    
    def run_analysis(self) -> AnalysisReport:
        """
        Esegue l'analisi completa di tutte le policies caricate.
        
        Returns:
            AnalysisReport con i risultati completi
        """
        if not self.policies_data:
            raise ValueError("Nessuna policy caricata. Usare load_policies_from_file o load_policies_from_dict.")
        
        all_recommendations = []
        policy_analyses = []
        category_stats = {}
        
        # Ottieni la lista delle policies
        policies_list = self.policies_data.get('policies', self.policies_data.get('value', [self.policies_data]))
        
        if not isinstance(policies_list, list):
            policies_list = [policies_list]
        
        # Analizza ogni policy
        for policy in policies_list:
            analysis = self.analyze_policy(policy)
            policy_analyses.append(analysis)
            all_recommendations.extend(analysis.recommendations)
            
            # Aggiorna statistiche per categoria
            cat_name = analysis.category.value
            if cat_name not in category_stats:
                category_stats[cat_name] = {
                    'total': 0,
                    'compliant': 0,
                    'non_compliant': 0,
                    'avg_score': 0,
                    'total_issues': 0
                }
            
            category_stats[cat_name]['total'] += 1
            if analysis.is_compliant:
                category_stats[cat_name]['compliant'] += 1
            else:
                category_stats[cat_name]['non_compliant'] += 1
            category_stats[cat_name]['total_issues'] += analysis.issues_found
        
        # Calcola medie per categoria
        for cat_name, stats in category_stats.items():
            cat_policies = [p for p in policy_analyses if p.category.value == cat_name]
            if cat_policies:
                stats['avg_score'] = sum(p.score for p in cat_policies) / len(cat_policies)
        
        # Calcola metriche globali
        total_policies = len(policy_analyses)
        compliant_policies = sum(1 for p in policy_analyses if p.is_compliant)
        non_compliant_policies = total_policies - compliant_policies
        overall_score = (sum(p.score for p in policy_analyses) / total_policies) if total_policies > 0 else 0
        
        # Ordina raccomandazioni per severità
        severity_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4
        }
        all_recommendations.sort(key=lambda x: severity_order[x.severity])
        
        # Prendi le top 10 raccomandazioni
        top_recommendations = all_recommendations[:10]
        
        # Crea il report
        report = AnalysisReport(
            report_id=f"RPT_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            generated_at=datetime.now().isoformat(),
            total_policies=total_policies,
            compliant_policies=compliant_policies,
            non_compliant_policies=non_compliant_policies,
            overall_score=round(overall_score, 2),
            policy_analyses=policy_analyses,
            summary_by_category=category_stats,
            top_recommendations=top_recommendations
        )
        
        self.analysis_results = report
        return report
    
    def export_report_json(self, output_path: str) -> bool:
        """
        Esporta il report in formato JSON.
        
        Args:
            output_path: Percorso del file di output
            
        Returns:
            True se l'esportazione è riuscita
        """
        if not self.analysis_results:
            raise ValueError("Nessun report disponibile. Eseguire prima run_analysis().")
        
        # Converte il report in un dizionario serializzabile
        report_dict = {
            'report_id': self.analysis_results.report_id,
            'generated_at': self.analysis_results.generated_at,
            'summary': {
                'total_policies': self.analysis_results.total_policies,
                'compliant_policies': self.analysis_results.compliant_policies,
                'non_compliant_policies': self.analysis_results.non_compliant_policies,
                'overall_score': self.analysis_results.overall_score
            },
            'category_summary': self.analysis_results.summary_by_category,
            'top_recommendations': [
                {
                    'id': rec.id,
                    'title': rec.title,
                    'severity': rec.severity.value,
                    'category': rec.category.value,
                    'description': rec.description,
                    'current_value': rec.current_value,
                    'recommended_value': rec.recommended_value,
                    'impact': rec.impact,
                    'remediation_steps': rec.remediation_steps
                }
                for rec in self.analysis_results.top_recommendations
            ],
            'policy_details': [
                {
                    'policy_id': pa.policy_id,
                    'policy_name': pa.policy_name,
                    'category': pa.category.value,
                    'is_compliant': pa.is_compliant,
                    'score': pa.score,
                    'issues_found': pa.issues_found,
                    'recommendations_count': len(pa.recommendations)
                }
                for pa in self.analysis_results.policy_analyses
            ]
        }
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_dict, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Errore durante l'esportazione: {e}")
            return False
    
    def export_report_html(self, output_path: str) -> bool:
        """
        Esporta il report in formato HTML.
        
        Args:
            output_path: Percorso del file HTML di output
            
        Returns:
            True se l'esportazione è riuscita
        """
        if not self.analysis_results:
            raise ValueError("Nessun report disponibile. Eseguire prima run_analysis().")
        
        html_content = f"""<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Report Analisi Policies Intune - {self.analysis_results.report_id}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #0078d4;
            border-bottom: 3px solid #0078d4;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #242424;
            margin-top: 30px;
        }}
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .card.success {{
            background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
        }}
        .card.warning {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }}
        .card.info {{
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }}
        .card-value {{
            font-size: 2.5em;
            font-weight: bold;
        }}
        .card-label {{
            font-size: 0.9em;
            opacity: 0.9;
        }}
        .score-display {{
            font-size: 3em;
            font-weight: bold;
            color: #0078d4;
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
            background-color: #0078d4;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .severity-CRITICA {{
            color: #d32f2f;
            font-weight: bold;
        }}
        .severity-ALTA {{
            color: #f57c00;
            font-weight: bold;
        }}
        .severity-MEDIA {{
            color: #fbc02d;
            font-weight: bold;
        }}
        .severity-BASSA {{
            color: #388e3c;
        }}
        .severity-INFORMATIVA {{
            color: #1976d2;
        }}
        .status-compliant {{
            color: #388e3c;
            font-weight: bold;
        }}
        .status-non-compliant {{
            color: #d32f2f;
            font-weight: bold;
        }}
        .recommendation {{
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }}
        .recommendation.critical {{
            background-color: #f8d7da;
            border-left-color: #dc3545;
        }}
        .recommendation.high {{
            background-color: #fff3cd;
            border-left-color: #fd7e14;
        }}
        .recommendation.medium {{
            background-color: #fff3cd;
            border-left-color: #ffc107;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .badge-category {{
            background-color: #e3f2fd;
            color: #1976d2;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 Report Analisi Policies Intune</h1>
        <p><strong>ID Report:</strong> {self.analysis_results.report_id}</p>
        <p><strong>Generato:</strong> {self.analysis_results.generated_at}</p>
        
        <h2>Riepilogo Generale</h2>
        <div class="summary-cards">
            <div class="card info">
                <div class="card-value">{self.analysis_results.total_policies}</div>
                <div class="card-label">Totale Policies</div>
            </div>
            <div class="card success">
                <div class="card-value">{self.analysis_results.compliant_policies}</div>
                <div class="card-label">Conformi</div>
            </div>
            <div class="card warning">
                <div class="card-value">{self.analysis_results.non_compliant_policies}</div>
                <div class="card-label">Non Conformi</div>
            </div>
            <div class="card">
                <div class="card-value">{self.analysis_results.overall_score}</div>
                <div class="card-label">Punteggio Medio</div>
            </div>
        </div>
        
        <h2>Raccomandazioni Prioritarie</h2>
"""
        
        # Aggiungi le raccomandazioni
        for rec in self.analysis_results.top_recommendations:
            severity_class = rec.severity.value.lower()
            html_content += f"""
        <div class="recommendation {severity_class}">
            <h3>[{rec.severity.value}] {rec.title}</h3>
            <p><strong>Categoria:</strong> {rec.category.value}</p>
            <p><strong>Descrizione:</strong> {rec.description}</p>
            <p><strong>Valore Attuale:</strong> {rec.current_value}</p>
            <p><strong>Valore Raccomandato:</strong> {rec.recommended_value}</p>
            <p><strong>Impatto:</strong> {rec.impact}</p>
            <p><strong>Azioni Correttive:</strong></p>
            <ol>
"""
            for step in rec.remediation_steps:
                html_content += f"                <li>{step}</li>\n"
            html_content += """            </ol>
        </div>
"""
        
        # Tabella dettaglio policies
        html_content += """
        <h2>Dettaglio Policies</h2>
        <table>
            <thead>
                <tr>
                    <th>Nome Policy</th>
                    <th>Categoria</th>
                    <th>Stato</th>
                    <th>Punteggio</th>
                    <th>Problemi</th>
                    <th>Raccomandazioni</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for pa in self.analysis_results.policy_analyses:
            status_class = "status-compliant" if pa.is_compliant else "status-non-compliant"
            status_text = "Conforme" if pa.is_compliant else "Non Conforme"
            html_content += f"""
                <tr>
                    <td>{pa.policy_name}</td>
                    <td><span class="badge badge-category">{pa.category.value}</span></td>
                    <td class="{status_class}">{status_text}</td>
                    <td>{pa.score}</td>
                    <td>{pa.issues_found}</td>
                    <td>{len(pa.recommendations)}</td>
                </tr>
"""
        
        html_content += """
            </tbody>
        </table>
        
        <h2>Statistiche per Categoria</h2>
        <table>
            <thead>
                <tr>
                    <th>Categoria</th>
                    <th>Totale</th>
                    <th>Conformi</th>
                    <th>Non Conformi</th>
                    <th>Punteggio Medio</th>
                    <th>Totale Problemi</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for cat_name, stats in self.analysis_results.summary_by_category.items():
            html_content += f"""
                <tr>
                    <td>{cat_name}</td>
                    <td>{stats['total']}</td>
                    <td>{stats['compliant']}</td>
                    <td>{stats['non_compliant']}</td>
                    <td>{stats['avg_score']:.2f}</td>
                    <td>{stats['total_issues']}</td>
                </tr>
"""
        
        html_content += f"""
            </tbody>
        </table>
        
        <div class="footer">
            <p>Report generato automaticamente da Intune Policy Analyzer</p>
            <p>Per ulteriori informazioni consultare la documentazione Microsoft Intune</p>
        </div>
    </div>
</body>
</html>
"""
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return True
        except Exception as e:
            print(f"Errore durante l'esportazione HTML: {e}")
            return False
    
    def print_summary(self) -> None:
        """Stampa un riepilogo testuale del report."""
        if not self.analysis_results:
            print("Nessun report disponibile. Eseguire prima run_analysis().")
            return
        
        print("\n" + "="*80)
        print("📊 REPORT ANALISI POLICIES INTUNE")
        print("="*80)
        print(f"ID Report: {self.analysis_results.report_id}")
        print(f"Generato: {self.analysis_results.generated_at}")
        print("-"*80)
        print("RIEPILOGO GENERALE")
        print("-"*80)
        print(f"  Totale Policies:        {self.analysis_results.total_policies}")
        print(f"  Policies Conformi:      {self.analysis_results.compliant_policies}")
        print(f"  Policies Non Conformi:  {self.analysis_results.non_compliant_policies}")
        print(f"  Punteggio Complessivo:  {self.analysis_results.overall_score}/100")
        print("-"*80)
        
        print("\nSTATISTICHE PER CATEGORIA")
        print("-"*80)
        for cat_name, stats in self.analysis_results.summary_by_category.items():
            print(f"\n  {cat_name}:")
            print(f"    Totale: {stats['total']} | Conformi: {stats['compliant']} | Non Conformi: {stats['non_compliant']}")
            print(f"    Punteggio Medio: {stats['avg_score']:.2f} | Problemi Totali: {stats['total_issues']}")
        
        print("\n" + "="*80)
        print("🔴 RACCOMANDAZIONI PRIORITARIE")
        print("="*80)
        
        for i, rec in enumerate(self.analysis_results.top_recommendations, 1):
            print(f"\n{i}. [{rec.severity.value}] {rec.title}")
            print(f"   Categoria: {rec.category.value}")
            print(f"   Descrizione: {rec.description}")
            print(f"   Valore Attuale: {rec.current_value}")
            print(f"   Valore Raccomandato: {rec.recommended_value}")
            print(f"   Impatto: {rec.impact}")
            print(f"   Azioni Correttive:")
            for step in rec.remediation_steps:
                print(f"     - {step}")
        
        print("\n" + "="*80)
        print("Per esportare il report completo usare:")
        print("  - export_report_json('report.json')")
        print("  - export_report_html('report.html')")
        print("="*80 + "\n")


def create_sample_data() -> Dict[str, Any]:
    """
    Crea dati di esempio per dimostrare le funzionalità dell'applicazione.
    
    Returns:
        Dizionario con policies di esempio
    """
    return {
        "policies": [
            {
                "id": "comp-001",
                "displayName": "Windows 10/11 Compliance Policy",
                "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
                "passwordRequired": False,
                "passwordMinimumLength": 4,
                "requireEncryption": False,
                "jailbrokenOrRootedDeviceBlocked": True,
                "lastModifiedDateTime": "2024-01-15T10:30:00Z",
                "assignments": [{"target": {"groupId": "group-001"}}],
                "settings": {
                    "password_required": False,
                    "password_minimum_length": 4,
                    "require_encryption": False,
                    "jailbrokenOrRooted_device_blocked": True
                }
            },
            {
                "id": "sec-001",
                "displayName": "Windows Security Baseline",
                "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
                "lastModifiedDateTime": "2024-01-20T14:45:00Z",
                "assignments": [{"target": {"groupId": "group-001"}}, {"target": {"groupId": "group-002"}}],
                "settings": [
                    {"id": "firewall_state", "value": "enabled"},
                    {"id": "defender_realtime_protection", "value": "true"},
                    {"id": "bitlocker_encryption", "value": "enabled"},
                    {"id": "smartscreen_enabled", "value": "true"}
                ]
            },
            {
                "id": "upd-001",
                "displayName": "Windows Update Ring - Production",
                "@odata.type": "#microsoft.graph.windowsUpdateForBusinessConfiguration",
                "lastModifiedDateTime": "2024-02-01T09:00:00Z",
                "assignments": [{"target": {"groupId": "group-001"}}],
                "settings": [
                    {"id": "quality_deferral_days", "value": "5"},
                    {"id": "feature_deferral_days", "value": "45"},
                    {"id": "quality_deadline_days", "value": "10"},
                    {"id": "feature_deadline_days", "value": "45"}
                ]
            },
            {
                "id": "app-001",
                "displayName": "Office Apps Protection Policy",
                "@odata.type": "#microsoft.graph.iosManagedAppProtection",
                "lastModifiedDateTime": "2024-01-25T16:20:00Z",
                "assignments": [{"target": {"groupId": "group-003"}}],
                "settings": {
                    "pin_required": True,
                    "pin_minimum_length": 4,
                    "data_transfer_blocked": True,
                    "save_copy_blocked": False
                }
            },
            {
                "id": "sec-002",
                "displayName": "Endpoint Protection Configuration",
                "@odata.type": "#microsoft.graph.windows10EndpointProtectionConfiguration",
                "lastModifiedDateTime": "2024-02-05T11:15:00Z",
                "assignments": [{"target": {"groupId": "group-001"}}],
                "settings": [
                    {"id": "firewall_rules", "value": "configured"},
                    {"id": "defender_cloud_protection", "value": "enabled"},
                    {"id": "attack_surface_reduction", "value": "enabled"}
                ]
            }
        ]
    }


def main():
    """Funzione principale per dimostrare l'utilizzo dell'applicazione."""
    print("\n" + "="*80)
    print("🚀 INTUNE POLICY ANALYZER")
    print("   Analisi delle policies con ottimizzazioni, standard e suggerimenti")
    print("="*80 + "\n")
    
    # Inizializza l'analizzatore
    analyzer = IntunePolicyAnalyzer()
    
    # Carica dati di esempio
    print("📥 Caricamento dati di esempio...")
    sample_data = create_sample_data()
    analyzer.load_policies_from_dict(sample_data)
    
    # Esegui l'analisi
    print("🔍 Esecuzione analisi policies...")
    report = analyzer.run_analysis()
    
    # Stampa il riepilogo
    analyzer.print_summary()
    
    # Esporta i report
    print("\n💾 Esportazione report...")
    
    if analyzer.export_report_json("intune_analysis_report.json"):
        print("✅ Report JSON esportato: intune_analysis_report.json")
    
    if analyzer.export_report_html("intune_analysis_report.html"):
        print("✅ Report HTML esportato: intune_analysis_report.html")
    
    print("\n✨ Analisi completata con successo!")
    print("="*80 + "\n")


if __name__ == "__main__":
    main()
