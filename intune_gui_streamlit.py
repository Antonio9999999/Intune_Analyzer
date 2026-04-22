import streamlit as st
import json
import os
import pandas as pd
from datetime import datetime

# Import del connettore e dell'analizzatore (assumendo che esistano o creando logica inline)
# Per semplicità in questo snippet, integriamo la logica di analisi direttamente o importiamo se esistono
try:
    from intune_connector import IntuneDataCollector
    CONNECTOR_AVAILABLE = True
except ImportError:
    CONNECTOR_AVAILABLE = False

try:
    # Assumiamo esista un modulo di analisi separato o lo integriamo
    # Per ora usiamo una logica semplificata inline per la demo
    ANALYZER_AVAILABLE = False 
except ImportError:
    ANALYZER_AVAILABLE = False

st.set_page_config(page_title="Intune Policy Analyzer Pro", layout="wide", page_icon="🛡️")

# CSS Personalizzato
st.markdown("""
<style>
    .metric-card {background-color: #f0f2f6; padding: 20px; border-radius: 10px; border-left: 5px solid #0078D4;}
    .critical {border-left-color: #d93025;}
    .high {border-left-color: #ea4335;}
    .medium {border-left-color: #fbbc04;}
    .low {border-left-color: #34a853;}
    h1, h2, h3 {color: #0078D4;}
    .stButton>button {width: 100%; background-color: #0078D4; color: white;}
</style>
""", unsafe_allow_html=True)

def load_data():
    if os.path.exists("intune_real_data.json"):
        with open("intune_real_data.json", "r") as f:
            return json.load(f)
    return None

def analyze_policies_simple(data):
    """Analisi semplificata inline se il modulo esterno non è disponibile"""
    recommendations = []
    
    # Controllo Compliance
    for policy in data.get("compliance_policies", []):
        props = policy.get("@odata.type", "")
        if "androidCompliance" in props:
            if not policy.get("passwordRequired", True):
                recommendations.append({
                    "severity": "CRITICA",
                    "category": "Compliance",
                    "policy": policy.get("displayName"),
                    "issue": "Password non obbligatoria su Android",
                    "remediation": "Imposta 'passwordRequired' a True"
                })
        elif "windowsCompliance" in props:
            if not policy.get("secureBootEnabled", False):
                 recommendations.append({
                    "severity": "ALTA",
                    "category": "Compliance",
                    "policy": policy.get("displayName"),
                    "issue": "Secure Boot non abilitato su Windows",
                    "remediation": "Abilita Secure Boot nella policy di compliance"
                })

    # Controllo Endpoint Security (BitLocker)
    for policy in data.get("intune_policies", []):
        if "diskEncryption" in policy.get("@odata.type", ""):
            # Logica semplificata per demo
            pass 
            
    return recommendations

def main():
    st.title("🛡️ Intune Policy Analyzer & Connector")
    st.markdown("Connettiti al tuo tenant Azure AD, scarica le policies e analizzale automaticamente.")

    # Sidebar per configurazione e connessione
    with st.sidebar:
        st.header("⚙️ Configurazione")
        
        tenant_id = st.text_input("Tenant ID", value="", help="Inserisci il tuo Tenant ID di Azure AD")
        
        if st.button("🔗 Connetti e Scarica Dati"):
            if not tenant_id:
                st.error("Inserisci il Tenant ID!")
            elif not CONNECTOR_AVAILABLE:
                st.warning("Modulo 'msal' non trovato. Esegui: `pip install msal requests`")
            else:
                with st.spinner("Avvio processo di autenticazione..."):
                    # Scriviamo temporaneamente il tenant ID nel file del connettore
                    # In produzione useremmo variabili d'ambiente o input diretti alla classe
                    import subprocess
                    import sys
                    
                    # Hack rapido per passare il tenant ID allo script standalone
                    # Meglio: istanziare la classe direttamente qui se importata correttamente
                    try:
                        from intune_connector import IntuneDataCollector
                        collector = IntuneDataCollector()
                        # Sovrascrittura dinamica per demo
                        collector.__init__() # Reset
                        import intune_connector
                        intune_connector.TENANT_ID = tenant_id
                        
                        # Ristanziamo con il nuovo ID
                        collector = IntuneDataCollector()
                        
                        if collector.authenticate():
                            st.success("Autenticazione riuscita! Avvio download...")
                            data = collector.collect_all_policies()
                            st.session_state['data'] = data
                            st.rerun()
                        else:
                            st.error("Autenticazione fallita.")
                    except Exception as e:
                        st.error(f"Errore durante la connessione: {str(e)}")
                        st.info("Alternativa: Esegui `python intune_connector.py` da terminale, poi ricarica questa pagina.")

        st.divider()
        
        if os.path.exists("intune_real_data.json"):
            st.success("✅ Dati locali rilevati")
            if st.button("🔄 Ricarica Dati Locali"):
                st.cache_data.clear()
                st.rerun()
        else:
            st.warning("❌ Nessun file dati trovato")

    # Caricamento dati
    data = load_data()
    
    if not data:
        st.info("👈 Usa la sidebar per connetterti al tenant o esegui lo script di connessione.")
        st.stop()

    # Dashboard Principale
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        count_comp = len(data.get("compliance_policies", []))
        st.metric("Compliance Policies", count_comp)
    with col2:
        count_dev = len(data.get("device_configurations", []))
        st.metric("Device Configs", count_dev)
    with col3:
        count_sec = len(data.get("intune_policies", []))
        st.metric("Endpoint Security", count_sec)
    with col4:
        count_app = len(data.get("app_protection_policies", []))
        st.metric("App Protection", count_app)

    st.divider()

    # Sezione Analisi
    st.subheader("📊 Analisi e Raccomandazioni")
    
    if st.button("🚀 Esegui Analisi Completa"):
        with st.spinner("Elaborazione policies in corso..."):
            # Qui integreremmo il motore di analisi completo
            # Per ora usiamo la funzione simple o un placeholder
            recs = analyze_policies_simple(data)
            st.session_state['recommendations'] = recs
            st.success("Analisi completata!")

    if 'recommendations' in st.session_state and st.session_state['recommendations']:
        recs = st.session_state['recommendations']
        
        # Filtri
        filter_col1, filter_col2 = st.columns(2)
        with filter_col1:
            severity_filter = st.multiselect("Filtra per Severità", options=["CRITICA", "ALTA", "MEDIA", "BASSA"], default=["CRITICA", "ALTA"])
        
        filtered_recs = [r for r in recs if r['severity'] in severity_filter]
        
        if not filtered_recs:
            st.warning("Nessuna raccomandazione critica o alta trovata con i filtri attuali.")
        else:
            for r in filtered_recs:
                color_class = "critical" if r['severity'] == "CRITICA" else "high" if r['severity'] == "ALTA" else "medium"
                with st.container():
                    st.markdown(f"""
                    <div class="metric-card {color_class}">
                        <h4>[{r['severity']}] {r['policy']}</h4>
                        <p><b>Problema:</b> {r['issue']}</p>
                        <p><b>Soluzione:</b> {r['remediation']}</p>
                    </div>
                    """, unsafe_allow_html=True)
    
    # Visualizzazione Dati Grezzi (Accordion)
    st.divider()
    st.subheader("📂 Esplora Dati")
    
    with st.expander("Vedi Compliance Policies"):
        if data.get("compliance_policies"):
            df_comp = pd.DataFrame(data["compliance_policies"])
            if not df_comp.empty:
                cols_to_show = [c for c in ['displayName', '@odata.type', 'description'] if c in df_comp.columns]
                st.dataframe(df_comp[cols_to_show], use_container_width=True)
            else:
                st.write("Nessuna policy trovata o struttura dati diversa.")
        else:
            st.write("Nessun dato disponibile.")

    with st.expander("Vedi Endpoint Security"):
        if data.get("intune_policies"):
            df_sec = pd.DataFrame(data["intune_policies"])
            if not df_sec.empty:
                cols_to_show = [c for c in ['displayName', '@odata.type', 'description'] if c in df_sec.columns]
                st.dataframe(df_sec[cols_to_show], use_container_width=True)

if __name__ == "__main__":
    main()
