# 🛡️ Intune Policy Analyzer - Guida all'uso

Applicazione completa per l'analisi delle policies Microsoft Intune con connessione diretta alle API Graph.

## 📋 Prerequisiti

1. **Account Azure AD** con ruolo **Global Reader** (o Intune Administrator)
2. **Python 3.8+** installato
3. **Tenant ID** del tuo ambiente Azure AD

## 🚀 Installazione

```bash
pip install msal requests streamlit pandas
```

## 🔧 Configurazione

### Passo 1: Recupera il Tenant ID
1. Vai su [portal.azure.com](https://portal.azure.com)
2. Naviga su **Azure Active Directory** > **Panoramica**
3. Copia l'**ID directory (tenant)**

### Passo 2: Esegui il Connettore

Hai due opzioni:

#### Opzione A: Da Terminale (Consigliata per primo setup)
```bash
python intune_connector.py
```
- Inserisci il tuo TENANT_ID nel file `intune_connector.py` alla riga 7
- Segui le istruzioni a schermo per l'autenticazione
- Riceverai un codice da inserire nella pagina di login Microsoft

#### Opzione B: Direttamente dalla GUI
```bash
streamlit run intune_gui_streamlit.py
```
- Inserisci il Tenant ID nella sidebar
- Clicca su "Connetti e Scarica Dati"

## 🖥️ Avvio della GUI

```bash
streamlit run intune_gui_streamlit.py
```

La dashboard si aprirà automaticamente nel browser all'indirizzo `http://localhost:8501`

## 📊 Funzionalità

### Dashboard Principale
- **Metriche in tempo reale**: conteggio policies per categoria
- **Grafici interattivi**: distribuzione delle policies
- **Filtri avanzati**: per severità, categoria, stato

### Analisi Automatica
- **Compliance Policies**: password, encryption, condizioni dispositivo
- **Endpoint Security**: firewall, BitLocker, Defender, SmartScreen
- **App Protection**: MAM, protezione dati aziendali
- **Update Rings**: politiche di aggiornamento Windows

### Raccomandazioni
- **5 livelli di severità**: CRITICA, ALTA, MEDIA, BASSA, INFORMATIVA
- **Step-by-step remediation**: istruzioni dettagliate per risolvere
- **Best practices**: suggerimenti basati su linee guida Microsoft

### Export
- **JSON**: dati grezzi per analisi ulteriori
- **HTML**: report formattato per condivisione
- **CSV**: tabelle filtrabili per Excel

## 🔐 Sicurezza

- **Device Code Flow**: nessun token salvato in chiaro
- **Solo lettura**: il ruolo Global Reader non permette modifiche
- **Dati locali**: i dati scaricati restano sul tuo computer

## 📁 File Generati

| File | Descrizione |
|------|-------------|
| `intune_real_data.json` | Dati grezzi scaricati da Intune |
| `intune_analysis_report.json` | Risultati dell'analisi |
| `intune_analysis_report.html` | Report visivo in HTML |

## 🐛 Risoluzione Problemi

### Errore 403 - Permessi Insufficienti
Verifica che l'account abbia almeno il ruolo **Global Reader** o **Intune Reader**.

### Errore di Autenticazione
- Assicurati che il Tenant ID sia corretto
- Controlla che l'account non abbia MFA bloccante
- Verifica la connettività di rete verso login.microsoftonline.com

### Nessun Dato Scaricato
Alcuni endpoint potrebbero essere vuoti se non hai configurato quelle specifiche policies. È normale.

## 📞 Supporto

Per problemi o suggerimenti, consultare la documentazione ufficiale Microsoft Graph:
- [Microsoft Graph API Docs](https://docs.microsoft.com/graph/api/overview)
- [Intune API Reference](https://docs.microsoft.com/graph/api/resources/intune-overview)
