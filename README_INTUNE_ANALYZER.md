# 🔍 Intune Policy Analyzer

Applicazione completa per l'analisi delle policies implementate sui device in Microsoft Intune, con definizione di ottimizzazioni, standard e suggerimenti da applicare.

## 📋 Funzionalità

### Analisi Automatica
- **Compliance Policies**: Password, encryption, jailbreak detection
- **Security Policies**: Firewall, Defender, BitLocker, SmartScreen
- **Update Policies**: Deferral days, deadline, active hours
- **App Protection**: PIN, data transfer, save restrictions

### Standard & Best Practices
- Basati sulle linee guida Microsoft
- 5 livelli di severità (CRITICA, ALTA, MEDIA, BASSA, INFORMATIVA)
- Punteggio di conformità 0-100 per ogni policy
- Step-by-step remediation per ogni problema

### Reportistica
- Dashboard interattiva con grafici
- Tabelle filtrabili e ricercabili
- Export JSON, HTML, CSV
- Report dettagliati con raccomandazioni prioritarie

## 🚀 Installazione

```bash
# Installa dipendenze
pip install streamlit plotly pandas

# Verifica installazione
python3 -c "import streamlit; print('OK')"
```

## 💻 Utilizzo

### Web GUI (Consigliata)

```bash
# Avvia applicazione web
streamlit run intune_analyzer_web.py

# L'app sarà disponibile su http://localhost:8501
```

### Desktop GUI (Tkinter - richiede lib GUI)

```bash
python3 intune_policy_analyzer_gui.py
```

### CLI (Linea di comando)

```bash
python3 intune_policy_analyzer.py
```

## 📁 Formato Input JSON

Le policies devono essere fornite in formato JSON:

```json
[
  {
    "id": "POL-001",
    "name": "Baseline Compliance Policy",
    "type": "Compliance",
    "category": "Compliance",
    "lastModified": "2024-01-15T10:30:00Z",
    "assignmentCount": 150,
    "settings": {
      "password_required": true,
      "password_min_length": 6,
      "encryption_required": true
    }
  }
]
```

### Categorie Supportate
- `Compliance`
- `Sicurezza` / `Protezione Endpoint`
- `Aggiornamenti`
- `Protezione App`
- `Restrizioni Device`

## 🎯 Esempio di Analisi

L'analizzatore rileva:

| Problema | Severità | Impatto |
|----------|----------|---------|
| Password non richiesta | CRITICA | Accesso non autorizzato |
| Password < 6 caratteri | ALTA | Password deboli |
| Encryption disabilitata | CRITICA | Dati esposti |
| Defender real-time off | CRITICA | Nessun anti-malware |
| SmartScreen disabilitato | ALTA | Rischio phishing |
| Update deferral > 30gg | MEDIA | Vulnerabilità non patchate |

## 📊 Output

### Dashboard
- Metriche principali (Total, Compliant, Score)
- Grafico performance per categoria
- Distribuzione raccomandazioni per severità

### Raccomandazioni
Ogni raccomandazione include:
- Titolo e descrizione
- Valore attuale vs raccomandato
- Impatto sul business
- Step di remediation dettagliati
- Link a documentazione Microsoft

### Export
- **JSON**: Dati strutturati per integrazione
- **HTML**: Report grafico condivisibile
- **CSV**: Raccomandazioni per Excel

## 🗂️ File Inclusi

| File | Descrizione |
|------|-------------|
| `intune_analyzer_web.py` | Web GUI con Streamlit |
| `intune_policy_analyzer_gui.py` | Desktop GUI con Tkinter |
| `intune_policy_analyzer.py` | Versione CLI |
| `demo_policies.json` | Dati demo per test |
| `README.md` | Questa documentazione |

## 🧪 Test Rapido

```bash
# Test con dati demo
cd /workspace
streamlit run intune_analyzer_web.py

# Oppure test CLI
python3 -c "
from intune_analyzer_web import IntunePolicyAnalyzer, load_demo_data
analyzer = IntunePolicyAnalyzer()
data = load_demo_data()
report = analyzer.analyze_all_policies(data)
print(f'Total: {report.total_policies}')
print(f'Score: {report.overall_score}/100')
print(f'Raccomandazioni: {len(report.top_recommendations)}')
"
```

## 📖 Standard Implementati

### Compliance
- Password required: ✅ Obbligatoria
- Password length: ✅ Minimo 6 caratteri
- Encryption: ✅ BitLocker richiesto
- Jailbreak detection: ✅ Attivo

### Security
- Firewall: ✅ Sempre attivo
- Defender: ✅ Real-time protection
- SmartScreen: ✅ Abilitato
- USB restriction: ⚠️ Audit/Block

### Updates
- Deferral days: ✅ Max 30 giorni
- Deadline: ✅ 7-14 giorni
- Active hours: ✅ Configurati

### App Protection
- PIN: ✅ Richiesto
- Data transfer: ✅ Solo app gestite
- Save copy: ⚠️ Block consigliato

## 🤝 Contributing

1. Fork del progetto
2. Crea feature branch
3. Commit cambiamenti
4. Push e Pull Request

## 📄 License

MIT License - Vedi file LICENSE per dettagli.

## 🔗 Risorse

- [Microsoft Intune Documentation](https://docs.microsoft.com/en-us/mem/intune/)
- [Best Practices for Intune](https://docs.microsoft.com/en-us/mem/intune/fundamentals/best-practices)
- [Windows Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)

---

**Sviluppato con ❤️ per la community IT**
