import msal
import requests
import json
import time
import os

# CONFIGURAZIONE
# Sostituisci con il tuo Tenant ID (lo trovi su portal.azure.com > Azure Active Directory > Panoramica)
TENANT_ID = "YOUR_TENANT_ID_HERE" 
CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e" # Microsoft Graph CLI App ID (pubblico) o crea la tua app
SCOPE = ["https://graph.microsoft.com/.default"]
OUTPUT_FILE = "intune_real_data.json"

class IntuneDataCollector:
    def __init__(self):
        self.token = None
        self.session = requests.Session()

    def authenticate(self):
        """Autenticazione tramite Device Code Flow (sicura e senza popup browser locali)"""
        print(f"[*] Inizio autenticazione per il Tenant: {TENANT_ID}")
        
        app = msal.PublicClientApplication(
            CLIENT_ID,
            authority=f"https://login.microsoftonline.com/{TENANT_ID}"
        )

        # Richiedi un codice dispositivo
        flow = app.initiate_device_flow(scopes=SCOPE)
        
        if "user_code" not in flow:
            raise ValueError("Fallimento creazione flusso device code")

        print("\n" + "="*50)
        print(f"CODICE DI AUTENTICAZIONE: {flow['user_code']}")
        print("="*50)
        print(f"1. Vai su: {flow['verification_uri']}")
        print(f"2. Inserisci il codice sopra riportato.")
        print(f"3. Accedi con il tuo account Global Reader.")
        print("="*50 + "\nIn attesa di completamento login...")

        result = app.acquire_token_by_device_flow(flow)

        if "access_token" in result:
            self.token = result["access_token"]
            print("[+] Autenticazione riuscita!")
            return True
        else:
            print(f"[-] Errore autenticazione: {result.get('error_description')}")
            return False

    def make_request(self, endpoint):
        """Esegue una richiesta GET alle Graph API con gestione pagination"""
        url = f"https://graph.microsoft.com/v1.0/{endpoint}"
        headers = {"Authorization": f"Bearer {self.token}"}
        
        all_data = []
        while url:
            response = self.session.get(url, headers=headers)
            if response.status_code == 403:
                print(f"[-] Errore 403: Permessi insufficienti per {endpoint}")
                return None
            elif response.status_code != 200:
                print(f"[-] Errore richiesta {url}: {response.status_code} - {response.text}")
                return None
            
            data = response.json()
            all_data.extend(data.get("value", []))
            
            # Gestione OData Next Link per liste lunghe
            url = data.get("@odata.nextLink")
            
        return all_data

    def collect_all_policies(self):
        """Raccoglie tutte le categorie di policy necessarie"""
        if not self.token:
            return None

        print("\n[*] Raccolta dati in corso...")
        
        data_store = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tenant_id": TENANT_ID,
            "compliance_policies": [],
            "device_configurations": [],
            "intune_policies": [], # Endpoint security
            "app_protection_policies": [],
            "update_policies": []
        }

        # 1. Compliance Policies
        print("   - Scaricamento Compliance Policies...")
        data_store["compliance_policies"] = self.make_request("deviceManagement/deviceCompliancePolicies") or []

        # 2. Device Configurations (General settings, Password, etc.)
        print("   - Scaricamento Device Configurations...")
        data_store["device_configurations"] = self.make_request("deviceManagement/deviceConfigurations") or []

        # 3. Endpoint Security Policies (Firewall, Disk Encryption, Antivirus)
        # Nota: Queste sono sotto endpointManagement
        print("   - Scaricamento Endpoint Security Policies...")
        # Account Protection
        data_store["intune_policies"].extend(
            self.make_request("deviceManagement/endpointSecurity/accountProtectionPolicies") or []
        )
        # Disk Encryption
        data_store["intune_policies"].extend(
            self.make_request("deviceManagement/endpointSecurity/diskEncryptionPolicies") or []
        )
        # Firewall
        data_store["intune_policies"].extend(
            self.make_request("deviceManagement/endpointSecurity/firewallPolicies") or []
        )
        # Antivirus
        data_store["intune_policies"].extend(
            self.make_request("deviceManagement/endpointSecurity/antivirusPolicies") or []
        )

        # 4. App Protection Policies (MAM)
        print("   - Scaricamento App Protection Policies...")
        data_store["app_protection_policies"] = self.make_request("deviceAppManagement/managedAppPolicies") or []

        # 5. Update Rings (Windows Update for Business)
        print("   - Scaricamento Windows Update Rings...")
        data_store["update_policies"] = self.make_request("deviceManagement/windowsUpdateForBusinessUpdateRings") or []

        # Salvataggio su file
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(data_store, f, indent=2, ensure_ascii=False)
        
        print(f"\n[+] Dati salvati con successo in: {os.path.abspath(OUTPUT_FILE)}")
        print(f"    - Compliance Policies: {len(data_store['compliance_policies'])}")
        print(f"    - Device Configs: {len(data_store['device_configurations'])}")
        print(f"    - Endpoint Security: {len(data_store['intune_policies'])}")
        print(f"    - App Protection: {len(data_store['app_protection_policies'])}")
        print(f"    - Update Rings: {len(data_store['update_policies'])}")
        
        return data_store

if __name__ == "__main__":
    if TENANT_ID == "YOUR_TENANT_ID_HERE":
        print("ERRORE: Devi inserire il tuo TENANT_ID nello script prima di eseguire.")
        print("Trovalo su: Azure Portal -> Azure Active Directory -> Panoramica -> ID directory (tenant)")
    else:
        collector = IntuneDataCollector()
        if collector.authenticate():
            collector.collect_all_policies()
