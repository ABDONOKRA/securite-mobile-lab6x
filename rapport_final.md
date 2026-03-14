# RAPPORT D'ANALYSE STATIQUE DE SÉCURITÉ MOBILE

## INFORMATIONS GÉNÉRALES

**Date d'analyse:** $(date +%Y-%m-%d)  
**Analyste:** ENNOUKRA ABDELGHAFOUR  
**Établissement:** EMSI  
**Cours:** Lab 6 - Sécurité Mobile  

**APK analysé:** AndroGoat.apk  
**Taille:** 6.77 MB  
**Package:** owasp.sat.agoat  
**Version:** 1.0 (Code: 1)  
**Hash SHA-256:** 3a3825d4ba654a4d4c6982f69ac72d66  

**Outils utilisés:**  
- MobSF v[VERSION] dans VM Mobexler  
- Plateforme: Ubuntu Linux  
- Date d'analyse: $(date)

---

## RÉSUMÉ EXÉCUTIF

L'analyse statique de l'application **AndroGoat** (application pédagogique OWASP) révèle un **niveau de risque CRITIQUE**. Le score de sécurité MobSF est de **48/100**, indiquant de nombreuses vulnérabilités majeures.

**Principales découvertes critiques:**

1. **Credentials AWS hardcodées** permettant un accès total aux ressources cloud du développeur (risque financier et de données catastrophique)
2. **Clé API OpenAI hardcodée** exposant le compte à une utilisation frauduleuse
3. **Mode debug activé** facilitant le reverse engineering
4. **Composants Android exportés sans protection** créant une large surface d'attaque
5. **Communication HTTP non chiffrée** exposant les données en transit

L'application présente **10 non-conformités majeures** au standard OWASP MASVS, principalement dans les catégories Stockage (STORAGE), Réseau (NETWORK), et Plateforme (PLATFORM).

**Verdict:** L'application nécessite une **remédiation URGENTE** avant toute mise en production. Les credentials cloud exposées doivent être **révoquées immédiatement**.

---

## VULNÉRABILITÉS CRITIQUES

### 🔴 VULNÉRABILITÉ #1 - CREDENTIALS AWS HARDCODÉES

**Sévérité:** CRITIQUE (CVSS 9.8)  
**Catégorie MASVS:** MSTG-STORAGE-14  
**CWE:** CWE-798 (Use of Hard-coded Credentials)  

**Description:**  
Les credentials AWS (Access Key ID et Secret Access Key) sont hardcodées en clair dans le fichier source `CloudServicesActivity.java`. Ces credentials donnent un accès administratif complet au compte AWS du développeur.

**Preuve technique:**
```java
// Fichier: owasp/sat/agoat/CloudServicesActivity.java
private final String aws_access_key_id = "AKIAX56QKKOLPQ7G7ABC";
private final String aws_secret_access_key = "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";
```

**Localisation:** `owasp/sat/agoat/CloudServicesActivity.java`, lignes ~27-28

**Impact:**
- Accès total aux ressources AWS (EC2, S3, RDS, Lambda, etc.)
- Création/suppression de ressources cloud
- Vol de toutes les données stockées (S3 buckets, bases de données)
- Cryptomining aux frais du propriétaire (factures potentiellement énormes)
- Compromission complète de l'infrastructure cloud
- Risque réglementaire (RGPD) si données clients compromises

**Scénario d'exploitation:**
1. Attaquant décompile l'APK avec `apktool` ou `jadx`
2. Extrait les credentials du code source Java
3. Configure AWS CLI: `aws configure`
4. Liste toutes les ressources: `aws s3 ls`, `aws ec2 describe-instances`
5. Exfiltre les données ou crée des ressources malveillantes

**Remédiation:**
1. **IMMÉDIAT:** Révoquer ces credentials dans AWS IAM Console
2. Auditer les logs CloudTrail pour détecter toute utilisation malveillante
3. Vérifier les factures AWS pour activités suspectes
4. Implémenter AWS Cognito ou STS pour générer des credentials temporaires
5. Utiliser AWS Secrets Manager ou Parameter Store
6. Ne JAMAIS inclure de credentials dans le code source
7. Utiliser des variables d'environnement côté backend uniquement

---

### 🔴 VULNÉRABILITÉ #2 - CLÉ API OPENAI HARDCODÉE

**Sévérité:** CRITIQUE (CVSS 8.5)  
**Catégorie MASVS:** MSTG-STORAGE-14  
**CWE:** CWE-312 (Cleartext Storage of Sensitive Information)  

**Description:**  
Une clé API OpenAI est hardcodée en clair dans le fichier `AIChatActivity.java`, permettant à tout attaquant de l'extraire et de l'utiliser à ses propres fins.

**Preuve technique:**
```java
// Fichier: owasp/sat/agoat/AIChatActivity.java
private final String openAIApiKey = "sk-abcdef1234567890abcdef1234567890abcdef12";
```

**Localisation:** `owasp/sat/agoat/AIChatActivity.java`, ligne ~27

**Impact:**
- Utilisation frauduleuse de l'API OpenAI (GPT-4, etc.)
- Coûts importants pour le propriétaire du compte
- Épuisement rapide des quotas et limites
- Bannissement possible du compte OpenAI
- Utilisation pour spam, contenu malveillant, ou abus

**Remédiation:**
1. **IMMÉDIAT:** Révoquer la clé API dans le dashboard OpenAI
2. Créer une nouvelle clé avec limitations de quota
3. Implémenter un backend proxy pour gérer les appels API
4. Ne jamais exposer de clés API côté client
5. Monitorer l'utilisation de l'API pour détecter abus

---

### 🟠 VULNÉRABILITÉ #3 - MODE DEBUG ACTIVÉ EN PRODUCTION

**Sévérité:** ÉLEVÉE (CVSS 7.5)  
**Catégorie MASVS:** MSTG-RESILIENCE-2  
**CWE:** CWE-489 (Active Debug Code)  

**Description:**  
L'application est compilée avec le flag `android:debuggable="true"`, permettant à tout attaquant d'attacher un debugger et d'analyser le comportement runtime.

**Preuve technique:**
```xml
<!-- AndroidManifest.xml -->
<application android:debuggable="true" ... >
```

**Impact:**
- Attachment de debugger (Android Studio, IDA Pro)
- Dumping de la mémoire et stack traces
- Analyse du flux d'exécution en temps réel
- Modification des variables runtime
- Facilite grandement le reverse engineering

**Remédiation:**
- Définir `android:debuggable="false"` dans le manifeste de production
- Utiliser BuildConfig.DEBUG pour différencier builds debug/release
- Implémenter une détection de debugger runtime
- Ajouter des checks anti-debugging (optionnel)

---

### 🟠 VULNÉRABILITÉ #4 - COMPOSANTS ANDROID EXPORTÉS SANS PROTECTION

**Sévérité:** ÉLEVÉE (CVSS 7.0)  
**Catégorie MASVS:** MSTG-PLATFORM-1  
**CWE:** CWE-927 (Improper Access Control)  

**Description:**  
Plusieurs composants Android (Service, Receivers, Provider, Activity) sont exportés sans protection par permission, permettant à n'importe quelle application tierce d'y accéder.

**Composants vulnérables:**

1. **Service:** `DownloadInvoiceService` (100% exporté)
   - Configuration: `android:exported="true"`
   - Protection: AUCUNE
   - Risque: Démarrage non autorisé, DoS

2. **Broadcast Receiver:** `ShowDataReceiver` (100% exporté)
   - Configuration: `android:exported="true"`
   - Protection: AUCUNE
   - Risque: Injection de broadcasts malveillants

3. **Content Provider:** `ContentProviderActivity`
   - Configuration: `android:exported="true"`
   - Protection: AUCUNE
   - Risque: **Fuite de données critiques**

4. **Activity:** `AccessControl1ViewActivity`
   - Configuration: `android:exported="true"`
   - Protection: AUCUNE
   - Risque: Bypass de contrôles d'accès

**Impact:**
- Accès non autorisé aux fonctionnalités de l'app
- Injection de données malveillantes
- Fuite de données via Content Provider
- Bypass de l'authentification
- Déni de service (crash de l'app)

**Remédiation:**
- Définir `exported="false"` pour tous les composants internes
- Ajouter `android:permission` pour composants devant rester accessibles
- Utiliser des permissions de niveau `signature` pour composants sensibles
- Valider tous les intents et données reçus

---

### 🟡 VULNÉRABILITÉ #5 - COMMUNICATION HTTP NON CHIFFRÉE

**Sévérité:** MOYENNE (CVSS 5.3)  
**Catégorie MASVS:** MSTG-NETWORK-1  
**CWE:** CWE-319 (Cleartext Transmission of Sensitive Information)  

**Description:**  
L'application communique avec au moins un endpoint utilisant HTTP (cleartext) au lieu de HTTPS.

**Preuve technique:**
```
URL: http://demo.testfire.net
Fichier: owasp/sat/agoat/TrafficActivity.java
```

**Impact:**
- Interception du trafic par Man-in-the-Middle
- Vol de données sensibles en transit (tokens, credentials)
- Manipulation des réponses serveur
- Session hijacking

**Remédiation:**
- Migrer toutes les URLs vers HTTPS
- Configurer Network Security Config pour bloquer cleartext:
```xml
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
</network-security-config>
```
- Implémenter certificate pinning pour les endpoints critiques

---

## AUTRES OBSERVATIONS

### Permissions dangereuses
- `android.permission.CAMERA` - Justification à vérifier
- `android.permission.READ_EXTERNAL_STORAGE` - Potentiellement excessive
- `android.permission.WRITE_EXTERNAL_STORAGE` - Potentiellement excessive

### Vulnérabilités additionnelles
- **AllowBackup enabled:** Données extractibles via ADB
- **SQL Injection:** Requêtes non paramétrées dans plusieurs activités
- **Weak Cryptography:** Utilisation de MD5 (algorithme cassé)
- **Target SDK 19:** Obsolète (Android 4.4), multiples CVEs non patchées
- **Insecure Logging:** Informations sensibles loggées

---

## RECOMMANDATIONS PRIORITAIRES

### 🔴 PRIORITÉ ABSOLUE (Immédiat - 24h)

1. **RÉVOQUER IMMÉDIATEMENT** tous les secrets exposés:
   - Clé API OpenAI
   - AWS Access Key ID et Secret Access Key
   - Auditer les logs pour utilisation malveillante

2. **Vérifier les factures** AWS et OpenAI pour détecter usage frauduleux

3. **Désactiver le mode debug:**
```xml
   <application android:debuggable="false" ... >
```

### 🟠 PRIORITÉ ÉLEVÉE (1 semaine)

4. **Sécuriser les composants exportés:**
   - Ajouter des permissions ou passer en `exported="false"`
   - Implémenter validation stricte des intents

5. **Implémenter une architecture sécurisée pour les secrets:**
   - Backend proxy pour API calls
   - Android Keystore pour secrets locaux
   - AWS Cognito/STS pour credentials temporaires

6. **Désactiver AllowBackup** ou implémenter BackupAgent chiffré

### 🟡 PRIORITÉ MOYENNE (2-4 semaines)

7. **Migrer vers HTTPS uniquement:**
   - Bloquer cleartext traffic
   - Implémenter certificate pinning

8. **Corriger les injections SQL:**
   - Utiliser des requêtes préparées
   - Migrer vers Room Database

9. **Remplacer MD5** par SHA-256 ou bcrypt

10. **Mettre à jour Target SDK** vers API 33 minimum

---

## ANNEXES

### Annexe A - Liste des permissions dangereuses
- android.permission.CAMERA
- android.permission.READ_EXTERNAL_STORAGE
- android.permission.WRITE_EXTERNAL_STORAGE

### Annexe B - Composants exportés
- Service: DownloadInvoiceService
- Receiver: ShowDataReceiver
- Receiver: ProfileInstallReceiver (protected by DUMP - faible)
- Provider: ContentProviderActivity
- Activity: AccessControl1ViewActivity

### Annexe C - URLs et endpoints identifiés
- http://demo.testfire.net (HTTP - NON SÉCURISÉ)
- https://cve.org
- https://owasp.org
- https://github.com/satishpatnayak/androgoat
- https://raw.githubusercontent.com/satishpatnayak/mytest/master/androgoatinvoice.txt

### Annexe D - Références OWASP MASVS
**Non-conformités détectées:**
- MSTG-STORAGE-2 (Temp files)
- MSTG-STORAGE-3 (Logging)
- MSTG-STORAGE-8 (Backup)
- MSTG-STORAGE-14 (Hardcoded secrets) ⭐
- MSTG-NETWORK-1 (Cleartext traffic)
- MSTG-CRYPTO-4 (Weak crypto)
- MSTG-PLATFORM-1 (Exported components)
- MSTG-PLATFORM-2 (Input validation)
- MSTG-RESILIENCE-2 (Debug mode)

**Score de conformité MASVS:** 0/10 exigences critiques respectées

---

## CONCLUSION

L'application **AndroGoat** présente de **multiples vulnérabilités critiques** qui la rendent **totalement inadaptée à une mise en production**. Les credentials cloud exposées représentent un **risque financier et de sécurité majeur**.

**Actions immédiates requises:**
1. Révoquer tous les secrets exposés
2. Auditer les comptes AWS et OpenAI
3. Ne pas déployer en production tant que les vulnérabilités critiques ne sont pas corrigées

**Note:** Cette application étant un outil pédagogique intentionnellement vulnérable (OWASP), ces vulnérabilités sont attendues et conçues pour l'apprentissage. Dans un contexte réel, cette application serait considérée comme **hautement dangereuse**.

---

**Rapport généré le:** $(date)  
**Analyste:** ENNOUKRA ABDELGHAFOUR  
**Signature:** ___________________________

