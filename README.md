# BYOVD-DriverKiller

⚠️ **Avertissement** : Ce projet est strictement éducatif et démonstratif. Il n’a pas vocation à être utilisé dans un contexte malveillant. L’objectif est d’apprendre la méthodologie de reverse engineering et les étapes d’exploitation d’un driver Windows.

---
J'explique ici la démarche que j’ai suivie pour résoudre l’exercice proposé par d1rk(SaadAhla) [https://github.com/SaadAhla](https://github.com/SaadAhla/Killer-Exercice), consistant à effectuer du reverse engineering et de l’exploitation sur un driver légitime, signé, et non présent dans les blocklists (HVCI, LOLBIN...).
Un programme C permettant de terminer n'importe quel processus actif sur le système via ce Kernel-mode Driver est disponible, je détaille son fonctionnement un peu plus bas.  

![POC-BYOD](https://github.com/user-attachments/assets/0d92f128-21fc-43ab-bc8b-6219fdc9e61e)

📃 **Usage** : DriverKiller.exe <nom_processus.exe> [-d]

Option -d : Permet de supprimer le service et le Driver du système après l'exploitation.

Le testsigning mode doit être activé sur la machine cible car le certificat du Driver a expiré.

---

**Partie 1 - Reverse engineering** :

L’exercice fournit un fichier .sys, nommé avec son hash SHA-256.
La première étape consiste à ouvrir ce fichier avec IDA.<br>
<sub>*IDA est disponible gratuitement. Il suffit de se rendre sur le site d’Hex-Rays afin de générer une licence et de télécharger le logiciel.*</sub>

On commence par lister l’IAT (Import Address Table) du Driver et rechercher l’appel à l’API qui nous intéresse : <code>ZwTerminateProcess</code>.

<img width="1920" height="840" alt="screen1-git" src="https://github.com/user-attachments/assets/6f17b8c1-2588-4f41-b7e4-664ac093f3e4" />

En double-cliquant sur <code>ZwTerminateProcess</code>, IDA nous redirige vers le code compilé de cette fonction. En sélectionnant l’entrée puis en affichant les cross-references, on obtient la liste des fonctions du Driver qui l’appellent.

<img width="1920" height="869" alt="screen2-git" src="https://github.com/user-attachments/assets/73d8f1af-44f0-4993-80ac-9238af66d457" />

On observe que c’est la fonction <code>sub_12EF4</code>, à l’offset <code>1CE</code>, qui utilise <code>ZwTerminateProcess</code>. Après un double-clic, IDA affiche son code compilé.<br>

<img width="1920" height="874" alt="screen11-git" src="https://github.com/user-attachments/assets/ac7e53ef-94c8-4675-ba57-e62ff02b1114" />

Le code décompilé révèle les appels à <code>ZwOpenProcess</code> (qui ouvre un handle vers le processus cible) et à <code>ZwTerminateProcess</code> (qui termine le processus via ce handle).

En consultant la documentation de <code>ZwOpenProcess</code> (https://learn.microsoft.com/fr-fr/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwopenprocess), on constate que le paramètre <code>ClientID</code> correspond à un pointeur indiquant le PID du processus visé.

Sur la ligne au-dessus, <code>ClientId.UniqueProcess</code> est initialisé avec la variable <code>v22</code>. Cette dernière est définie juste au-dessus : <pre>v22 = (void )((_QWORD *)i + 10);</pre>

Pour comprendre cette affectation, il faut identifier la variable <code>i</code> et le champ +10.<br>

<img width="1920" height="870" alt="screen3-git" src="https://github.com/user-attachments/assets/d5e89199-ae7a-4107-ab9a-54a977050352" />

Plus haut dans cette fonction, on observe un appel à <code>ZwQuerySystemInformation</code> avec le paramètre <code>SYSTEM_PROCESS_INFORMATION</code>. On comprend également que <code>i</code> est l’itérateur sur les entrées de cette structure avec la variable <code>v6</code>.</br>

D’après la documentation de <code>ZwQuerySystemInformation</code> : (https://learn.microsoft.com/en-us/windows/win32/sysinfo/zwquerysysteminformation), cette fonction retourne un tableau contenant une entrée par processus actif sur le système.

La structure <code>SYSTEM_PROCESS_INFORMATION</code> est décrite ici : https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation

<pre>typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION;</pre>

Rappel : tailles de certains types sur Windows x64

- ULONG = 4 octets
- USHORT = 2 octets
- HANDLE = 8 octets
- PWSTR = 8 octets
- KPRIORITY (typedef d'un LONG) = 4 octets
- UNICODE_STRING = 16 octets car voici sa structure :
<pre>
  typedef struct _UNICODE_STRING {
    USHORT Length;        -> 2      
    USHORT MaximumLength; -> + 2 = 4
    PWSTR  Buffer;        -> + 8 = 12 (12 n'est pas un multiple de 8 donc padding de 4 ajouté en amont de Buffer) = 16
} UNICODE_STRING;</pre>

Calcul de l’offset de <code>UniqueProcessId</code> :
<pre>
    ULONG NextEntryOffset;        -> 4
    ULONG NumberOfThreads;        -> + 4 = 8
    BYTE Reserved1[48];           -> + 48 = 56
    UNICODE_STRING ImageName;     -> + 16 = 72
    KPRIORITY BasePriority;       -> + 4 = 76 (76 n'est pas un multiple de 8 donc padding de 4 ajouté) = 80
    HANDLE UniqueProcessId;       -> + 8 = 88
</pre>

Le membre <code>UniqueProcessId</code> est donc à l’offset 0x50 (80 décimal).

En regardant l'affectation de notre variable <code>v22</code>, on constate que <code>i</code> est casté en pointeur <code>QWORD</code> (8 octets) <pre>v22 = (void *)*((_QWORD *)i + 10);</pre>
Donc <code>v22</code> correspond l'adresse de <code>i</code> + 10 * 8 = 80 octets. Cette variable contient donc bien le PID récupéré de la structure SYSTEM_PROCESS_INFORMATION.

Pour savoir quel PID sera passé à <code>ZwTerminateProcess</code>, il faut analyser la condition qui entoure cette affectation.

<img width="1920" height="870" alt="screen4-git" src="https://github.com/user-attachments/assets/5510517c-ac61-48ce-94aa-60aab4f52f60" />

On constate que le nom de l’image du processus est d’abord récupéré : <pre>v9 = (wchar_t *)*((_QWORD *)i + 8);</pre>
Car <code>v9</code> = adresse de <code>i</code> + 8 × 8 = 64 octets. Cela correspond au <code>Buffer</code> du membre <code>ImageName</code>, puisque ce membre se trouve à l’offset 56 + 2 (USHORT) + 2 (USHORT) + 4 (padding) = 64

Au vu des manipulations et des boucles dessous, on peut émettre l’hypothèse qu’une comparaison entre le nom du processus passé en argument (<code>a2</code>) et les processus actifs sur le système <code>v9/String</code> est effectuée.
<pre>
sub_1C078(String, v9, (int)v13);
v17 = strupr(a2);
v18 = strupr(String);
</pre>

C’est donc le paramètre <code>a2</code> qui est censé contenir le nom du processus à terminer via <code>ZwTerminateProcess</code>.
On remarque que <code>a2</code> est un paramètre de la fonction <code>sub_12EF4</code>. Pour aller plus loin, il faut examiner les références de cette fonction (je l’ai renommée <code>ZwTerminateProcessCaller</code> pour une meilleure lisibilité).

<img width="1920" height="872" alt="screen5-git" src="https://github.com/user-attachments/assets/eada954b-d339-4a46-8362-a38ffde8f5d7" />

On constate que <code>ZwTerminateProcessCaller</code> est appelée par la fonction <code>sub_13624</code> à l'offset <code>61A</code>.

<img width="1920" height="871" alt="screen6-git" src="https://github.com/user-attachments/assets/f514c732-538d-4364-81be-15ce150bcd1c" />

Avant d’analyser ce code décompilé, je vais chercher les références de la fonction <code>sub_13624</code> (renommée <code>ZwTerminateProcessCallerCaller</code>) afin de m’assurer que ce code est bien utilisé après un appel API à <code>DeviceIoControl</code> depuis le UserMode.

<img width="1920" height="872" alt="screen§-git" src="https://github.com/user-attachments/assets/8cce90f7-a0cb-46fb-bfcc-5ef39f1afc2a" />

On constate que <code>ZwTerminateProcessCallerCaller</code> est appelée par la fonction <code>sub_14130</code> (renommée <code>ZwTerminateProcessCallerCallerCaller</code> ...heureusement pour nous, c'est la dernière avant le point d'entrée 😅).

<img width="1920" height="875" alt="screen7-git" src="https://github.com/user-attachments/assets/4806434d-d3d5-474d-ad6a-60480806d946" />

On constate que <code>ZwTerminateProcessCallerCallerCaller</code> est appelée par la fonction <code>sub_1A4A8</code> à l'offset <code>306</code>.

<img width="1920" height="875" alt="screen8-git" src="https://github.com/user-attachments/assets/f463ee14-b290-4d16-ac18-9902b175a3fb" />

On trouve l'assignation de la fonction <code>ZwTerminateProcessCallerCallerCaller</code> : <pre>memset64(DriverObject->MajorFunction, (unsigned __int64)ZwTerminateProcessCallerCallerCaller, 0x1Cu);</pre>
Ce qui signifie que cette fonction est assignée à toutes les entrées de la table MajorFunction (0x1B = 27, et il existe 28 IRP majeures).

<img width="1920" height="869" alt="screen9-git" src="https://github.com/user-attachments/assets/bfd21b4c-a0c8-43f6-8305-73d52e0859c8" />

Avant de revenir à la fonction <code>sub_13624</code> (alias <code>ZwTerminateProcessCallerCaller</code>), on récupère le Symbolic Name et le Device Name (identiques ici) : <code>Viragtlt</code>.

<img width="1920" height="870" alt="screen12-git" src="https://github.com/user-attachments/assets/98b7ff4e-85d6-4592-96fd-05c4be78e3fb" />

En revenant sur <code>ZwTerminateProcessCallerCaller</code>, on remarque que son deuxième paramètre (donc <code>a2</code>) correspond à <code>MasterIrp->AssociatedIrp.SystemBuffer</code>.<br>

<img width="1920" height="870" alt="screen13-git" src="https://github.com/user-attachments/assets/f3c29457-7677-476a-be51-5936910a7b81" />

Juste au dessus de l'appel à <code>ZwTerminateProcessCaller</code> on trouve le IOCTL code : <code>-2106392528</code> (en hexadécimal : <code>0x82730030</code>).<br>

Grâce à ces informations, on peut en déduire que pour exploiter ce Driver, il faut envoyer un appel API <code>DeviceIoControl</code> au Driver avec le nom du processus à terminer dans le SystemBuffer.

---

🔷 **Informations récupérées grâce au reverse engineering** :

- IOCTLCode : <code>0x82730030</code>
- Device Name : <code>Viragtlt</code>
- Symbolic Name : <code>Viragtlt</code>
- SystemBuffer doit contenir le nom du processus cible
  
---

**Partie 2 - Exploitation**

Pour exploiter ce Driver (s'il est installé et actif sur la machine cible), il est nécessaire d'ouvrir un handle vers celui-ci, puis de faire un appel API DeviceIoControl avec un Buffer contenant le nom du processus que l'on souhaite terminer.<br>
Pour cet exercice, j'ai développé un projet C qui :
- Vérifie si le Driver est présent et actif sur le système (avec un nom de service précis) :
     - Si oui, le programme exploite le Driver avec un appel API DeviceIoControl.
     - Si non, le programme extrait le driver de ses ressources, le déploie sur le bureau de l'utilisateur, crée un service actif puis exploite le Driver avec un appel API DeviceIoControl. (Nécessite les droits admin car une création de service est effectuée.) 
- Si le Driver est présent sur le système mais que le service n'est pas démarré, le programme essaye de démarrer le service puis l'exploite avec un appel API DeviceIoControl.

J'ai également ajouté une option <code>-d</code> qui permet de supprimer le service et le Driver du système après l'exploitation.

Voici le comportement du programme C dans son cycle d'exécution complet :

<img width="1105" height="334" alt="git" src="https://github.com/user-attachments/assets/3cb6a57e-45a1-4607-b7f1-fe1dcb5ddb27" />

---

**Evasion AV/EDR**

Dans ce cas, DriverKiller.exe n’est pas détecté par Microsoft Defender, ni en statique ni en dynamique.
L’évasion n’a pas vraiment de sens ici car le Driver exploité possède un certificat expiré, son utilisation en conditions réelles est donc difficilement envisageable.
Mais pour une meilleure furtivité, on aurait pu implémenter :

- Le masquage de certains appels API de la table IAT grâce à des implémentations personnalisées de GetProcAddress et GetModuleHandle
- Un rapprochement du Kernel pour l’exécution des appels API (Direct/Indirect Syscalls)
- Des techniques Anti-VM / Anti-Debug

Détection sur le driver au 29/08/2025 (résultat déjà existant, je n'ai rien soumis sur VirusTotal pour des raisons évidentes) :

<img width="1359" height="1227" alt="image" src="https://github.com/user-attachments/assets/de114a60-2cc2-4d5a-b5cc-c9eb1b19a877" />

---

⚠️ Ce projet est réalisé dans un cadre d’apprentissage. Il peut contenir des imprécisions ou des erreurs. Toute suggestion, correction ou discussion est la bienvenue ! 😃
Merci à d1rk(SaadAhla) : https://github.com/SaadAhla !
