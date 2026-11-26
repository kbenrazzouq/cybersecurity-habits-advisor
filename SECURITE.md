# Sécurité du projet lui-même

Un outil qui conseille de bonnes pratiques de sécurité doit les appliquer. Ce document décrit ce qui est protégé, les
menaces considérées, les mesures mises en œuvre, les tests qui les vérifient, et ce qui reste exposé.

## 1. Périmètre et hypothèses
- Outil **local** : les réponses sont déclaratives, traitées en mémoire, jamais enregistrées ni transmises.
- Le seul fichier de données persistant est le modèle `modele_arbre.json` (et son empreinte).
- Hors périmètre : sécurité de l'hébergement si l'application est déployée sur un serveur (HTTPS, authentification,
  sauvegarde, journalisation), à traiter séparément.

## 2. Menaces et mesures

| # | Menace | Mesure | Où | Test |
|---|---|---|---|---|
| 1 | **Désérialisation non sûre** : un fichier modèle `.joblib` (pickle) modifié exécute du code arbitraire à l'ouverture | Modèle stocké en **JSON** (tableaux de nombres) ; plus aucun `pickle` ni `joblib` dans `moteur.py` | `moteur.py` : `exporter_arbre`, `charger_modele` | `test_pickle_piege_jamais_execute`, `test_le_moteur_n_importe_pas_pickle_ni_joblib` |
| 2 | **Altération du modèle** (corruption, remplacement) | Empreinte **SHA-256** dans un fichier voisin ; refus si absente ou différente | `charger_modele` | `test_octet_modifie_detecte_par_empreinte`, `test_empreinte_absente_refuse` |
| 3 | **Fichier modèle malveillant même avec une empreinte valide** (boucle infinie, indices hors limites, classes inconnues) | **Validation structurelle** : enfants d'indice supérieur au parent (pas de cycle), bornes, types, valeurs finies, classes autorisées, questions identiques | `valider_arbre` | `test_structures_malveillantes_refusees` (9 cas) |
| 4 | **Déni de service** par fichier énorme | Taille maximale 5 Mo avant lecture ; nombre de nœuds borné | `charger_modele`, `valider_arbre` | `test_fichier_trop_gros_refuse` |
| 5 | **Entrées invalides** | Validation stricte des réponses et du contexte (valeurs, clés, types) ; erreur explicite sinon | `valider_reponses`, `valider_contexte` | `TestValidation` |
| 6 | **Injection HTML (XSS)** : l'interface utilise `unsafe_allow_html` | Tout texte injecté est échappé avec `html.escape` ; aucune saisie libre n'existe aujourd'hui | `app.py` | `test_interface.test_contenu_pirate_est_echappe` |
| 7 | **Fuite de données vers des tiers** | Police Google Fonts supprimée (polices système) ; **télémétrie Streamlit désactivée** | `app.py`, `.streamlit/config.toml` | `test_interface.test_aucune_url_externe` |
| 8 | **Chaîne d'approvisionnement des dépendances** | Versions **épinglées** (`==`) ; dépendances minimales ; scikit-learn utilisé seulement à l'entraînement | `requirements.txt` | à compléter par `pip-audit` (ci-dessous) |
| 9 | **Manipulation des conseils** (empoisonnement du modèle) | L'arbre n'est qu'un second avis : les **règles** restent la référence affichée ; un désaccord est montré, pas imposé | `app.py`, `analyser` | `TestAnalyse` |
| 10 | **Secrets / informations personnelles dans le rendu** | `.gitignore` ; pas de `.venv`, `.idea` ni `.git` vide dans l'archive ; aucune donnée personnelle dans le code | racine | relecture |

## 3. Risques résiduels (à assumer dans le rapport)
- **L'empreinte SHA-256 stockée à côté du modèle détecte la corruption et les modifications maladroites, pas un attaquant
  qui modifie les deux fichiers.** Le test #1 simule précisément ce cas : le fichier est alors refusé s'il n'est pas du
  JSON valide, mais un JSON bien formé et modifié serait accepté. Dans ce cas l'impact est borné : l'arbre ne peut produire
  qu'une action parmi les 13 autorisées, et les règles, non modifiées, restent la référence. Pour aller plus loin :
  signature numérique du modèle, ou empreinte de référence stockée hors du dossier applicatif.
- Un attaquant qui contrôle le dossier de l'application peut modifier le code lui-même : la protection du serveur et des
  droits d'écriture relève du déploiement.
- Les réponses sont **déclaratives** : l'outil ne vérifie pas les habitudes réelles.
- Si une saisie libre était ajoutée un jour, elle devrait être validée et échappée avant tout affichage.

## 4. Vérifier les dépendances
    pip install pip-audit
    pip-audit -r requirements.txt

## 5. Si l'application est déployée
HTTPS obligatoire, authentification si l'accès doit être restreint, droits d'écriture minimaux sur le dossier de
l'application, mises à jour régulières des dépendances épinglées, et pas de journalisation des réponses des utilisateurs.
