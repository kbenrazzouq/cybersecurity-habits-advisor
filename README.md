# Système intelligent de recommandation de bonnes pratiques de sécurité

Outil qui évalue les habitudes numériques d'un utilisateur et lui suggère des **actions prioritaires** selon les risques
identifiés (activer la double authentification, éviter la réutilisation des mots de passe, etc.).

Techniques : **système de règles** + **recommandation par profil** (score, profil plafonné, contexte) + **arbre de décision**
(scikit-learn) utilisé comme second avis interprétable.

## Installation
    python -m venv .venv
    .venv\Scripts\activate          # Windows   |   source .venv/bin/activate  # Linux / macOS
    pip install -r requirements.txt

## Utilisation
    streamlit run app.py            # interface web
    python console.py               # version terminal
    python entrainer.py             # (ré)entraîne l'arbre -> modele_arbre.json + modele_arbre.json.sha256
    python -m unittest -v test_moteur test_interface   # 40 tests (moteur, sécurité du modèle, interface)
    python tests_profils.py         # rapport d'évaluation (scénarios, sensibilité, figures dans docs/)

## Fichiers
| Fichier | Rôle |
|---|---|
| `moteur.py` | base de connaissances, règles, score, profil plafonné, contexte, arbre, chargement sécurisé du modèle |
| `app.py` | interface Streamlit |
| `console.py` | version terminal |
| `entrainer.py` | entraîne et enregistre le modèle (JSON + empreinte SHA-256) |
| `test_moteur.py` | 33 tests unitaires et de sécurité (`unittest`) |
| `test_interface.py` | 7 tests de l'interface (AppTest), dont une régression XSS |
| `tests_profils.py` | évaluation : scénarios, comparaison de méthodes, sensibilité, avis externes |
| `modele_arbre.json`, `.sha256` | modèle appris (JSON, aucun pickle) et son empreinte |
| `SECURITE.md` | modèle de menaces, mesures, tests, risques résiduels |
| `CHANGELOG.md` | améliorations par rapport à la première version |
| `docs/` | figure de l'arbre (illustration), arbre réel exporté, gabarit d'avis externes |
| `.streamlit/config.toml` | télémétrie Streamlit désactivée |

## Ce que fait l'outil
1. **12 questions** (Oui / Parfois / Non) et un **contexte facultatif** (étudiant ou professionnel, banque en ligne).
2. **Règles** : priorité = gravité × facteur d'aggravation × poids du manque × facteur de contexte.
3. **Profil** : score sur 100, plafonné si une action critique ou plusieurs risques combinés subsistent.
4. **Gains rapides** : actions à effort faible et priorité élevée, mises en avant.
5. **Second avis** de l'arbre de décision, sans jamais afficher deux « actions les plus urgentes » contradictoires.
6. **Rapport** téléchargeable, avec les références de chaque conseil.

## Ajouter une habitude
Ajouter un dictionnaire dans `QUESTIONS` (`moteur.py`) : `id`, `categorie`, `gravite` (1-5), `effort` (1-3), `question`,
`risque`, `conseil`, `sources` (clés de `SOURCES`). Puis relancer `python entrainer.py` et `python -m unittest test_moteur`.
Un modèle devenu périmé (questions modifiées) est refusé au chargement et ré-entraîné automatiquement.

## Travail en groupe
Chaque membre doit committer avec sa propre identité (`git config user.name "Prénom Nom"`). La contribution de chacun se
lit ensuite avec `git log --format="%an | %s"`. Le dossier `.venv` ne doit jamais être versionné ni rendu (voir `.gitignore`).
