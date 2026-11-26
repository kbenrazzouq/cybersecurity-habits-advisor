# Améliorations par rapport à la première version

Chaque ligne renvoie au point correspondant de l'analyse (PDF `analyse_projet_securite.pdf`, sections 5 et 6).

| # | Point de l'analyse | Avant | Après |
|---|---|---|---|
| 1 | 5.1 Profil contradictoire | Pas de 2FA + mots de passe réutilisés = score 76, « Utilisateur avancé », « Très bon niveau ! » | Profil **plafonné** : une action critique -> au mieux « Utilisateur moyen » ; au moins 2 risques combinés -> « Débutant à risque ». La raison est affichée à l'utilisateur. |
| 2 | 5.2 Arbre = copie des règles | « 89 % de précision » présentés comme une qualité ; « action la plus urgente » parfois en contradiction avec la liste | Arbre présenté comme **approximation interprétable** des règles ; métriques honnêtes (fidélité, classe majoritaire) ; **second avis** : accord affiché, désaccord signalé, règles = référence. Fidélité 99,4 % sur 20 000 profils jamais vus (contre 89,4 %). Entraînement sur 8 000 profils, contexte et réponses nuancées inclus. |
| 3 | 5.3 Évaluation trop favorable | 9 scénarios, comparaison avec l'ordre alphabétique, `attendu_top3` testait le top 1, « probabilité » | 13 scénarios ; `top1_acceptable` et `top3_requis` réellement testés ; comparaison avec un **tri par gravité seule** ; **sensibilité du facteur** d'aggravation ; gabarit d'**avis externes** ; vocabulaire corrigé (« facteur d'aggravation »). |
| 4 | 5.4 Figure trompeuse | Figure de profondeur 3 présentée comme « le modèle » | Titre d'avertissement dans la figure ; **arbre réel exporté** en texte (`docs/arbre_decision_reel.txt`). |
| 5 | 5.5 Sécurité du projet | `joblib.load` (pickle) ; Google Fonts ; télémétrie Streamlit par défaut ; versions `>=` ; HTML non échappé | Modèle **JSON + SHA-256 + validation** ; polices système ; **télémétrie désactivée** ; versions épinglées ; `html.escape` ; validation des entrées ; `SECURITE.md`. |
| 6 | 5.6 Personnalisation limitée | Oui/Non ; effort = simple départage ; pas de contexte ; pas de sources | **Oui / Parfois / Non** ; **gains rapides** ; **contexte** (étudiant, professionnel, banque en ligne) ; **références** par conseil dans l'interface et le rapport. |
| 7 | 5.7 Présentation du rendu | `.venv` de 573 Mo, `.idea`, dépôt git sans commit, pas de `.gitignore`, pas de documentation | Archive propre (~100 Ko), `.gitignore`, README, `SECURITE.md`, conseils de travail en groupe. |

## Autres corrections
- Sous-titres de catégories répétés dans le formulaire (« Mots de passe » apparaissait deux fois) : regroupement par catégorie.
- Question « 12 caractères » reformulée : la recommandation de la CNIL raisonne en entropie, pas en longueur minimale ;
  « 12 caractères » est une règle pratique, pas une exigence officielle.
- Conseil 2FA précisé : application d'authentification ou clé de sécurité de préférence au SMS.
- 40 tests automatiques (`test_moteur.py`, `test_interface.py`) au lieu d'assertions dans un script ; le test XSS a été
  vérifié par mutation (il échoue quand l'échappement est supprimé).

## À savoir (honnêteté sur les limites de cette version)
- Les **attendus de profil** des scénarios ont été révisés en même temps que la règle de plafonnement : ils décrivent
  l'intention de la règle, ils ne la valident pas de façon indépendante. Faire relire les scénarios par des personnes
  extérieures (`docs/avis_externes_modele.csv`) reste la meilleure suite.
- Sur les scénarios simples, le **tri par gravité seule** donne déjà la bonne action n°1 (12/13). Les règles de
  combinaison changent l'action n°1 dans 2 à 4 % des profils tirés au hasard ; leur apport principal est l'alerte
  explicite et le plafond de profil.
- Les **gravités, efforts et coefficients** restent des choix d'expert ; les références étayent le principe de chaque
  conseil, pas les valeurs chiffrées.
- Testé avec Python 3.12, Streamlit 1.65.0, scikit-learn 1.7.2 et 1.9.1, matplotlib 3.10.9 (versions épinglées).
