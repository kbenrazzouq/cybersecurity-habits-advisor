"""
tests_profils.py - Rapport d'évaluation (scénarios, comparaison de méthodes, sensibilité, avis externes).
Lancer avec :  python tests_profils.py
Les tests automatiques unitaires sont dans test_moteur.py. Ce script produit des CHIFFRES pour le rapport.

Honnêteté méthodologique : les « attendus » ci-dessous sont l'avis de l'équipe, pas celui d'un expert extérieur.
Les attendus de PROFIL ont été révisés en même temps que la règle de plafonnement (voir CHANGELOG.md) : ils décrivent
l'intention de cette règle, ils ne la valident pas de façon indépendante. Pour une évaluation plus crédible, faire remplir docs/avis_externes_modele.csv par
d'autres personnes, le renommer avis_externes.csv (même dossier que ce script) et relancer.
"""
import csv
import random
from pathlib import Path

from moteur import (IDS, PAR_ID, QUESTIONS, FEATURE_NOMS, analyser, appliquer_regles, classer_profil, calculer_score,
                    profil_selon_score, entrainer_arbre, generer_dataset, exporter_arbre, valider_arbre,
                    obtenir_modele, action_arbre, valider_reponses, _vecteur, valider_contexte)

DOCS = Path(__file__).with_name("docs")
DEB, MOY, AVA = "Débutant à risque", "Utilisateur moyen", "Utilisateur avancé"


def rep(non=(), parfois=()):
    return {k: ("non" if k in non else "parfois" if k in parfois else "oui") for k in IDS}


# top1_acceptable : actions acceptables en n°1 (ensemble vide = rien à signaler)
# top3_requis     : actions qui doivent TOUTES figurer dans les 3 premières
SCENARIOS = {
    "Imprudent (tout est mauvais)":
        dict(non=set(IDS), top1_acceptable={"mdp_unique", "a2f"}, top3_requis={"mdp_unique", "a2f"}, profil=DEB),
    "Étudiant moyen":
        dict(non={"a2f", "gestionnaire", "sauvegarde", "fuites", "wifi"}, contexte=dict(usage="etudiant"),
             top1_acceptable={"a2f"}, top3_requis={"a2f"}, profil=MOY),
    "Prudent (tout est bon)":
        dict(non=set(), top1_acceptable=set(), top3_requis=set(), profil=AVA),
    "Mot de passe réutilisé seulement":
        dict(non={"mdp_unique"}, top1_acceptable={"mdp_unique"}, top3_requis={"mdp_unique"}, profil=MOY),
    "Pas de 2FA ni de mises à jour":
        dict(non={"a2f", "maj"}, top1_acceptable={"a2f", "maj"}, top3_requis={"a2f", "maj"}, profil=MOY),
    "Télécharge du pirate, sans sauvegarde":
        dict(non={"sources", "sauvegarde", "antivirus"}, top1_acceptable={"sources", "sauvegarde"},
             top3_requis={"sources", "sauvegarde"}, profil=MOY),
    "Mot de passe court + pas de 2FA":
        dict(non={"mdp_long", "a2f"}, top1_acceptable={"a2f"}, top3_requis={"a2f", "mdp_long"}, profil=MOY),
    "Pas d'antivirus ni de 2FA":
        dict(non={"antivirus", "a2f", "fuites"}, top1_acceptable={"a2f"}, top3_requis={"a2f"}, profil=MOY),
    "Verrouillage absent + phishing":
        dict(non={"verrouillage", "phishing", "gestionnaire"}, top1_acceptable={"phishing"},
             top3_requis={"phishing"}, profil=AVA),
    "2FA seulement partielle (parfois)":
        dict(parfois={"a2f"}, top1_acceptable={"a2f"}, top3_requis={"a2f"}, profil=AVA),
    "Banque en ligne + pro, sans vigilance phishing":
        dict(non={"phishing"}, contexte=dict(usage="professionnel", banque_en_ligne=True),
             top1_acceptable={"phishing"}, top3_requis={"phishing"}, profil=AVA),
    "Logiciels piratés + pas de sauvegarde + pas de mises à jour (illustre une règle de combinaison)":
        dict(non={"sources", "sauvegarde", "maj"}, top1_acceptable={"sources", "sauvegarde"},
             top3_requis={"sources", "sauvegarde"}, profil=MOY),
    "Plusieurs risques combinés":
        dict(non={"a2f", "mdp_unique", "phishing", "wifi"}, top1_acceptable={"a2f", "mdp_unique"},
             top3_requis={"a2f", "mdp_unique"}, profil=DEB),
}


# ---- Méthodes de comparaison ----
def top_naif(niveaux):
    """Sans priorisation : premier problème dans l'ordre alphabétique des identifiants."""
    return next((k for k in sorted(IDS) if niveaux[k] < 1), None)


def top_gravite(niveaux):
    """Tri par gravité seule : sans règles de combinaison, sans contexte, sans effort."""
    manquants = [k for k in IDS if niveaux[k] < 1]
    return max(manquants, key=lambda k: (PAR_ID[k]["gravite"] * (1 - niveaux[k]), -IDS.index(k)), default=None)


def reussi_top1(top1, acceptable):
    return (top1 is None) if not acceptable else (top1 in acceptable)


def ecrire_modele_avis():
    """Gabarit à faire remplir par des personnes extérieures au projet."""
    DOCS.mkdir(exist_ok=True)
    with open(DOCS / "avis_externes_modele.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["scenario", "description", "action_n1_selon_vous (id)", "profil_selon_vous"])
        for nom, s in SCENARIOS.items():
            d = [f"NON : {PAR_ID[k]['question']}" for k in sorted(s.get("non", ()), key=IDS.index)]
            d += [f"PARFOIS : {PAR_ID[k]['question']}" for k in sorted(s.get("parfois", ()), key=IDS.index)]
            ctx = s.get("contexte")
            if ctx:
                d.append(f"CONTEXTE : {ctx}")
            w.writerow([nom, " | ".join(d) or "Toutes les habitudes sont en place", "", ""])
        w.writerow([])
        w.writerow(["# Ids possibles (action_n1) :", ", ".join(IDS) + ", aucune"])
        w.writerow(["# Profils possibles :", f"{DEB} / {MOY} / {AVA}"])


def comparer_avis_externes(arbre):
    chemin = Path(__file__).with_name("avis_externes.csv")
    if not chemin.exists():
        print("  (aucun fichier avis_externes.csv : voir docs/avis_externes_modele.csv pour faire relire les scénarios)")
        return
    n = ok_action = ok_profil = 0
    with open(chemin, newline="", encoding="utf-8-sig") as f:
        for ligne in csv.reader(f, delimiter=";"):
            if not ligne or ligne[0].startswith("#") or ligne[0] not in SCENARIOS or len(ligne) < 4:
                continue
            s = SCENARIOS[ligne[0]]
            res = analyser(rep(s.get("non", ()), s.get("parfois", ())), arbre, s.get("contexte"))
            top = res["recommandations"][0]["id"] if res["recommandations"] else "aucune"
            if ligne[2].strip():
                n += 1
                ok_action += top == ligne[2].strip()
                ok_profil += res["profil"] == ligne[3].strip()
    print(f"  Avis externes lus : {n} scénarios | action n°1 identique : {ok_action}/{n} | profil identique : {ok_profil}/{n}")


def main():
    arbre, metriques = obtenir_modele()
    print("=" * 74 + "\nSCÉNARIOS (avis de l'équipe, voir l'avertissement en tête du fichier)\n" + "=" * 74)
    n = len(SCENARIOS)
    c = dict(profil=0, regles1=0, regles3=0, arbre1=0, gravite1=0, naif1=0)
    for nom, s in SCENARIOS.items():
        niveaux = valider_reponses(rep(s.get("non", ()), s.get("parfois", ())))
        ctx = valider_contexte(s.get("contexte"))
        res = analyser(niveaux, arbre, ctx)
        ids_ordonnes = [r["id"] for r in res["recommandations"]]
        top1 = ids_ordonnes[0] if ids_ordonnes else None
        acceptable = s["top1_acceptable"]
        c["profil"] += res["profil"] == s["profil"]
        c["regles1"] += reussi_top1(top1, acceptable)
        c["regles3"] += s["top3_requis"] <= set(ids_ordonnes[:3])
        c["arbre1"] += reussi_top1(res["action_arbre"], acceptable)
        c["gravite1"] += reussi_top1(top_gravite(niveaux), acceptable)
        c["naif1"] += reussi_top1(top_naif(niveaux), acceptable)
        print(f"\n[{nom}]")
        print(f"  Score {res['score']}/100 | profil : {res['profil']} (attendu : {s['profil']}) | par score seul : {res['profil_selon_score']}")
        print(f"  Top 3 règles : {ids_ordonnes[:3]} | arbre : {res['action_arbre']} | gravité seule : {top_gravite(niveaux)} "
              f"| naïf : {top_naif(niveaux)} | acceptable en n°1 : {sorted(acceptable) or 'aucun'}")

    print("\n" + "=" * 74 + f"\nRÉSULTATS SUR {n} SCÉNARIOS\n" + "=" * 74)
    plafonnes = sum(analyser(rep(sc.get("non", ()), sc.get("parfois", ())), None, sc.get("contexte"))["raison_plafond"] is not None
                    for sc in SCENARIOS.values())
    print(f"  Profil conforme à l'avis de l'équipe : {c['profil']}/{n} (avis révisé avec la règle de plafonnement, cf. en-tête)")
    print(f"  Profil plafonné dans {plafonnes}/{n} scénarios : le score seul aurait donné un profil plus favorable malgré")
    print("  une action critique ou plusieurs risques combinés.")
    print(f"  Action n°1 acceptable : règles {c['regles1']}/{n} | arbre {c['arbre1']}/{n} | "
          f"tri par gravité seule {c['gravite1']}/{n} | ordre alphabétique {c['naif1']}/{n}")
    print(f"  Actions attendues toutes présentes dans le top 3 (règles) : {c['regles3']}/{n}")
    print("  Lecture : seul le scénario marqué « illustre une règle de combinaison » départage les règles du tri par gravité")
    print("  seule, et il a été écrit pour cela. Sur les autres cas, la gravité suffit à trouver l'action n°1 ; l'apport")
    print("  des règles de combinaison est surtout l'ALERTE explicite et le plafond de profil. Voir la sensibilité.")

    # ---- Qualité de l'arbre : fidélité aux règles (PAS une validation indépendante) ----
    print("\n" + "=" * 74 + "\nARBRE DE DÉCISION : fidélité aux règles\n" + "=" * 74)
    X, y = generer_dataset(n=5000, graine=99)
    pred = arbre.predict(X)
    desaccords = [(x, t, p) for x, t, p in zip(X, y, pred) if t != p]
    print(f"  Mesuré à l'entraînement : fidélité {metriques['fidelite_nouveaux_profils']:.1%}, précision test "
          f"{metriques['precision_test']:.1%}, classe majoritaire seule {metriques['baseline_majoritaire']:.1%}")
    print(f"  Nouveau tirage de 5000 profils : désaccord arbre/règles sur {len(desaccords)} "
          f"({len(desaccords) / len(X):.1%}). Les règles restent la référence affichée.")
    for x, t, p in desaccords[:3]:
        manque = [k for k, v in zip(IDS, x) if v < 1]
        print(f"   ex. habitudes manquantes {manque} | règles : {t} | arbre : {p}")
    print("  RAPPEL : l'arbre est entraîné sur des étiquettes produites par les règles. Sa fidélité mesure sa capacité à")
    print("  les imiter, pas la justesse des conseils. Il apporte l'explicabilité et un second avis.")

    # ---- Sensibilité du facteur d'aggravation ----
    print("\n" + "=" * 74 + "\nSENSIBILITÉ DU FACTEUR D'AGGRAVATION (référence : 1.25)\n" + "=" * 74)
    rnd = random.Random(11)
    profils = [({k: rnd.choice(["oui", "parfois", "non"]) for k in IDS},
                dict(usage=rnd.choice(["autre", "etudiant", "professionnel"]), banque_en_ligne=rnd.random() < .5))
               for _ in range(5000)]

    def resume(f):
        out = []
        for r, ctx in profils:
            recos, al = appliquer_regles(r, ctx, facteur_aggravation=f)
            out.append((recos[0]["id"] if recos else None, classer_profil(calculer_score(r), recos, al)[0]))
        return out

    ref = resume(1.25)
    print("  facteur | même action n°1 | même profil")
    for f in (1.0, 1.1, 1.25, 1.5, 2.0):
        cur = resume(f)
        print(f"   {f:5.2f}  |      {sum(a[0] == b[0] for a, b in zip(ref, cur)) / len(ref):6.1%}     |  "
              f"{sum(a[1] == b[1] for a, b in zip(ref, cur)) / len(ref):6.1%}")

    # ---- Avis externes + gabarit ----
    print("\n" + "=" * 74 + "\nAVIS EXTERNES\n" + "=" * 74)
    ecrire_modele_avis()
    comparer_avis_externes(arbre)

    # ---- Figures / exports pour le rapport ----
    DOCS.mkdir(exist_ok=True)
    modele_reel, _ = entrainer_arbre()
    try:
        from sklearn.tree import export_text
        (DOCS / "arbre_decision_reel.txt").write_text(
            f"Arbre RÉEL utilisé par l'application (profondeur {modele_reel.get_depth()}, {modele_reel.tree_.node_count} nœuds)\n"
            "Valeurs 0 = Non, 0.5 = Parfois, 1 = Oui.  Les ctx_* valent 0 ou 1.\n\n"
            + export_text(modele_reel, feature_names=FEATURE_NOMS), encoding="utf-8")
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from sklearn.tree import plot_tree
        m3, _ = entrainer_arbre(profondeur=3)
        plt.figure(figsize=(18, 8))
        plot_tree(m3, feature_names=FEATURE_NOMS, class_names=list(m3.classes_), filled=True, fontsize=7)
        plt.title(f"ILLUSTRATION SIMPLIFIÉE (profondeur 3) - le modèle utilisé est de profondeur {modele_reel.get_depth()}.\n"
                  "Les feuilles encore impures (gini > 0) montrent ce que l'arbre simplifié ne distingue pas.", fontsize=11)
        plt.savefig(DOCS / "arbre_decision_illustration.png", dpi=110, bbox_inches="tight")
        print("\nFichiers écrits dans docs/ : arbre_decision_reel.txt, arbre_decision_illustration.png, avis_externes_modele.csv")
    except Exception as e:     # matplotlib facultatif
        print("Figure non générée :", e)


if __name__ == "__main__":
    main()
