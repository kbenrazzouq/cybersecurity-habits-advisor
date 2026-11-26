"""
entrainer.py - Entraîne l'arbre de décision et l'enregistre en JSON (modele_arbre.json + empreinte SHA-256).
Lancer avec :  python entrainer.py
À relancer si les questions ou les règles de moteur.py changent. Nécessite scikit-learn (entraînement seulement).
"""
from moteur import entrainer_arbre, sauvegarder_modele, charger_modele, CHEMIN_MODELE

if __name__ == "__main__":
    modele, metriques = entrainer_arbre()
    sauvegarder_modele(modele, metriques)
    assert charger_modele() is not None, "le modèle enregistré n'a pas passé la vérification"
    print(f"Modèle enregistré : {CHEMIN_MODELE.name} (+ empreinte .sha256), vérifié au rechargement.")
    print(f"  Fidélité aux règles sur profils jamais vus : {metriques['fidelite_nouveaux_profils']:.1%}"
          f" | précision test : {metriques['precision_test']:.1%}"
          f" | référence 'toujours la classe majoritaire' : {metriques['baseline_majoritaire']:.1%}")
    print(f"  Arbre : profondeur {metriques['profondeur']}, {metriques['nb_noeuds']} nœuds.")
