"""
console.py - Version en ligne de commande (sans Streamlit).
Lancer avec :  python console.py
"""
from moteur import QUESTIONS, USAGES, obtenir_modele, analyser, rapport_texte

REPONSES = {"o": "oui", "oui": "oui", "p": "parfois", "parfois": "parfois", "n": "non", "non": "non"}


def poser(question):
    while True:
        r = input(question + " (o = oui, p = parfois, n = non) : ").strip().lower()
        if r in REPONSES:
            return REPONSES[r]
        print("  Réponds par o, p ou n.")


def poser_contexte():
    """Contexte facultatif : Entrée = valeur par défaut."""
    print("\nContexte (facultatif, Entrée pour passer) :")
    cles = list(USAGES)
    for i, c in enumerate(cles, 1):
        print(f"  {i}. {USAGES[c]}")
    choix = input("Ton profil d'usage [1] : ").strip()
    usage = cles[int(choix) - 1] if choix.isdigit() and 1 <= int(choix) <= len(cles) else "autre"
    banque = input("Utilises-tu la banque ou le paiement en ligne ? (o/n) [n] : ").strip().lower() in ("o", "oui")
    return dict(usage=usage, banque_en_ligne=banque)


def main():
    modele, _ = obtenir_modele()
    print("=== Conseiller de sécurité personnelle ===\n")
    reponses = {q["id"]: poser(q["question"]) for q in QUESTIONS}
    contexte = poser_contexte()
    res = analyser(reponses, modele, contexte)
    print("\n" + rapport_texte(res))


if __name__ == "__main__":
    main()
