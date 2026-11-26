"""
moteur.py - Cœur du système intelligent de recommandation de bonnes pratiques de sécurité.

Trois techniques combinées (celles du sujet) :
  1. Système de RÈGLES         : détecte chaque mauvaise habitude + règles de combinaison (risques aggravés)
  2. RECOMMANDATION PAR PROFIL : score, profil (débutant / moyen / avancé) et contexte (usage, banque en ligne)
  3. ARBRE DE DÉCISION         : modèle appris (scikit-learn) qui APPROXIME les règles et donne un second avis

Les règles restent la référence. L'arbre est un modèle interprétable entraîné sur des profils fictifs
étiquetés par les règles : il sert de contrôle de cohérence, pas de vérité indépendante (voir docs/).

Réponses : "oui" (1.0) / "parfois" (0.5) / "non" (0.0). Les booléens True/False sont acceptés (oui/non).
Sécurité : le modèle est stocké en JSON (aucun pickle), validé et contrôlé par empreinte SHA-256 au chargement.
"""
import hashlib
import json
import math
import random
from pathlib import Path

# ----------------------------------------------------------------------------
# 0. RÉFÉRENCES (indicatives : elles étayent le PRINCIPE de chaque conseil, pas les valeurs de gravité)
# ----------------------------------------------------------------------------
SOURCES = {
    "anssi_mfa": "ANSSI / CNIL - Recommandations relatives à l'authentification multifacteur et aux mots de passe (2021)",
    "cnil_mdp": "CNIL - Délibération n° 2022-100 du 21 juillet 2022 (recommandation sur les mots de passe)",
    "cyber10": "Cybermalveillance.gouv.fr / ANSSI - Les 10 mesures essentielles pour assurer votre sécurité numérique",
    "cyber_bp": "Cybermalveillance.gouv.fr - Fiches de bonnes pratiques (mots de passe, mises à jour, sauvegardes, appareils mobiles)",
    "nist63b": "NIST SP 800-63B-4 (juillet 2025) - Authentication and Authenticator Management",
    "owasp_cs": "OWASP - Credential Stuffing Prevention Cheat Sheet",
}

# ----------------------------------------------------------------------------
# 1. BASE DE CONNAISSANCES : une ligne = une habitude évaluée
#    gravite : 1 (faible) à 5 (critique)   |   effort : 1 (facile) à 3 (difficile)
# ----------------------------------------------------------------------------
QUESTIONS = [
    dict(id="mdp_unique", categorie="Mots de passe", gravite=5, effort=2,
         question="Utilises-tu un mot de passe DIFFÉRENT pour chaque site ?",
         risque="Si un seul site est piraté, tous tes comptes le sont (credential stuffing).",
         conseil="Utilise un mot de passe unique par site.",
         sources=["owasp_cs", "cyber10"]),
    dict(id="a2f", categorie="Authentification", gravite=5, effort=1,
         question="As-tu activé la double authentification (2FA) sur ton email et tes comptes importants ?",
         risque="Un mot de passe volé suffit à prendre le contrôle de ton compte.",
         conseil="Active la double authentification (2FA) sur ton email, ta banque et tes réseaux sociaux, "
                 "de préférence avec une application d'authentification ou une clé de sécurité plutôt que par SMS.",
         sources=["anssi_mfa", "nist63b"]),
    dict(id="maj", categorie="Mises à jour", gravite=4, effort=1,
         question="Fais-tu régulièrement les mises à jour de ton téléphone et de ton ordinateur ?",
         risque="Les failles connues restent ouvertes et sont exploitées par les pirates.",
         conseil="Active les mises à jour automatiques (système et applications).",
         sources=["cyber10"]),
    dict(id="phishing", categorie="Phishing", gravite=4, effort=1,
         question="Vérifies-tu les liens et l'expéditeur avant de cliquer sur un mail ou un SMS ?",
         risque="Le phishing permet de voler tes identifiants ou d'installer un logiciel malveillant.",
         conseil="Ne clique jamais sur un lien suspect : vérifie l'expéditeur et passe par le site officiel.",
         sources=["cyber10"]),
    dict(id="sources", categorie="Applications", gravite=4, effort=1,
         question="Télécharges-tu tes logiciels et applications uniquement depuis des sources officielles ?",
         risque="Les logiciels piratés ou non officiels contiennent souvent des malwares.",
         conseil="Télécharge uniquement depuis les stores officiels ou le site de l'éditeur.",
         sources=["cyber10"]),
    dict(id="mdp_long", categorie="Mots de passe", gravite=3, effort=1,
         question="Tes mots de passe sont-ils longs (12 caractères ou plus, ou une phrase de passe) ?",
         risque="Un mot de passe court est deviné rapidement par force brute.",
         conseil="Utilise des mots de passe longs : 12 caractères ou plus, ou une phrase de passe.",
         sources=["cnil_mdp", "nist63b"]),
    dict(id="gestionnaire", categorie="Mots de passe", gravite=3, effort=2,
         question="Utilises-tu un gestionnaire de mots de passe ?",
         risque="Sans gestionnaire, on réutilise ou on note ses mots de passe de façon peu sûre.",
         conseil="Installe un gestionnaire de mots de passe (ex. Bitwarden, KeePass).",
         sources=["anssi_mfa", "nist63b"]),
    dict(id="wifi", categorie="Réseau", gravite=3, effort=2,
         question="Évites-tu de te connecter à des comptes sensibles sur un Wi-Fi public sans VPN ?",
         risque="Un attaquant sur le même réseau peut espionner ou détourner ta connexion.",
         conseil="Évite le Wi-Fi public pour les comptes sensibles, ou utilise un VPN.",
         sources=["cyber10"]),
    dict(id="sauvegarde", categorie="Données", gravite=3, effort=2,
         question="Fais-tu des sauvegardes régulières de tes fichiers importants ?",
         risque="Panne, vol ou ransomware : tu peux perdre tes données définitivement.",
         conseil="Fais une sauvegarde régulière (règle 3-2-1 : 3 copies, 2 supports, 1 hors site).",
         sources=["cyber10"]),
    dict(id="verrouillage", categorie="Appareils", gravite=3, effort=1,
         question="Ton téléphone et ton ordinateur sont-ils verrouillés (code, empreinte, mot de passe) ?",
         risque="En cas de perte ou de vol, tout est accessible à n'importe qui.",
         conseil="Active le verrouillage automatique de l'écran avec un code ou une empreinte.",
         sources=["cyber_bp"]),
    dict(id="antivirus", categorie="Appareils", gravite=2, effort=1,
         question="As-tu un antivirus actif (ou Microsoft Defender activé) ?",
         risque="Les logiciels malveillants passent inaperçus.",
         conseil="Active un antivirus à jour (Microsoft Defender suffit pour la plupart des usages).",
         sources=["cyber10"]),
    dict(id="fuites", categorie="Comptes", gravite=2, effort=1,
         question="Vérifies-tu de temps en temps si tes comptes ont fuité (ex. haveibeenpwned.com) ?",
         risque="Tu continues d'utiliser un mot de passe déjà exposé dans une fuite de données.",
         conseil="Vérifie tes comptes sur haveibeenpwned.com et change les mots de passe exposés.",
         sources=["nist63b"]),
]

IDS = [q["id"] for q in QUESTIONS]
PAR_ID = {q["id"]: q for q in QUESTIONS}
CATEGORIES = list(dict.fromkeys(q["categorie"] for q in QUESTIONS))   # ordre de première apparition

# Réponses possibles -> crédit (part de la bonne habitude réellement en place)
NIVEAUX_REPONSE = {"oui": 1.0, "parfois": 0.5, "non": 0.0}

# ----------------------------------------------------------------------------
# 2. RÈGLES DE COMBINAISON : deux habitudes absentes ("non") ensemble = risque aggravé
# ----------------------------------------------------------------------------
REGLES_COMBINAISON = [
    dict(si_manquants={"mdp_unique", "a2f"}, cibles={"mdp_unique", "a2f"},
         message="Mots de passe réutilisés ET pas de 2FA : un seul vol de mot de passe donne accès à tous tes comptes."),
    dict(si_manquants={"phishing", "a2f"}, cibles={"phishing", "a2f"},
         message="Pas de vigilance face au phishing ET pas de 2FA : un faux site suffit pour perdre ton compte."),
    dict(si_manquants={"sauvegarde", "sources"}, cibles={"sauvegarde", "sources"},
         message="Logiciels non officiels ET pas de sauvegarde : un ransomware ferait perdre tes données."),
    dict(si_manquants={"wifi", "a2f"}, cibles={"wifi", "a2f"},
         message="Wi-Fi public sans protection ET pas de 2FA : une session interceptée est directement exploitable."),
]
# Coefficient d'aggravation par règle déclenchée. Valeur choisie par expertise ; sa sensibilité est mesurée
# dans tests_profils.py (le top-1 change très peu entre 1.1 et 1.5).
FACTEUR_AGGRAVATION = 1.25

# ----------------------------------------------------------------------------
# 3. CONTEXTE (facultatif) : ajuste la priorité de certaines habitudes (+10 % par contexte pertinent)
# ----------------------------------------------------------------------------
USAGES = {"autre": "Autre / je préfère ne pas le dire", "etudiant": "Étudiant(e)", "professionnel": "Professionnel(le)"}
CONTEXTE_DEFAUT = {"usage": "autre", "banque_en_ligne": False}
BONUS_CONTEXTE = 0.10
HABITUDES_CIBLEES = {
    "banque_en_ligne": {"a2f", "mdp_unique", "phishing", "wifi"},      # enjeu financier
    "etudiant": {"sauvegarde", "wifi"},                                # mémoires, projets, Wi-Fi du campus
    "professionnel": {"maj", "phishing", "gestionnaire"},              # comptes et données de l'organisation
}
CONSEILS_CONTEXTE = {
    "banque_en_ligne": "Banque en ligne : active les alertes de transaction et utilise uniquement l'application officielle de ta banque.",
    "etudiant": "Étudiant : sauvegarde régulièrement ton mémoire, tes projets et tes cours (une copie hors site) et méfie-toi des faux mails de l'administration ou de la scolarité.",
    "professionnel": "Professionnel : sépare tes comptes professionnels et personnels, et signale vite à ton service informatique tout mail suspect.",
}

# ----------------------------------------------------------------------------
# 4. PROFILS
# ----------------------------------------------------------------------------
SEUIL_DEBUTANT = 40
SEUIL_MOYEN = 70
ORDRE_PROFIL = {"Débutant à risque": 0, "Utilisateur moyen": 1, "Utilisateur avancé": 2}

PROFILS = {
    "Débutant à risque": dict(
        emoji="🔴",
        message="Tes comptes sont très exposés. Commence par les bases, une à la fois.",
        bonus=["Change d'abord les mots de passe de ton email principal et de ta banque.",
               "Fais ces corrections dans l'ordre de la liste : les 3 premières suffisent à réduire fortement le risque."]),
    "Utilisateur moyen": dict(
        emoji="🟠",
        message="Tu as de bonnes bases mais il reste des failles à combler.",
        bonus=["Étends la 2FA à tous tes comptes importants.",
               "Entraîne-toi à reconnaître les mails de phishing (tests en ligne gratuits)."]),
    "Utilisateur avancé": dict(
        emoji="🟢",
        message="Très bon niveau ! Il reste quelques améliorations pour aller plus loin.",
        bonus=["Utilise une clé de sécurité physique (FIDO2) pour tes comptes critiques.",
               "Fais un audit annuel de tes comptes et supprime ceux que tu n'utilises plus."]),
}

SEUIL_CRITIQUE = 5.0
SEUIL_IMPORTANT = 2.5
SEUIL_GAIN_RAPIDE = 4.0     # gain rapide = effort 1 ET priorité >= 4


# ----------------------------------------------------------------------------
# VALIDATION DES ENTRÉES (aucune entrée n'est supposée fiable)
# ----------------------------------------------------------------------------
def _niveau_reponse(valeur):
    if isinstance(valeur, bool):
        return 1.0 if valeur else 0.0
    if isinstance(valeur, str) and valeur.strip().lower() in NIVEAUX_REPONSE:
        return NIVEAUX_REPONSE[valeur.strip().lower()]
    if isinstance(valeur, (int, float)) and float(valeur) in NIVEAUX_REPONSE.values():
        return float(valeur)
    raise ValueError(f"Réponse invalide : {valeur!r} (attendu : oui / parfois / non)")


def valider_reponses(reponses):
    """Retourne {id: niveau (1.0, 0.5 ou 0.0)}. Lève ValueError si une réponse manque, est inconnue ou invalide."""
    if not isinstance(reponses, dict):
        raise ValueError("Les réponses doivent être un dictionnaire {id: réponse}.")
    manquantes = [k for k in IDS if k not in reponses]
    inconnues = [k for k in reponses if k not in PAR_ID]
    if manquantes or inconnues:
        raise ValueError(f"Réponses manquantes : {manquantes} ; identifiants inconnus : {inconnues}")
    return {k: _niveau_reponse(reponses[k]) for k in IDS}


def valider_contexte(contexte):
    """Retourne un contexte normalisé {usage, banque_en_ligne}. None = contexte neutre."""
    ctx = dict(CONTEXTE_DEFAUT)
    if contexte:
        if not isinstance(contexte, dict) or set(contexte) - set(CONTEXTE_DEFAUT):
            raise ValueError("Contexte invalide.")
        ctx.update(contexte)
    if ctx["usage"] not in USAGES:
        raise ValueError(f"Usage invalide : {ctx['usage']!r}")
    if not isinstance(ctx["banque_en_ligne"], bool):
        raise ValueError("banque_en_ligne doit être True ou False.")
    return ctx


def contextes_actifs(ctx):
    actifs = []
    if ctx["banque_en_ligne"]:
        actifs.append("banque_en_ligne")
    if ctx["usage"] in ("etudiant", "professionnel"):
        actifs.append(ctx["usage"])
    return actifs


# ----------------------------------------------------------------------------
# FONCTIONS
# ----------------------------------------------------------------------------
def calculer_score(reponses):
    """Score sur 100 : somme des gravités x crédit de chaque habitude / total possible."""
    niveaux = valider_reponses(reponses)
    total = sum(q["gravite"] for q in QUESTIONS)
    obtenus = sum(PAR_ID[k]["gravite"] * n for k, n in niveaux.items())
    return round(obtenus / total * 100)


def profil_selon_score(score):
    if score < SEUIL_DEBUTANT:
        return "Débutant à risque"
    if score < SEUIL_MOYEN:
        return "Utilisateur moyen"
    return "Utilisateur avancé"


def classer_profil(score, recommandations=(), alertes=()):
    """
    Recommandation fondée sur un profil. Le score est une somme : il ne doit pas masquer une faille grave.
    Plafonds : au moins 2 règles de combinaison déclenchées -> "Débutant à risque" ;
               au moins 1 action critique -> "Utilisateur moyen" au mieux.
    Retourne (profil, raison_du_plafonnement ou None).
    """
    profil = profil_selon_score(score)
    plafond, raison = None, None
    if len(alertes) >= 2:
        plafond = "Débutant à risque"
        raison = "Plusieurs risques combinés sont présents : ton profil est ramené au niveau le plus prudent."
    elif any(r["niveau"] == "critique" for r in recommandations):
        plafond = "Utilisateur moyen"
        raison = "Une action critique reste à faire : ton profil ne peut pas dépasser « Utilisateur moyen »."
    if plafond and ORDRE_PROFIL[profil] > ORDRE_PROFIL[plafond]:
        return plafond, raison
    return profil, None


def niveau(priorite):
    if priorite >= SEUIL_CRITIQUE:
        return "critique"
    if priorite >= SEUIL_IMPORTANT:
        return "important"
    return "recommandé"


EMOJI_NIVEAU = {"critique": "🔴", "important": "🟠", "recommandé": "🟡"}


def appliquer_regles(reponses, contexte=None, facteur_aggravation=None):
    """
    Système de règles.
    Pour chaque habitude manquante (non ou parfois) :
        priorité = gravité x facteur d'aggravation x poids du manque x facteur de contexte
      - facteur d'aggravation : x1.25 par règle de combinaison déclenchée (seulement si les habitudes sont à "non")
      - poids du manque       : 1.0 si "non", 0.5 si "parfois"
      - facteur de contexte   : +10 % par contexte pertinent (banque en ligne, étudiant, professionnel)
    Retourne (recommandations triées, alertes de combinaison).
    """
    niveaux = valider_reponses(reponses)
    ctx = valider_contexte(contexte)
    f_aggr = FACTEUR_AGGRAVATION if facteur_aggravation is None else facteur_aggravation
    manquants = {k for k, n in niveaux.items() if n < 1.0}
    absents = {k for k, n in niveaux.items() if n == 0.0}
    alertes = []
    facteur = {k: 1.0 for k in manquants}
    for regle in REGLES_COMBINAISON:
        if regle["si_manquants"] <= absents:
            alertes.append(regle["message"])
            for cible in regle["cibles"]:
                facteur[cible] *= f_aggr

    actifs = contextes_actifs(ctx)
    recos = []
    for k in manquants:
        q = PAR_ID[k]
        f_ctx = 1 + BONUS_CONTEXTE * sum(k in HABITUDES_CIBLEES[c] for c in actifs)
        priorite = round(q["gravite"] * facteur[k] * (1.0 - niveaux[k]) * f_ctx, 2)
        recos.append(dict(id=k, categorie=q["categorie"], conseil=q["conseil"], risque=q["risque"],
                          gravite=q["gravite"], effort=q["effort"], priorite=priorite, niveau=niveau(priorite),
                          reponse="parfois" if niveaux[k] == 0.5 else "non",
                          gain_rapide=(q["effort"] == 1 and priorite >= SEUIL_GAIN_RAPIDE),
                          sources=[SOURCES[s] for s in q["sources"]]))
    # tri : priorité décroissante, puis effort croissant (le plus facile d'abord), puis ordre de la base
    recos.sort(key=lambda r: (-r["priorite"], r["effort"], IDS.index(r["id"])))
    return recos, alertes


# ----- Arbre de décision -----
FEATURE_NOMS = IDS + ["ctx_banque", "ctx_etudiant", "ctx_pro"]
CLASSES_POSSIBLES = set(IDS) | {"aucune"}


def _vecteur(niveaux, ctx):
    return ([niveaux[k] for k in IDS]
            + [1.0 if ctx["banque_en_ligne"] else 0.0,
               1.0 if ctx["usage"] == "etudiant" else 0.0,
               1.0 if ctx["usage"] == "professionnel" else 0.0])


def etiquette_regles(niveaux, ctx):
    """Action n°1 du système de règles (ou 'aucune')."""
    recos, _ = appliquer_regles(niveaux, ctx)
    return recos[0]["id"] if recos else "aucune"


def generer_dataset(n=8000, graine=42):
    """
    Profils fictifs. Chaque personne a un "niveau de prudence" aléatoire ; chaque habitude est "oui" avec cette
    probabilité, sinon "parfois" (35 %) ou "non". Le contexte est tiré au hasard.
    L'étiquette est l'action n°1 du système de règles : l'arbre APPREND donc les règles (il ne les valide pas).
    """
    rnd = random.Random(graine)
    X, y = [], []
    for _ in range(n):
        prudence = rnd.random()
        niveaux = {}
        for k in IDS:
            r = rnd.random()
            niveaux[k] = 1.0 if r < prudence else (0.5 if rnd.random() < 0.35 else 0.0)
        ctx = dict(usage=rnd.choice(list(USAGES)), banque_en_ligne=rnd.random() < 0.5)
        X.append(_vecteur(niveaux, ctx))
        y.append(etiquette_regles(niveaux, ctx))
    return X, y


class ArbreDecision:
    """Arbre de décision en lecture seule, construit depuis des tableaux JSON (aucun code exécutable)."""

    def __init__(self, classes, gauche, droite, feature, seuil, classe):
        self.classes, self.gauche, self.droite = classes, gauche, droite
        self.feature, self.seuil, self.classe = feature, seuil, classe

    def predire(self, x):
        i = 0
        while self.gauche[i] != -1:          # la validation garantit que les enfants ont un indice supérieur : pas de boucle
            i = self.gauche[i] if x[self.feature[i]] <= self.seuil[i] else self.droite[i]
        return self.classes[self.classe[i]]

    def predict(self, X):
        return [self.predire(x) for x in X]

    @property
    def nb_noeuds(self):
        return len(self.gauche)


def exporter_arbre(modele_sklearn):
    """Convertit un DecisionTreeClassifier entraîné en dictionnaire JSON-compatible."""
    t = modele_sklearn.tree_
    return dict(
        format="arbre-json-v1", features=FEATURE_NOMS, classes=[str(c) for c in modele_sklearn.classes_],
        noeuds=dict(gauche=[int(v) for v in t.children_left], droite=[int(v) for v in t.children_right],
                    feature=[int(v) for v in t.feature], seuil=[float(v) for v in t.threshold],
                    classe=[int(v.argmax()) for v in t.value[:, 0, :]]))


def _entier(v):
    return isinstance(v, int) and not isinstance(v, bool)


def valider_arbre(donnees):
    """Valide la structure d'un arbre chargé depuis un fichier non fiable. Retourne un ArbreDecision ou lève ValueError."""
    if not isinstance(donnees, dict) or donnees.get("format") != "arbre-json-v1":
        raise ValueError("format inconnu")
    if donnees.get("features") != FEATURE_NOMS:
        raise ValueError("questions modifiées : modèle périmé")
    classes = donnees.get("classes")
    if (not isinstance(classes, list) or not classes
            or not all(isinstance(c, str) and c in CLASSES_POSSIBLES for c in classes)):
        raise ValueError("classes invalides")
    nd = donnees.get("noeuds")
    if not isinstance(nd, dict):
        raise ValueError("noeuds manquants")
    g, d, f, s, c = (nd.get(k) for k in ("gauche", "droite", "feature", "seuil", "classe"))
    if not all(isinstance(v, list) for v in (g, d, f, s, c)):
        raise ValueError("tableaux manquants")
    n = len(g)
    if not (1 <= n <= 200_000) or not (len(d) == len(f) == len(s) == len(c) == n):
        raise ValueError("tailles incohérentes")
    for i in range(n):
        if not (_entier(g[i]) and _entier(d[i]) and _entier(c[i]) and 0 <= c[i] < len(classes)):
            raise ValueError("noeud invalide")
        if g[i] == -1 and d[i] == -1:
            continue                                            # feuille
        if not (i < g[i] < n and i < d[i] < n):
            raise ValueError("enfants invalides")
        if not (_entier(f[i]) and 0 <= f[i] < len(FEATURE_NOMS)):
            raise ValueError("variable invalide")
        if isinstance(s[i], bool) or not isinstance(s[i], (int, float)) or not math.isfinite(s[i]):
            raise ValueError("seuil invalide")
    return ArbreDecision(classes, g, d, f, s, c)


def _evaluer(arbre, X, y):
    return sum(p == t for p, t in zip(arbre.predict(X), y)) / len(y)


def entrainer_arbre(profondeur=20, n=8000, graine=42):
    """
    Entraîne l'arbre (scikit-learn, nécessaire seulement pour l'entraînement).
    Retourne (modele_sklearn, metriques). Les métriques mesurent la FIDÉLITÉ AUX RÈGLES, pas la qualité réelle des conseils.
    """
    from sklearn.model_selection import train_test_split
    from sklearn.tree import DecisionTreeClassifier
    X, y = generer_dataset(n=n, graine=graine)
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.3, random_state=graine)
    modele = DecisionTreeClassifier(max_depth=profondeur, random_state=graine).fit(X_tr, y_tr)
    arbre = valider_arbre(exporter_arbre(modele))
    classe_majoritaire = max(set(y_tr), key=y_tr.count)
    X_new, y_new = generer_dataset(n=20000, graine=graine + 1000)          # profils jamais vus
    metriques = dict(
        precision_test=round(_evaluer(arbre, X_te, y_te), 4),
        baseline_majoritaire=round(sum(t == classe_majoritaire for t in y_te) / len(y_te), 4),
        fidelite_nouveaux_profils=round(_evaluer(arbre, X_new, y_new), 4),
        profondeur=int(modele.get_depth()), nb_noeuds=int(arbre.nb_noeuds), n_profils=n)
    return modele, metriques


# ----- Sauvegarde / chargement du modèle : JSON + empreinte SHA-256, JAMAIS de pickle -----
CHEMIN_MODELE = Path(__file__).with_name("modele_arbre.json")
TAILLE_MAX_MODELE = 5_000_000   # octets


def _chemin_empreinte(chemin):
    return Path(str(chemin) + ".sha256")


def sauvegarder_modele(modele_sklearn, metriques, chemin=CHEMIN_MODELE):
    """Écrit le modèle en JSON et son empreinte SHA-256 dans un fichier voisin."""
    donnees = exporter_arbre(modele_sklearn)
    donnees["metriques"] = metriques
    contenu = json.dumps(donnees, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    Path(chemin).write_bytes(contenu)
    _chemin_empreinte(chemin).write_text(hashlib.sha256(contenu).hexdigest() + "\n", encoding="ascii")


def charger_modele(chemin=CHEMIN_MODELE):
    """
    Retourne (ArbreDecision, metriques) ou None si le fichier est absent, trop gros, altéré (empreinte),
    mal formé ou périmé. Un fichier refusé n'est JAMAIS exécuté : seul du JSON est lu.
    """
    try:
        chemin = Path(chemin)
        if not chemin.is_file() or chemin.stat().st_size > TAILLE_MAX_MODELE:
            return None
        contenu = chemin.read_bytes()
        attendu = _chemin_empreinte(chemin).read_text(encoding="ascii").strip()
        if hashlib.sha256(contenu).hexdigest() != attendu:
            return None
        donnees = json.loads(contenu.decode("utf-8"))
        arbre = valider_arbre(donnees)
        m = donnees.get("metriques")
        metriques = {k: v for k, v in (m.items() if isinstance(m, dict) else [])
                     if isinstance(v, (int, float)) and not isinstance(v, bool)}
        return arbre, metriques
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        return None


def obtenir_modele(forcer=False):
    """Charge le modèle vérifié ; sinon l'entraîne (déterministe, graine fixe) et tente de l'enregistrer."""
    if not forcer:
        charge = charger_modele()
        if charge:
            return charge
    modele, metriques = entrainer_arbre()
    try:
        sauvegarder_modele(modele, metriques)
    except OSError:
        pass                                    # dossier en lecture seule : on garde le modèle en mémoire
    return valider_arbre(exporter_arbre(modele)), metriques


def action_arbre(arbre, reponses, contexte=None):
    """Action la plus urgente prédite par l'arbre (second avis)."""
    pred = arbre.predire(_vecteur(valider_reponses(reponses), valider_contexte(contexte)))
    return None if pred == "aucune" else pred


# ----- Analyse complète -----
def analyser(reponses, modele=None, contexte=None):
    """Combine règles, profil, contexte et (si fourni) l'arbre. Retourne un dictionnaire de résultats."""
    niveaux = valider_reponses(reponses)
    ctx = valider_contexte(contexte)
    score = calculer_score(niveaux)
    recos, alertes = appliquer_regles(niveaux, ctx)
    profil, raison = classer_profil(score, recos, alertes)
    res = dict(score=score, profil=profil, profil_info=PROFILS[profil], profil_selon_score=profil_selon_score(score),
               raison_plafond=raison, recommandations=recos, alertes=alertes,
               gains_rapides=[r for r in recos if r["gain_rapide"]], contexte=ctx,
               conseils_contexte=[CONSEILS_CONTEXTE[c] for c in contextes_actifs(ctx)],
               action_arbre=None, accord_arbre=None)
    if modele is not None:
        res["action_arbre"] = action_arbre(modele, niveaux, ctx)
        res["accord_arbre"] = res["action_arbre"] == (recos[0]["id"] if recos else None)
    return res


def rapport_texte(res):
    """Rapport texte exportable (généré localement, rien n'est transmis)."""
    L = ["RAPPORT DE SÉCURITÉ PERSONNELLE",
         f"Score : {res['score']}/100",
         f"Profil : {res['profil']}",
         res["profil_info"]["message"]]
    if res.get("raison_plafond"):
        L.append(f"Note : {res['raison_plafond']} (score seul : {res['profil_selon_score']})")
    L.append("")
    if res["alertes"]:
        L.append("ALERTES (risques combinés) :")
        L += [f" ! {a}" for a in res["alertes"]]
        L.append("")
    if res["gains_rapides"]:
        L.append("GAINS RAPIDES (effort faible, gros effet) :")
        L += [f" * {r['conseil']}" for r in res["gains_rapides"]]
        L.append("")
    L.append("ACTIONS PRIORITAIRES :")
    if not res["recommandations"]:
        L.append(" Aucune : toutes les bonnes pratiques évaluées sont en place.")
    for i, r in enumerate(res["recommandations"], 1):
        partiel = " (déjà en partie en place)" if r["reponse"] == "parfois" else ""
        L.append(f" {i}. [{r['niveau'].upper()}] {r['conseil']}{partiel}")
        L.append(f"    Pourquoi : {r['risque']}")
        L.append(f"    Références : {' ; '.join(r['sources'])}")
    L.append("")
    L.append("CONSEILS ADAPTÉS À TON PROFIL :")
    L += [f" - {b}" for b in res["profil_info"]["bonus"] + res["conseils_contexte"]]
    return "\n".join(L)
