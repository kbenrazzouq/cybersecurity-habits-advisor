"""
test_moteur.py - Tests automatiques (unittest, aucune dépendance en plus).
Lancer avec :  python -m unittest -v test_moteur
Couvre : score, validation des entrées, règles, profil plafonné, contexte, et SÉCURITÉ du chargement du modèle.
"""
import json
import os
import pickle
import random
import shutil
import tempfile
import unittest
from pathlib import Path

import moteur
from moteur import (IDS, QUESTIONS, analyser, appliquer_regles, calculer_score, charger_modele, classer_profil,
                    entrainer_arbre, exporter_arbre, generer_dataset, sauvegarder_modele, valider_arbre,
                    valider_contexte, valider_reponses, _vecteur, ORDRE_PROFIL)


def rep(non=(), parfois=()):
    """Réponses : toutes 'oui' sauf les habitudes listées."""
    return {k: ("non" if k in non else "parfois" if k in parfois else "oui") for k in IDS}


class TestScore(unittest.TestCase):
    def test_extremes(self):
        self.assertEqual(calculer_score(rep()), 100)
        self.assertEqual(calculer_score(rep(non=IDS)), 0)

    def test_parfois_vaut_la_moitie(self):
        self.assertEqual(calculer_score(rep(parfois=IDS)), 50)

    def test_booleens_acceptes(self):
        self.assertEqual(calculer_score({k: True for k in IDS}), 100)


class TestValidation(unittest.TestCase):
    def test_reponse_manquante(self):
        r = rep(); del r["a2f"]
        with self.assertRaises(ValueError):
            valider_reponses(r)

    def test_identifiant_inconnu(self):
        r = rep(); r["pirate"] = "oui"
        with self.assertRaises(ValueError):
            valider_reponses(r)

    def test_valeurs_invalides(self):
        for mauvaise in (None, "peut-être", 0.3, 2, [], {}):
            r = rep(); r["a2f"] = mauvaise
            with self.assertRaises(ValueError, msg=repr(mauvaise)):
                valider_reponses(r)

    def test_contexte_invalide(self):
        for ctx in ({"usage": "alien"}, {"banque_en_ligne": "oui"}, {"inconnu": 1}, "texte"):
            with self.assertRaises(ValueError, msg=repr(ctx)):
                valider_contexte(ctx)


class TestRegles(unittest.TestCase):
    def test_combinaison_2fa_mdp(self):
        recos, alertes = appliquer_regles(rep(non={"mdp_unique", "a2f"}))
        self.assertEqual(len(alertes), 1)
        self.assertEqual(recos[0]["priorite"], 6.25)          # 5 x 1.25

    def test_parfois_ne_declenche_pas_de_combinaison(self):
        recos, alertes = appliquer_regles(rep(non={"mdp_unique"}, parfois={"a2f"}))
        self.assertEqual(alertes, [])

    def test_parfois_pese_moitie(self):
        recos, _ = appliquer_regles(rep(parfois={"a2f"}))
        self.assertEqual(recos[0]["priorite"], 2.5)
        self.assertEqual(recos[0]["niveau"], "important")
        self.assertEqual(recos[0]["reponse"], "parfois")

    def test_tout_bon_aucune_action(self):
        self.assertEqual(appliquer_regles(rep()), ([], []))

    def test_gain_rapide(self):
        recos, _ = appliquer_regles(rep(non={"a2f", "mdp_unique"}))
        par_id = {r["id"]: r for r in recos}
        self.assertTrue(par_id["a2f"]["gain_rapide"])          # effort 1, priorité 6.25
        self.assertFalse(par_id["mdp_unique"]["gain_rapide"])  # effort 2

    def test_contexte_ajoute_10_pour_cent(self):
        sans, _ = appliquer_regles(rep(non={"a2f"}))
        avec, _ = appliquer_regles(rep(non={"a2f"}), {"banque_en_ligne": True})
        self.assertEqual(sans[0]["priorite"], 5.0)
        self.assertEqual(avec[0]["priorite"], 5.5)

    def test_contexte_sans_effet_sur_habitude_non_ciblee(self):
        sans, _ = appliquer_regles(rep(non={"antivirus"}))
        avec, _ = appliquer_regles(rep(non={"antivirus"}), {"banque_en_ligne": True, "usage": "etudiant"})
        self.assertEqual(sans[0]["priorite"], avec[0]["priorite"])

    def test_tri_decroissant(self):
        recos, _ = appliquer_regles(rep(non=IDS))
        prios = [r["priorite"] for r in recos]
        self.assertEqual(prios, sorted(prios, reverse=True))


class TestProfil(unittest.TestCase):
    def test_cas_du_sujet_n_est_plus_avance(self):
        """Pas de 2FA + mots de passe réutilisés : score 76 mais profil plafonné."""
        res = analyser(rep(non={"a2f", "mdp_unique"}))
        self.assertEqual(res["score"], 76)
        self.assertEqual(res["profil_selon_score"], "Utilisateur avancé")
        self.assertEqual(res["profil"], "Utilisateur moyen")
        self.assertIsNotNone(res["raison_plafond"])

    def test_deux_alertes_donnent_debutant(self):
        res = analyser(rep(non={"a2f", "mdp_unique", "phishing"}))
        self.assertGreaterEqual(len(res["alertes"]), 2)
        self.assertEqual(res["profil"], "Débutant à risque")

    def test_pas_de_plafond_sans_action_critique(self):
        res = analyser(rep(non={"verrouillage", "gestionnaire"}))
        self.assertEqual(res["profil"], "Utilisateur avancé")
        self.assertIsNone(res["raison_plafond"])

    def test_proprietes_sur_profils_aleatoires(self):
        """Pour 3000 profils : le plafond ne relève jamais le profil, et critique => jamais 'avancé'."""
        rnd = random.Random(1)
        for _ in range(3000):
            r = {k: rnd.choice(["oui", "parfois", "non"]) for k in IDS}
            ctx = dict(usage=rnd.choice(["autre", "etudiant", "professionnel"]), banque_en_ligne=rnd.random() < .5)
            res = analyser(r, contexte=ctx)
            self.assertLessEqual(ORDRE_PROFIL[res["profil"]], ORDRE_PROFIL[res["profil_selon_score"]])
            self.assertTrue(0 <= res["score"] <= 100)
            if any(x["niveau"] == "critique" for x in res["recommandations"]):
                self.assertNotEqual(res["profil"], "Utilisateur avancé")
            if len(res["alertes"]) >= 2:
                self.assertEqual(res["profil"], "Débutant à risque")


class TestModele(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sk, cls.metriques = entrainer_arbre(profondeur=10, n=1500)
        cls.arbre = valider_arbre(exporter_arbre(cls.sk))

    def setUp(self):
        self.dossier = Path(tempfile.mkdtemp())
        self.chemin = self.dossier / "modele.json"

    def tearDown(self):
        shutil.rmtree(self.dossier, ignore_errors=True)

    def _ecrire_avec_empreinte(self, contenu: bytes):
        """Simule un attaquant qui modifie le fichier ET son empreinte voisine."""
        import hashlib
        self.chemin.write_bytes(contenu)
        moteur._chemin_empreinte(self.chemin).write_text(hashlib.sha256(contenu).hexdigest())

    def test_predictions_identiques_a_scikit_learn(self):
        X, _ = generer_dataset(n=500, graine=3)
        self.assertEqual(list(self.sk.predict(X)), self.arbre.predict(X))

    def test_aller_retour(self):
        sauvegarder_modele(self.sk, self.metriques, self.chemin)
        arbre, metriques = charger_modele(self.chemin)
        X, _ = generer_dataset(n=200, graine=4)
        self.assertEqual(arbre.predict(X), self.arbre.predict(X))
        self.assertIn("fidelite_nouveaux_profils", metriques)

    def test_fichier_absent(self):
        self.assertIsNone(charger_modele(self.dossier / "absent.json"))

    def test_octet_modifie_detecte_par_empreinte(self):
        sauvegarder_modele(self.sk, self.metriques, self.chemin)
        contenu = bytearray(self.chemin.read_bytes()); contenu[40] ^= 1
        self.chemin.write_bytes(bytes(contenu))
        self.assertIsNone(charger_modele(self.chemin))

    def test_empreinte_absente_refuse(self):
        sauvegarder_modele(self.sk, self.metriques, self.chemin)
        moteur._chemin_empreinte(self.chemin).unlink()
        self.assertIsNone(charger_modele(self.chemin))

    def test_fichier_trop_gros_refuse(self):
        self._ecrire_avec_empreinte(b" " * (moteur.TAILLE_MAX_MODELE + 1))
        self.assertIsNone(charger_modele(self.chemin))

    def test_pickle_piege_jamais_execute(self):
        """Un attaquant remplace le modèle par un pickle malveillant (et recalcule l'empreinte) : refusé, non exécuté."""
        marqueur = self.dossier / "EXECUTE"

        class Piege:
            def __reduce__(self):
                return (os.mkdir, (str(marqueur),))          # charge utile inoffensive : crée un dossier témoin

        octets = pickle.dumps(Piege())
        self._ecrire_avec_empreinte(octets)
        self.assertIsNone(charger_modele(self.chemin))
        self.assertFalse(marqueur.exists(), "le contenu du fichier a été exécuté !")

    def test_temoin_le_piege_est_reellement_dangereux(self):
        """Témoin : avec pickle.loads, la même charge utile s'exécute. Prouve que le test précédent a un sens."""
        marqueur = self.dossier / "TEMOIN"

        class Piege:
            def __reduce__(self):
                return (os.mkdir, (str(marqueur),))

        pickle.loads(pickle.dumps(Piege()))                  # noqa: S301 (volontaire, dossier temporaire)
        self.assertTrue(marqueur.exists())

    def test_structures_malveillantes_refusees(self):
        base = exporter_arbre(self.sk)

        def variante(modif):
            d = json.loads(json.dumps(base)); modif(d); return d

        cas = {
            "boucle (enfant <= parent)": lambda d: d["noeuds"]["gauche"].__setitem__(0, 0),
            "enfant hors limites":       lambda d: d["noeuds"]["droite"].__setitem__(0, 10 ** 9),
            "variable hors limites":     lambda d: d["noeuds"]["feature"].__setitem__(0, 999),
            "seuil non fini":            lambda d: d["noeuds"]["seuil"].__setitem__(0, float("inf")),
            "classe hors limites":       lambda d: d["noeuds"]["classe"].__setitem__(0, 99),
            "classe inconnue":           lambda d: d["classes"].__setitem__(0, "rm -rf"),
            "tailles incohérentes":      lambda d: d["noeuds"]["seuil"].pop(),
            "questions modifiées":       lambda d: d["features"].reverse(),
            "format inconnu":            lambda d: d.__setitem__("format", "pickle"),
        }
        for nom, modif in cas.items():
            with self.subTest(nom):
                with self.assertRaises(ValueError):
                    valider_arbre(variante(modif))
                self._ecrire_avec_empreinte(json.dumps(variante(modif)).encode())
                self.assertIsNone(charger_modele(self.chemin))

    def test_le_moteur_n_importe_pas_pickle_ni_joblib(self):
        source = Path(moteur.__file__).read_text(encoding="utf-8")
        for interdit in ("import pickle", "import joblib", "joblib.load", "pickle.load"):
            self.assertNotIn(interdit, source)

    def test_modele_livre_valide(self):
        """Le modèle fourni dans le projet passe la vérification et prédit comme les règles (>= 97 %)."""
        charge = charger_modele()
        self.assertIsNotNone(charge, "modele_arbre.json absent ou altéré : relancer python entrainer.py")
        arbre, metriques = charge
        self.assertGreaterEqual(metriques["fidelite_nouveaux_profils"], 0.97)


class TestAnalyse(unittest.TestCase):
    def test_second_avis(self):
        arbre, _ = moteur.obtenir_modele()
        res = analyser(rep(non={"a2f"}), arbre)
        self.assertIn(res["accord_arbre"], (True, False))
        self.assertEqual(res["action_arbre"], "a2f")

    def test_rapport_contient_references_et_gains_rapides(self):
        texte = moteur.rapport_texte(analyser(rep(non={"a2f", "mdp_unique"})))
        for attendu in ("GAINS RAPIDES", "Références", "ANSSI", "ACTIONS PRIORITAIRES"):
            self.assertIn(attendu, texte)

    def test_chaque_question_a_au_moins_une_source_connue(self):
        for q in QUESTIONS:
            self.assertTrue(q["sources"], q["id"])
            self.assertTrue(all(s in moteur.SOURCES for s in q["sources"]), q["id"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
