"""
test_interface.py - Tests de l'interface Streamlit (AppTest, sans navigateur).
Lancer avec :  python -m unittest -v test_interface      (nécessite streamlit, ignoré s'il est absent)
"""
import re
import unittest
from pathlib import Path

import moteur

try:
    from streamlit.testing.v1 import AppTest
except ImportError:                                           # streamlit absent : les tests sont ignorés
    AppTest = None

APP = str(Path(__file__).with_name("app.py"))


def lancer(reponses=None, defaut="Oui", banque="Non", usage=None):
    """Lance l'application, remplit le formulaire et clique sur « Analyser »."""
    at = AppTest.from_file(APP, default_timeout=30).run()
    assert not at.exception, at.exception
    reponses = reponses or {}
    for radio in at.radio:
        if radio.key == "ctx_banque":
            radio.set_value(banque)
        else:
            radio.set_value(reponses.get(radio.key, defaut))
    if usage:
        at.selectbox(key="ctx_usage").set_value(usage)
    at.button[0].click().run()
    return at


def html_de(at):
    return " ".join(m.value for m in at.markdown)


@unittest.skipIf(AppTest is None, "streamlit non installé")
class TestInterface(unittest.TestCase):
    def test_chargement_sans_erreur(self):
        at = AppTest.from_file(APP, default_timeout=30).run()
        self.assertFalse(at.exception)
        self.assertEqual(len(at.radio), 13)             # 12 habitudes + 1 question de contexte

    def test_formulaire_incomplet_avertit(self):
        at = AppTest.from_file(APP, default_timeout=30).run()
        at.button[0].click().run()
        self.assertTrue(any("sans réponse" in w.value for w in at.warning))

    def test_profil_plafonne_et_raison_affichee(self):
        at = lancer({"a2f": "Non", "mdp_unique": "Non"}, banque="Oui", usage="Étudiant(e)")
        self.assertFalse(at.exception)
        h = html_de(at)
        self.assertIn("Utilisateur moyen", h)
        self.assertIn("Score seul", h)                  # la raison du plafond est montrée
        self.assertIn("Risque combiné", h)
        self.assertIn("Gain rapide", h)
        self.assertIn("Références :", h)
        self.assertTrue(any("Second avis" in c.value for c in at.caption))

    def test_tout_bon(self):
        at = lancer()
        self.assertTrue(any("en place" in s.value for s in at.success))

    def test_tout_mauvais(self):
        at = lancer(defaut="Non")
        h = html_de(at)
        self.assertIn("Débutant à risque", h)
        self.assertEqual(h.count('<details class="reco"'), len(moteur.QUESTIONS))

    def test_aucune_url_externe(self):
        h = html_de(lancer({"a2f": "Non"}))
        for interdit in ("http://", "https://", "fonts.googleapis", "@import"):
            self.assertNotIn(interdit, h)

    def test_contenu_pirate_est_echappe(self):
        """Régression XSS : un conseil contenant du HTML doit s'afficher échappé, pas interprété."""
        original = moteur.PAR_ID["a2f"]["conseil"]
        moteur.PAR_ID["a2f"]["conseil"] = '<img src=x onerror="alert(1)">'
        try:
            h = html_de(lancer({"a2f": "Non"}))
        finally:
            moteur.PAR_ID["a2f"]["conseil"] = original
        self.assertNotIn('<img src=x', h)
        self.assertIn("&lt;img", h)


if __name__ == "__main__":
    unittest.main(verbosity=2)
