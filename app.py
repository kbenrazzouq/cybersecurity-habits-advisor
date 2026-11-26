"""
app.py - Interface web Streamlit.
Lancer avec :  streamlit run app.py
Le modèle est chargé depuis modele_arbre.json (JSON + empreinte SHA-256, voir moteur.py et SECURITE.md).
Aucun service externe n'est appelé : polices système, télémétrie Streamlit désactivée (.streamlit/config.toml).
"""
import html

import streamlit as st

from moteur import (QUESTIONS, CATEGORIES, PAR_ID, USAGES, obtenir_modele, analyser, rapport_texte)

st.set_page_config(page_title="Conseiller de sécurité", page_icon="🔐", layout="centered")

esc = html.escape   # tout texte injecté dans du HTML est échappé (défense en profondeur)

# Couleurs : une teinte par niveau, utilisée partout (anneau, bordures, pastilles)
COULEUR = {"critique": "#B8392F", "important": "#C98418", "recommandé": "#3F7D6B"}
COULEUR_PROFIL = {"Débutant à risque": "#B8392F", "Utilisateur moyen": "#C98418", "Utilisateur avancé": "#2E7D5B"}
CHOIX = {"Oui": "oui", "Parfois": "parfois", "Non": "non"}

st.markdown("""
<style>
html, body, [class*="css"], .stMarkdown, label, button { font-family: system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif !important; }
#MainMenu, footer, header[data-testid="stHeader"] { visibility: hidden; height: 0; }
.block-container { max-width: 760px; padding-top: 2.2rem; padding-bottom: 4rem; }
h1 { font-size: 1.9rem !important; font-weight: 700 !important; letter-spacing: -0.02em; color: #16212E; }
h3 { font-size: 1.05rem !important; font-weight: 600 !important; color: #1F4E79; margin-top: 1.6rem !important; }
.intro { color: #4A5868; line-height: 1.65; max-width: 62ch; margin-bottom: 1.4rem; }
[data-testid="stForm"] { background: #FFFFFF; border: 1px solid #DCE3EA; border-radius: 10px; padding: 1.4rem 1.6rem; }
[data-testid="stForm"] label p { font-size: 0.95rem; line-height: 1.5; }
.stButton > button, .stDownloadButton > button, [data-testid="stFormSubmitButton"] > button {
  border-radius: 8px; font-weight: 600; padding: 0.6rem 1.4rem; }
.bilan { display: flex; gap: 1.8rem; align-items: center; background: #FFFFFF; border: 1px solid #DCE3EA;
  border-radius: 10px; padding: 1.4rem 1.6rem; margin: 1rem 0 1.2rem; }
.bilan svg { flex: 0 0 auto; }
.bilan .profil { font-size: 1.35rem; font-weight: 700; margin: 0 0 .3rem; }
.bilan .msg { color: #4A5868; line-height: 1.55; margin: 0; }
.bilan .plafond { color: #7A4B00; background: #FFF4DE; border-radius: 6px; font-size: .85rem; line-height: 1.45;
  padding: .45rem .7rem; margin: .6rem 0 0; }
.alerte { border-left: 4px solid #B8392F; background: #FBEFEE; padding: .7rem 1rem; border-radius: 0 8px 8px 0;
  margin-bottom: .6rem; color: #5A1D18; font-size: .93rem; line-height: 1.5; }
.rapide { border-left: 4px solid #2E7D5B; background: #EDF6F1; padding: .6rem 1rem; border-radius: 0 8px 8px 0;
  margin-bottom: .5rem; color: #1D4D39; font-size: .93rem; line-height: 1.5; }
details.reco { background: #FFFFFF; border: 1px solid #DCE3EA; border-left-width: 5px; border-radius: 8px;
  margin-bottom: .6rem; padding: .75rem 1rem; }
details.reco summary { cursor: pointer; font-weight: 600; line-height: 1.45; }
details.reco summary:focus-visible { outline: 2px solid #1F4E79; outline-offset: 3px; }
details.reco .detail { color: #4A5868; font-size: .92rem; line-height: 1.6; margin-top: .6rem; }
.badge { display: inline-block; background: #2E7D5B; color: #fff; border-radius: 999px; font-size: .7rem;
  font-weight: 600; padding: .1rem .55rem; margin-left: .4rem; vertical-align: middle; }
.meta { color: #6B7886; font-size: .82rem; margin-top: .5rem; }
.refs { color: #6B7886; font-size: .8rem; margin-top: .4rem; line-height: 1.45; }
@media (max-width: 560px) { .bilan { flex-direction: column; text-align: center; } }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def charger_modele_cache():
    return obtenir_modele()   # lit modele_arbre.json (vérifié) ; l'entraîne seulement s'il est absent ou altéré


def anneau(score, couleur):
    """Jauge circulaire du score sur 100 (SVG). Le score est un entier, la couleur une constante."""
    score = int(score)
    c = 339.29
    reste = c * (1 - score / 100)
    return (f'<svg width="130" height="130" viewBox="0 0 130 130" role="img" aria-label="Score {score} sur 100">'
            f'<circle cx="65" cy="65" r="54" fill="none" stroke="#E3E9EF" stroke-width="12"/>'
            f'<circle cx="65" cy="65" r="54" fill="none" stroke="{couleur}" stroke-width="12" stroke-linecap="round" '
            f'stroke-dasharray="{c}" stroke-dashoffset="{reste:.2f}" transform="rotate(-90 65 65)"/>'
            f'<text x="65" y="64" text-anchor="middle" font-size="30" font-weight="700" fill="#16212E">{score}</text>'
            f'<text x="65" y="86" text-anchor="middle" font-size="12" fill="#6B7886">sur 100</text></svg>')


arbre, metriques = charger_modele_cache()

st.title("Ton niveau de sécurité numérique")
st.markdown('<p class="intro">Réponds aux 12 questions (Oui, Parfois ou Non). Tu obtiens un score, ton profil et la liste '
            'des actions à faire en premier. Aucune donnée n\'est enregistrée ni envoyée.</p>', unsafe_allow_html=True)

with st.form("questionnaire"):
    st.subheader("Ton contexte (facultatif)")
    usage_libelle = st.selectbox("Tu es plutôt…", list(USAGES.values()), key="ctx_usage")
    banque = st.radio("Utilises-tu la banque ou le paiement en ligne ?", ["Non", "Oui"], horizontal=True,
                      key="ctx_banque")
    reponses = {}
    for categorie in CATEGORIES:
        st.subheader(categorie)
        for q in (q for q in QUESTIONS if q["categorie"] == categorie):
            choix = st.radio(q["question"], list(CHOIX), index=None, horizontal=True, key=q["id"])
            reponses[q["id"]] = CHOIX[choix] if choix else None
    envoye = st.form_submit_button("Analyser mes habitudes", type="primary")

if envoye:
    manquantes = sum(v is None for v in reponses.values())
    if manquantes:
        st.warning(f"Il reste {manquantes} question(s) sans réponse. Réponds à toutes pour lancer l'analyse.")
    else:
        usage = next(k for k, v in USAGES.items() if v == usage_libelle)
        res = analyser(reponses, arbre, dict(usage=usage, banque_en_ligne=(banque == "Oui")))
        info = res["profil_info"]
        col = COULEUR_PROFIL[res["profil"]]
        plafond = (f'<p class="plafond">Score seul : {esc(res["profil_selon_score"])}. {esc(res["raison_plafond"])}</p>'
                   if res["raison_plafond"] else "")

        st.markdown(f'<div class="bilan">{anneau(res["score"], col)}<div>'
                    f'<p class="profil" style="color:{col}">{esc(info["emoji"])} {esc(res["profil"])}</p>'
                    f'<p class="msg">{esc(info["message"])}</p>{plafond}</div></div>', unsafe_allow_html=True)

        for a in res["alertes"]:
            st.markdown(f'<div class="alerte"><b>Risque combiné.</b> {esc(a)}</div>', unsafe_allow_html=True)

        if res["gains_rapides"]:
            st.subheader("Gains rapides")
            st.caption("Peu d'effort, gros effet : à faire en premier si tu n'as qu'un moment.")
            for r in res["gains_rapides"]:
                st.markdown(f'<div class="rapide">{esc(r["conseil"])}</div>', unsafe_allow_html=True)

        st.subheader("Actions à faire, dans cet ordre")
        if not res["recommandations"]:
            st.success("Toutes les bonnes pratiques évaluées sont en place.")
        for i, r in enumerate(res["recommandations"], 1):
            ouvert = " open" if i <= 3 else ""
            badge = '<span class="badge">Gain rapide</span>' if r["gain_rapide"] else ""
            partiel = " <i>(déjà en partie en place)</i>" if r["reponse"] == "parfois" else ""
            refs = " · ".join(esc(s) for s in r["sources"])
            st.markdown(
                f'<details class="reco" style="border-left-color:{COULEUR[r["niveau"]]}"{ouvert}>'
                f'<summary>{i}. {esc(r["conseil"])}{partiel}{badge}</summary>'
                f'<div class="detail"><b>Pourquoi ?</b> {esc(r["risque"])}</div>'
                f'<div class="meta">Niveau {esc(r["niveau"])} · Gravité {r["gravite"]}/5 · '
                f'Effort {r["effort"]}/3 · Priorité {r["priorite"]}</div>'
                f'<div class="refs">Références : {refs}</div></details>', unsafe_allow_html=True)

        # Second avis de l'arbre : un contrôle de cohérence, jamais une action concurrente
        if res["accord_arbre"]:
            st.caption("Second avis : l'arbre de décision (modèle appris à partir des règles) confirme cette priorité.")
        else:
            propose = (f"« {PAR_ID[res['action_arbre']]['conseil']} »" if res["action_arbre"]
                       else "aucune action")
            st.caption(f"Second avis : l'arbre de décision, simple approximation des règles, aurait plutôt proposé "
                       f"{propose}. Le système de règles reste la référence.")

        st.subheader("Conseils pour ton profil")
        for b in info["bonus"] + res["conseils_contexte"]:
            st.write(f"- {b}")

        st.download_button("Télécharger mon rapport", rapport_texte(res),
                           file_name="rapport_securite.txt", mime="text/plain")
