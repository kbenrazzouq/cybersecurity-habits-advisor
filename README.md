# Cybersecurity Habits Advisor

A tool that evaluates a user's digital security habits and suggests **prioritized actions** based on the identified risks
(enable two-factor authentication, stop reusing passwords, etc.).

Techniques: **rule-based system** + **profile-based recommendation** (score, capped profile, context) + **decision tree**
(scikit-learn) used as an interpretable second opinion.

> The user interface and the advice are written in French.

## Installation
    python -m venv .venv
    .venv\Scripts\activate          # Windows   |   source .venv/bin/activate  # Linux / macOS
    pip install -r requirements.txt

## Usage
    streamlit run app.py            # web interface
    python console.py               # terminal version
    python entrainer.py             # (re)train the tree -> modele_arbre.json + modele_arbre.json.sha256
    python -m unittest -v test_moteur test_interface   # 40 tests (engine, model security, interface)
    python tests_profils.py         # evaluation report (scenarios, sensitivity, figures in docs/)

## Files
| File | Role |
|---|---|
| `moteur.py` | knowledge base, rules, score, capped profile, context, decision tree, secure model loading |
| `app.py` | Streamlit web interface (questionnaire + technical "Méthode" tab) |
| `console.py` | terminal version |
| `entrainer.py` | trains and saves the model (JSON + SHA-256 fingerprint) |
| `test_moteur.py` | 33 unit and security tests (`unittest`) |
| `test_interface.py` | 7 interface tests (AppTest), including an XSS regression test |
| `tests_profils.py` | evaluation: scenarios, method comparison, sensitivity, external reviews |
| `modele_arbre.json`, `.sha256` | trained model (JSON, no pickle) and its fingerprint |
| `SECURITE.md` | threat model, countermeasures, tests, residual risks |
| `CHANGELOG.md` | improvements compared to the first version |
| `docs/` | tree figure (illustration), exported real tree, external reviews template |
| `.streamlit/config.toml` | Streamlit telemetry disabled |

## What the tool does
1. **12 questions** (Yes / Sometimes / No) and an **optional context** (student or professional, online banking).
2. **Rules**: priority = severity × aggravation factor × weight of the gap × context factor.
3. **Profile**: score out of 100, capped if a critical action or several combined risks remain.
4. **Quick wins**: low-effort, high-priority actions are highlighted.
5. **Second opinion** from the decision tree, without ever showing two contradictory "most urgent actions".
6. **Downloadable report**, with the references for each piece of advice.

## Adding a habit
Add a dictionary to `QUESTIONS` (`moteur.py`) with: `id`, `categorie`, `gravite` (1-5), `effort` (1-3), `question`,
`risque`, `conseil`, `sources` (keys of `SOURCES`). Then run `python entrainer.py` and `python -m unittest test_moteur`
again. An outdated model (questions changed) is rejected at load time and automatically retrained.

## Teamwork
- [@kbenrazzoug](https://github.com/kbenrazzoug)
- [@Fadwa-hub211](https://github.com/Fadwa-hub211)
- [@salmagarboune](https://github.com/salmagarboune)
