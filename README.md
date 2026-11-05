<div align="center">

# redveil

### Un cadre de simulation red team, pensé pour les engagements autorisés

[![CI](https://github.com/galaxytrip5/redveil/actions/workflows/ci.yml/badge.svg)](https://github.com/galaxytrip5/redveil/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-%E2%89%A5%203.11-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Licence](https://img.shields.io/badge/Licence-GPL--3.0-blue.svg)](LICENSE)

**redveil** regroupe des composants destinés à préparer, exécuter et documenter des simulations de sécurité encadrées. Le projet fournit une interface en ligne de commande, un stockage local SQLite et des outils de génération et de reporting — sans service externe obligatoire.

[Découvrir les fonctionnalités](#fonctionnalités) · [Installation](#installation) · [Tests](#tests-et-qualité) · [Documentation](#documentation)

</div>

> [!IMPORTANT]
> **Usage strictement autorisé.** N’utilisez redveil que dans le cadre d’un audit, d’un exercice ou d’une recherche pour lesquels vous disposez d’une autorisation explicite et préalable. Vous êtes responsable du respect des lois, du périmètre convenu et des règles d’engagement. Consultez également [EULA.md](EULA.md).

## Sommaire

- [Présentation](#présentation)
- [Fonctionnalités](#fonctionnalités)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Démarrage](#démarrage)
- [Tests et qualité](#tests-et-qualité)
- [Structure du projet](#structure-du-projet)
- [Éditions](#éditions)
- [Configuration et données](#configuration-et-données)
- [Documentation](#documentation)
- [Licence et utilisation responsable](#licence-et-utilisation-responsable)

## Présentation

redveil est un framework Python pour les équipes de sécurité qui souhaitent organiser des exercices red team contrôlés et reproductibles. Il rassemble la gestion des campagnes, un catalogue de techniques, des scénarios et modèles, ainsi que des fonctions de reporting dans une architecture légère.

Le cœur du projet s’appuie sur **Python 3.11+**, **SQLite** et un client HTTP asynchrone basé sur `aiohttp`. Les données opérationnelles sont conservées localement. Les tests sont conçus pour fonctionner hors ligne par défaut.

## Fonctionnalités

| Domaine | Aperçu |
|---|---|
| **Organisation d’exercices** | Gestion structurée des campagnes et de leurs éléments associés. |
| **Scénarios et modèles** | Bibliothèque de scénarios et génération à partir de packs de données validés. |
| **Catalogue de techniques** | Catalogue éditable, avec validation des entrées et prise en charge des catégories intégrées. |
| **Composants de simulation** | Modules regroupés autour de la préparation, de la livraison contrôlée et de l’observation des exercices. Leur usage doit rester dans le périmètre autorisé. |
| **Interface** | CLI et tableau de bord local pour accéder aux fonctions du projet. |
| **Suivi et restitution** | Stockage SQLite, événements de campagne et génération de rapports. Certaines options dépendent de l’édition et de la licence. |
| **Conception sobre** | Pas de compte ni de télémétrie annoncés ; aucun service externe n’est requis pour utiliser le cœur du projet. |

La portée exacte des fonctionnalités varie selon l’édition. Voir [EDITIONS.md](EDITIONS.md) pour la matrice détaillée.

## Prérequis

- Python **3.11 ou supérieur**
- `pip`
- Un environnement virtuel Python est recommandé

## Installation

Depuis la racine du dépôt :

```bash
python -m venv .venv
source .venv/bin/activate  # Windows : .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

La dépendance d’exécution principale est `aiohttp`. L’extra `dev` installe `pytest` pour lancer les tests.

## Démarrage

Afficher l’aide de la CLI :

```bash
python redveil.py help
```

Autres points d’entrée disponibles :

```bash
python -m cf help
python clickfix.py help
```

Ces points d’entrée appellent la même interface. Consultez l’aide intégrée pour découvrir les commandes et options disponibles dans votre édition. Avant tout exercice, définissez et faites approuver le périmètre, les systèmes concernés, les dates et les règles d’engagement.

## Tests et qualité

Exécuter la suite de tests :

```bash
pytest
```

Les tests sont hors ligne par défaut et n’ouvrent pas de connexion réseau ; la couche réseau est testée au moyen de transports simulés.

| Fichier | Couverture générale |
|---|---|
| `tests/test_cf.py` | Composants principaux, stockage, scénarios, rapports et interface |
| `tests/test_http.py` | Client HTTP et comportements réseau simulés |
| `tests/test_store_perf.py` | Requêtes et écritures du stockage |
| `tests/test_cli_fixes.py` | Régressions de la CLI |
| `tests/test_ops_boost.py` | Tests complémentaires des fonctions du projet |
| `tests/test_license_ed.py` | Gestion des licences et primitives associées |

## Structure du projet

| Chemin | Rôle |
|---|---|
| `cf/cli.py`, `cf/cli_core.py`, `cf/cmds_*.py` | Interface et groupes de commandes |
| `cf/store.py` | Persistance SQLite |
| `cf/http.py` | Client HTTP asynchrone mutualisé |
| `cf/lure.py`, `cf/stager.py` | Composants de scénarios et de préparation |
| `cf/techniques.py`, `cf/generator.py` | Catalogue et génération pilotée par des données |
| `cf/report.py`, `cf/gui.py`, `cf/gui.html` | Restitution et tableau de bord |
| `cf/data/` | Catalogues, scénarios et modèles fournis |
| `tests/` | Tests automatisés |
| `redveil.py`, `clickfix.py`, `cf/__main__.py` | Points d’entrée |

> La présence de modules dans le dépôt ne signifie pas que chacun est inclus dans la distribution OSS. Référez-vous à [EDITIONS.md](EDITIONS.md) pour connaître le contenu publié.

## Éditions

Le dépôt documente une édition open source et une édition Pro distribuée séparément. Certaines catégories et options avancées ne sont pas incluses dans le paquet OSS. Les détails et les règles de séparation sont décrits dans [EDITIONS.md](EDITIONS.md).

## Configuration et données

Les fichiers de données du projet se trouvent dans `cf/data/` et sont inclus dans le paquet selon la configuration de `pyproject.toml`. Les catalogues et packs suivent des schémas validés par les tests.

Pour les paramètres et secrets, consultez la documentation source et l’aide de la CLI. **Ne placez jamais de secrets, clés privées, jetons ou données sensibles dans le dépôt**, les journaux ou les rapports partagés. Utilisez des valeurs de test pour les démonstrations et stockez les secrets selon les règles de votre organisation.

## Documentation

- [EDITIONS.md](EDITIONS.md) — différence entre les éditions
- [EULA.md](EULA.md) — conditions d’utilisation (modèle à faire vérifier juridiquement)
- [LICENSE](LICENSE) — licence du code
- [ROADMAP.md](ROADMAP.md) — évolutions envisagées
- [TODOS.md](TODOS.md) — tâches en attente
- [SELLING.md](SELLING.md) — informations commerciales

## Licence et utilisation responsable

Le code de ce dépôt est distribué sous **GNU GPL-3.0** ; consultez [LICENSE](LICENSE) pour les conditions complètes. Des conditions additionnelles ou distinctes peuvent concerner d’autres éditions : vérifiez les documents applicables avant toute distribution ou utilisation.

Toute utilisation doit être limitée aux systèmes pour lesquels une autorisation explicite a été obtenue. Respectez le périmètre, les règles d’engagement, la confidentialité et les obligations de signalement convenus avec le propriétaire des systèmes.

---

<div align="center">

Fait pour des exercices de sécurité **autorisés, maîtrisés et documentés**.

</div>
