---
id: RB-000
title: Politique de changement en production
tags: [policy, production, approval, change management]
---

## Règles
- L'assistant ne fait que **proposer** des actions ; il n'exécute jamais rien.
- Les commandes en lecture seule (`get`, `describe`, `logs`, `top`) sont autorisées.
- Toute commande qui modifie l'état (`rollout`, `scale`, `set`, `patch`, `apply`) exige une validation humaine.
- Interdits : suppression de namespace, suppression massive (`--all`), `drain` de nœuds,
  exfiltration réseau, affichage de secrets.
