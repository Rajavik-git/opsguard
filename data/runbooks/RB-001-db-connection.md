---
id: RB-001
title: CrashLoopBackOff — connexion à la base de données refusée
tags: [crashloopbackoff, postgresql, connection refused, database, 5432]
---

## Symptômes
Les pods applicatifs redémarrent en boucle (CrashLoopBackOff). Les logs contiennent
`Connection refused` vers le service PostgreSQL (port 5432) au démarrage.

## Diagnostic
1. Vérifier que le service et les endpoints de la base existent et pointent vers un pod prêt.
2. Vérifier l'état du StatefulSet PostgreSQL et ses événements.
3. Contrôler les NetworkPolicies du namespace (un déploiement récent peut avoir restreint le trafic).

```
kubectl get endpoints pg-payments -n payments
kubectl get statefulset -n payments
kubectl get networkpolicy -n payments
```

## Remédiation
Si la base est saine mais l'application ne la joint pas après un déploiement, revenir à la
version précédente pendant l'analyse. Toute action en production nécessite une validation humaine.

```
kubectl rollout undo deployment/payments-api -n payments
kubectl rollout status deployment/payments-api -n payments
```
