---
id: RB-004
title: Erreurs 503 — readiness probe en échec
tags: [503, readiness, probe, unhealthy, 404, health]
---

## Symptômes
Les pods sont `Running` mais `0/1 Ready` ; le Service n'a aucun endpoint et renvoie 503.
Les événements montrent `Readiness probe failed`.

## Diagnostic
Comparer le chemin de la sonde avec les routes exposées par la nouvelle version de l'application.

```
kubectl get endpoints gateway -n gateway
kubectl describe deployment gateway -n gateway
```

## Remédiation
Corriger le chemin de la readiness probe dans le manifeste (source GitOps), puis redéployer.

```
kubectl patch deployment gateway -n gateway --type=json -p='[{"op":"replace","path":"/spec/template/spec/containers/0/readinessProbe/httpGet/path","value":"/readyz"}]'
kubectl rollout status deployment/gateway -n gateway
```
