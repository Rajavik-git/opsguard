---
id: RB-003
title: ImagePullBackOff — image introuvable ou registre inaccessible
tags: [imagepullbackoff, errimagepull, registry, manifest unknown, tag]
---

## Symptômes
Le pod reste en `ImagePullBackOff` / `ErrImagePull`. Un message `manifest unknown` indique
un tag inexistant dans le registre ; `unauthorized` indique un problème d'imagePullSecret.

## Diagnostic
```
kubectl describe pod -n reporting -l app=reporting-api
kubectl get deployment reporting-api -n reporting -o jsonpath='{.spec.template.spec.containers[0].image}'
```

## Remédiation
Corriger le tag dans la chaîne CI/CD (GitOps) ou revenir à la dernière image publiée.

```
kubectl rollout undo deployment/reporting-api -n reporting
```
