---
id: RB-002
title: OOMKilled — conteneur tué pour dépassement mémoire
tags: [oomkilled, memory, exit code 137, jvm, heap]
---

## Symptômes
Le conteneur redémarre avec `OOMKilled` (code de sortie 137). Pour une JVM, le heap (`-Xmx`)
est souvent égal à la limite mémoire du conteneur, sans marge pour la mémoire hors heap.

## Diagnostic
```
kubectl top pod -n checkout
kubectl describe pod -n checkout -l app=checkout
```

## Remédiation
Aligner le heap sur ~75 % de la limite mémoire, ou augmenter la limite si la charge le justifie.
Changement en production : validation humaine obligatoire.

```
kubectl set resources deployment/checkout -n checkout --limits=memory=1536Mi
kubectl rollout status deployment/checkout -n checkout
```
