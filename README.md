# SecureFileTransfer – Système de Transfert de Fichiers Sécurisé

Application Client-Serveur en Java permettant le transfert sécurisé de fichiers via TCP, avec chiffrement AES et vérification d’intégrité SHA-256.

## Équipe
- Laaraich Lina
- El Moussaoui Safae

*Projet supervisé par : Professeur M. Ahmed Bentajer*

## Fonctionnalités

- Authentification client via login/mot de passe  
- Négociation des métadonnées (nom, taille, hachage du fichier)  
- Transfert chiffré avec AES  
- Vérification d’intégrité via SHA-256  

## Identifiants de test

- **Username:** `admin`  
- **Password:** `admin123`

> Ces identifiants sont configurés en dur dans le serveur pour les tests.

## Protocole de Communication

1. Authentification
   Client → Serveur : login + password
   Serveur → Client : "AUTH_OK" ou "AUTH_FAIL"

2. Négociation
   Client → Serveur : nom_fichier, taille, SHA-256
   Serveur → Client : "READY_FOR_TRANSFER"

3. Transfert & Vérification
   Client → Serveur : contenu chiffré (AES)
   Serveur : déchiffre, sauvegarde, vérifie SHA-256
   Serveur → Client : "TRANSFER_SUCCESS" ou "TRANSFER_FAIL"


## Sécurité

- **Chiffrement** : AES/ECB/PKCS5Padding  
- **Clé AES** : partagée statiquement (hardcodée)  
- **Hachage** : SHA-256 via `java.security.MessageDigest`  

## Structure du Projet

SecureFileTransfer/
└── src/
├── SecureFileServer.java
├── SecureFileClient.java



