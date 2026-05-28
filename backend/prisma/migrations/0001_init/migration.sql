-- Initial schema migration for MySQL
SET FOREIGN_KEY_CHECKS=0;

CREATE TABLE `User` (
  `id` varchar(36) NOT NULL,
  `username` varchar(191) NOT NULL,
  `createdAt` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username_unique` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `Message` (
  `id` varchar(36) NOT NULL,
  `conversationId` varchar(191) NOT NULL,
  `text` text NOT NULL,
  `fromId` varchar(36) NOT NULL,
  `createdAt` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `indexedAt` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `conversation_idx` (`conversationId`),
  KEY `from_idx` (`fromId`),
  CONSTRAINT `fk_message_user` FOREIGN KEY (`fromId`) REFERENCES `User` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `Media` (
  `id` varchar(36) NOT NULL,
  `key` varchar(191) NOT NULL,
  `provider` varchar(50) DEFAULT NULL,
  `uploaderId` varchar(36) DEFAULT NULL,
  `createdAt` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `media_key_unique` (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `RefreshToken` (
  `id` varchar(36) NOT NULL,
  `tokenHash` varchar(128) NOT NULL,
  `userId` varchar(36) NOT NULL,
  `revoked` tinyint(1) NOT NULL DEFAULT 0,
  `expiresAt` datetime DEFAULT NULL,
  `createdAt` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `token_hash_unique` (`tokenHash`),
  KEY `refresh_user_idx` (`userId`),
  CONSTRAINT `fk_refresh_user` FOREIGN KEY (`userId`) REFERENCES `User` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SET FOREIGN_KEY_CHECKS=1;
