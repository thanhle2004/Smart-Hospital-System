-- CreateTable
CREATE TABLE `User` (
    `id` CHAR(36) NOT NULL,
    `email` VARCHAR(191) NOT NULL,
    `passwordHash` VARCHAR(191) NOT NULL,
    `role` ENUM('USER', 'ADMIN') NOT NULL DEFAULT 'USER',
    `isActive` BOOLEAN NOT NULL DEFAULT true,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `User_email_key`(`email`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `RefreshToken` (
    `id` CHAR(36) NOT NULL,
    `userId` CHAR(36) NOT NULL,
    `tokenHash` VARCHAR(191) NOT NULL,
    `expiresAt` DATETIME(3) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `UserProfile` (
    `id` CHAR(36) NOT NULL,
    `userId` CHAR(36) NOT NULL,
    `fullName` VARCHAR(191) NULL,
    `avatarUrl` VARCHAR(191) NULL,
    `bio` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `UserProfile_userId_key`(`userId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `PatientType` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `code` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `description` VARCHAR(191) NULL,
    `basePriority` INTEGER NULL,
    `isActive` BOOLEAN NOT NULL DEFAULT true,

    UNIQUE INDEX `PatientType_code_key`(`code`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Patient` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `name` VARCHAR(191) NOT NULL,
    `email` VARCHAR(191) NULL,
    `phone` VARCHAR(191) NOT NULL,
    `patientTypeId` INTEGER NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `Patient_email_key`(`email`),
    UNIQUE INDEX `Patient_phone_key`(`phone`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `PriorityRule` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `ruleName` VARCHAR(191) NOT NULL,
    `minAge` INTEGER NULL,
    `maxAge` INTEGER NULL,
    `patientTypeId` INTEGER NULL,
    `isEmergency` BOOLEAN NOT NULL DEFAULT false,
    `priorityValue` INTEGER NOT NULL,
    `applyOrder` INTEGER NOT NULL DEFAULT 0,
    `isActive` BOOLEAN NOT NULL DEFAULT true,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Flow` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `name` VARCHAR(191) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Room` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `name` VARCHAR(191) NOT NULL,
    `roomNumber` INTEGER NOT NULL,
    `capacity` INTEGER NOT NULL,
    `avgProcessTime` INTEGER NOT NULL,
    `roomTypeId` INTEGER NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `RoomType` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `name` VARCHAR(191) NOT NULL,
    `description` VARCHAR(191) NULL,
    `avgProcessTime` INTEGER NOT NULL,
    `defaultCapacity` INTEGER NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `FlowRoom` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `flowId` INTEGER NOT NULL,
    `roomTypeId` INTEGER NOT NULL,
    `defaultOrder` INTEGER NOT NULL,

    UNIQUE INDEX `FlowRoom_flowId_roomTypeId_key`(`flowId`, `roomTypeId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `FlowRoomDependency` (
    `flowId` INTEGER NOT NULL,
    `roomTypeId` INTEGER NOT NULL,
    `requiredRoomTypeId` INTEGER NOT NULL,

    PRIMARY KEY (`flowId`, `roomTypeId`, `requiredRoomTypeId`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Visit` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `patientId` INTEGER NOT NULL,
    `flowId` INTEGER NOT NULL,
    `checkInTime` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `appliedPriorityRuleId` INTEGER NULL,
    `status` ENUM('WAITING', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED') NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `VisitRoom` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `visitId` INTEGER NOT NULL,
    `roomId` INTEGER NOT NULL,
    `priority` INTEGER NULL,
    `status` ENUM('WAITING', 'IN_PROGRESS', 'COMPLETED', 'SKIPPED') NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `VisitRoom_visitId_roomId_key`(`visitId`, `roomId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `CentralQueue` (
    `id` BIGINT NOT NULL AUTO_INCREMENT,
    `visitId` INTEGER NOT NULL,
    `calculatedPriority` INTEGER NULL,
    `manualPriority` INTEGER NULL,
    `queueTime` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `globalSequence` BIGINT NOT NULL,

    UNIQUE INDEX `CentralQueue_visitId_key`(`visitId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `RoomQueue` (
    `id` BIGINT NOT NULL AUTO_INCREMENT,
    `visitRoomId` INTEGER NOT NULL,
    `enqueueTime` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `RefreshToken` ADD CONSTRAINT `RefreshToken_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `UserProfile` ADD CONSTRAINT `UserProfile_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Patient` ADD CONSTRAINT `Patient_patientTypeId_fkey` FOREIGN KEY (`patientTypeId`) REFERENCES `PatientType`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `PriorityRule` ADD CONSTRAINT `PriorityRule_patientTypeId_fkey` FOREIGN KEY (`patientTypeId`) REFERENCES `PatientType`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Room` ADD CONSTRAINT `Room_roomTypeId_fkey` FOREIGN KEY (`roomTypeId`) REFERENCES `RoomType`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `FlowRoom` ADD CONSTRAINT `FlowRoom_flowId_fkey` FOREIGN KEY (`flowId`) REFERENCES `Flow`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `FlowRoom` ADD CONSTRAINT `FlowRoom_roomTypeId_fkey` FOREIGN KEY (`roomTypeId`) REFERENCES `RoomType`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `FlowRoomDependency` ADD CONSTRAINT `FlowRoomDependency_flowId_fkey` FOREIGN KEY (`flowId`) REFERENCES `Flow`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `FlowRoomDependency` ADD CONSTRAINT `FlowRoomDependency_roomTypeId_fkey` FOREIGN KEY (`roomTypeId`) REFERENCES `RoomType`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `FlowRoomDependency` ADD CONSTRAINT `FlowRoomDependency_requiredRoomTypeId_fkey` FOREIGN KEY (`requiredRoomTypeId`) REFERENCES `RoomType`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Visit` ADD CONSTRAINT `Visit_patientId_fkey` FOREIGN KEY (`patientId`) REFERENCES `Patient`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Visit` ADD CONSTRAINT `Visit_flowId_fkey` FOREIGN KEY (`flowId`) REFERENCES `Flow`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Visit` ADD CONSTRAINT `Visit_appliedPriorityRuleId_fkey` FOREIGN KEY (`appliedPriorityRuleId`) REFERENCES `PriorityRule`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `VisitRoom` ADD CONSTRAINT `VisitRoom_visitId_fkey` FOREIGN KEY (`visitId`) REFERENCES `Visit`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `VisitRoom` ADD CONSTRAINT `VisitRoom_roomId_fkey` FOREIGN KEY (`roomId`) REFERENCES `Room`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `CentralQueue` ADD CONSTRAINT `CentralQueue_visitId_fkey` FOREIGN KEY (`visitId`) REFERENCES `Visit`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `RoomQueue` ADD CONSTRAINT `RoomQueue_visitRoomId_fkey` FOREIGN KEY (`visitRoomId`) REFERENCES `VisitRoom`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
