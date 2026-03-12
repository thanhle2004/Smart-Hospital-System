/*
  Warnings:

  - Added the required column `avgProcessTime` to the `Room` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE `room` ADD COLUMN `avgProcessTime` INTEGER NOT NULL;
