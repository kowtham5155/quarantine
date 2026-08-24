-- AlterTable
ALTER TABLE "User" ADD COLUMN     "lastTotpTimeStep" INTEGER,
ADD COLUMN     "totpRecoveryCodes" TEXT[] DEFAULT ARRAY[]::TEXT[];
