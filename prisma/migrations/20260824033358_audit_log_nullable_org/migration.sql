-- AlterTable
ALTER TABLE "AuditLog" ALTER COLUMN "orgId" DROP NOT NULL;

-- CreateIndex
CREATE INDEX "AuditLog_actorEmail_createdAt_idx" ON "AuditLog"("actorEmail", "createdAt");
