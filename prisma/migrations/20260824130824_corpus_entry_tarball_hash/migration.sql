-- AlterTable
ALTER TABLE "CorpusEntry" ADD COLUMN     "tarballSha256" TEXT;

-- CreateIndex
CREATE INDEX "CorpusEntry_tarballSha256_idx" ON "CorpusEntry"("tarballSha256");
