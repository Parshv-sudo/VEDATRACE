-- CreateTable
CREATE TABLE "public"."Contact_Us" (
    "contact_id" SERIAL NOT NULL,
    "full_name" VARCHAR(255) NOT NULL,
    "Email" VARCHAR(255) NOT NULL,
    "ph_no" VARCHAR(15),
    "user_type" VARCHAR(50),
    "subject" VARCHAR(100),
    "message" TEXT,

    CONSTRAINT "Contact_Us_pkey" PRIMARY KEY ("contact_id")
);

-- CreateTable
CREATE TABLE "public"."Harvest" (
    "Harvest_id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "Herb_type" VARCHAR(255) NOT NULL,
    "scientific_name" VARCHAR(255),
    "quantity_magnitude" DECIMAL,
    "quantity_unit" VARCHAR(50),
    "color_name" VARCHAR(50),
    "longitude" DECIMAL,
    "latitude" DECIMAL,
    "timestamp" TIMESTAMPTZ(6) DEFAULT CURRENT_TIMESTAMP,
    "date_of_sending_harvest" DATE,
    "Batch_id" UUID NOT NULL,
    "cid_of_harvest" VARCHAR(255),

    CONSTRAINT "Harvest_pkey" PRIMARY KEY ("Harvest_id")
);

-- CreateTable
CREATE TABLE "public"."Lab_Testing" (
    "lab_testing_id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "name_of_lab" VARCHAR(255),
    "Date" DATE,
    "City" VARCHAR(100),
    "batch_id" UUID,
    "purity_percent" DECIMAL,
    "cid_of_lab" VARCHAR(255),

    CONSTRAINT "Lab_Testing_pkey" PRIMARY KEY ("lab_testing_id")
);

-- CreateTable
CREATE TABLE "public"."Manufacturing" (
    "Mfg_id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "mdate" DATE,
    "Expdate" DATE,
    "batch_id" UUID,
    "Pr_id" VARCHAR(255),
    "cid_of_manf" VARCHAR(255),

    CONSTRAINT "Manufacturing_pkey" PRIMARY KEY ("Mfg_id")
);

-- CreateTable
CREATE TABLE "public"."Processing" (
    "Processing_id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "Name_of_center" VARCHAR(255),
    "Date" DATE,
    "City" VARCHAR(100),
    "Batch_id" UUID,
    "cid_of_processing" VARCHAR(255),

    CONSTRAINT "Processing_pkey" PRIMARY KEY ("Processing_id")
);

-- CreateTable
CREATE TABLE "public"."User" (
    "UserName" VARCHAR(100) NOT NULL,
    "FullName" VARCHAR(255) NOT NULL,
    "aadharId" VARCHAR(12) NOT NULL,
    "ph_number" VARCHAR(15) NOT NULL,
    "EmailId" VARCHAR(255) NOT NULL,
    "state" VARCHAR(100),
    "City" VARCHAR(100),
    "District" VARCHAR(100),
    "User_type" VARCHAR(50),
    "password" VARCHAR(255) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("UserName")
);

-- CreateIndex
CREATE UNIQUE INDEX "Harvest_Batch_id_key" ON "public"."Harvest"("Batch_id");

-- CreateIndex
CREATE UNIQUE INDEX "User_aadharId_key" ON "public"."User"("aadharId");

-- CreateIndex
CREATE UNIQUE INDEX "User_ph_number_key" ON "public"."User"("ph_number");

-- CreateIndex
CREATE UNIQUE INDEX "User_EmailId_key" ON "public"."User"("EmailId");

-- AddForeignKey
ALTER TABLE "public"."Lab_Testing" ADD CONSTRAINT "Lab_Testing_batch_id_fkey" FOREIGN KEY ("batch_id") REFERENCES "public"."Harvest"("Batch_id") ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "public"."Manufacturing" ADD CONSTRAINT "Manufacturing_batch_id_fkey" FOREIGN KEY ("batch_id") REFERENCES "public"."Harvest"("Batch_id") ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "public"."Processing" ADD CONSTRAINT "Processing_Batch_id_fkey" FOREIGN KEY ("Batch_id") REFERENCES "public"."Harvest"("Batch_id") ON DELETE NO ACTION ON UPDATE NO ACTION;
