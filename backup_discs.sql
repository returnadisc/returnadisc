BEGIN TRANSACTION;
CREATE TABLE discs (
            id TEXT PRIMARY KEY,
            owner TEXT
        , disc_name TEXT, contact TEXT);
INSERT INTO "discs" VALUES('DF-287349','Robert',NULL,NULL);
INSERT INTO "discs" VALUES('DF-792562','Robert',NULL,NULL);
INSERT INTO "discs" VALUES('DF-378439','Robert',NULL,NULL);
INSERT INTO "discs" VALUES('DF-349569','Pia',NULL,NULL);
INSERT INTO "discs" VALUES('DF-278766','Robert',NULL,NULL);
INSERT INTO "discs" VALUES('DF-501440','Robert','BERG','robert.winterqvist@gmail.com');
INSERT INTO "discs" VALUES('DF-521187','Robert W','GULD','robert.winterqvist@gmail.com');
INSERT INTO "discs" VALUES('DF-520858','Robert','FALK','robert.winterqvist@gmail.com');
INSERT INTO "discs" VALUES('DF-930879','Pia','BERG','robert.winterqvist@gmail.com');
INSERT INTO "discs" VALUES('DF-850552','Robert','FALK','robert.winterqvist@gmail.com');
INSERT INTO "discs" VALUES('DF-514188','Fredrik','BOSS','robert.winterqvist@gmail.com');
INSERT INTO "discs" VALUES('DF-270481','Robert','Shryke','robert.winterqvist@gmail.com');
INSERT INTO "discs" VALUES('DF-351379','Pia','Smooniie','pia.winterqvist@gmail.com');
INSERT INTO "discs" VALUES('DF-109771','Robert','GULD','robert.winterqvist@gmail.com');
INSERT INTO "discs" VALUES('DF-122512','Fredrik','Shryke','robert.winterqvist@gmail.com');
INSERT INTO "discs" VALUES('DF-119662','Pia','Smoodie','pia.winterqvist@gmail.com');
INSERT INTO "discs" VALUES('DF-831708','Robert','MALM','robert.winterqvist@gmail.com');
INSERT INTO "discs" VALUES('DF-820126','Robert','Smoodie','robert.winterqvist@gmail.com');
INSERT INTO "discs" VALUES('DF-212128','Robert','BOSS','robert.winterqvist@gmail.com');
INSERT INTO "discs" VALUES('DF-620841','Robert','FALK','robert.winterqvist@gmail.com');
CREATE TABLE handovers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            disc_id TEXT,
            action TEXT,
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
INSERT INTO "handovers" VALUES(1,'DF-278766','Jag gömde discen','I papperskorgen vid hål 18','2026-02-02 10:42:52');
INSERT INTO "handovers" VALUES(2,'DF-520858','Jag gömde discen','I korgen på hål 18','2026-02-02 11:09:33');
INSERT INTO "handovers" VALUES(3,'DF-930879','Jag gömde discen','Hål 2 tee','2026-02-02 11:12:48');
INSERT INTO "handovers" VALUES(4,'DF-850552','Jag gömde discen','I hål 17 korgen','2026-02-02 11:53:47');
INSERT INTO "handovers" VALUES(5,'DF-270481','Jag behåller tills vi ses','Vi ses ','2026-02-02 12:52:19');
INSERT INTO "handovers" VALUES(6,'DF-270481','Jag gömde discen','I busken','2026-02-02 13:10:43');
INSERT INTO "handovers" VALUES(7,'DF-351379','Jag gömde discen','Bakom hål 18','2026-02-02 17:01:36');
INSERT INTO "handovers" VALUES(8,'DF-351379','Jag gömde discen','Gömde den i dina byxor','2026-02-02 17:05:00');
INSERT INTO "handovers" VALUES(9,'DF-109771','Jag gömde discen','Det är min nu','2026-02-02 17:06:11');
INSERT INTO "handovers" VALUES(10,'DF-109771','Jag gömde discen','Hej då','2026-02-02 17:17:11');
INSERT INTO "handovers" VALUES(11,'DF-109771','Kontakta ägaren','Ring mig','2026-02-02 17:21:24');
INSERT INTO "handovers" VALUES(12,'DF-109771','Jag gömde discen','Hål 1 ','2026-02-02 17:25:48');
INSERT INTO "handovers" VALUES(13,'DF-122512','Jag gömde discen','Hej','2026-02-02 17:31:32');
INSERT INTO "handovers" VALUES(14,'DF-119662','Jag gömde discen','Den är min nu','2026-02-02 17:35:00');
INSERT INTO "handovers" VALUES(15,'DF-831708','Kontakta ägaren','Hämta mötethål 18','2026-02-03 13:44:20');
INSERT INTO "handovers" VALUES(16,'DF-820126','Jag gömde discen','Hej','2026-02-03 14:13:32');
DELETE FROM "sqlite_sequence";
INSERT INTO "sqlite_sequence" VALUES('handovers',16);
COMMIT;
