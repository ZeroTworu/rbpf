CREATE TABLE IF NOT EXISTS rules (
     id                      INTEGER PRIMARY KEY AUTOINCREMENT,
     rule_name               TEXT NOT NULL,

     "drop"                  BOOLEAN NOT NULL,
     ok                      BOOLEAN NOT NULL,
     v4                      BOOLEAN NOT NULL,
     v6                      BOOLEAN NOT NULL,
     tcp                     BOOLEAN NOT NULL,
     udp                     BOOLEAN NOT NULL,
     "on"                    BOOLEAN NOT NULL,

     source_addr_v6          TEXT NOT NULL,
     destination_addr_v6     TEXT NOT NULL,

     source_addr_v4          INTEGER NOT NULL,
     destination_addr_v4     INTEGER NOT NULL,

     ifindex                 INTEGER NOT NULL,
     uindex                  INTEGER NOT NULL,

     source_port_start       INTEGER NOT NULL,
     source_port_end         INTEGER NOT NULL,
     destination_port_start  INTEGER NOT NULL,
     destination_port_end    INTEGER NOT NULL,

     input                   BOOLEAN NOT NULL,
     output                  BOOLEAN NOT NULL,

     source_mask_v4          INTEGER NOT NULL,
     destination_mask_v4     INTEGER NOT NULL,
     source_mask_v6          INTEGER NOT NULL,
     destination_mask_v6     INTEGER NOT NULL
);