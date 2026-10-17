-- XEP-0474: priority of the strongest SASL mechanism used for the account so far (-1: none).
-- Once SCRAM was used PLAIN is refused, and a weaker SCRAM variant needs the server's downgrade
-- protection hash. Reset when the user enters the password again.
ALTER TABLE accounts ADD COLUMN sasl_pin INTEGER NOT NULL DEFAULT -1;
