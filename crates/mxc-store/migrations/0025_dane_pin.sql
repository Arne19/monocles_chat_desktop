-- DANE pin (HSTS-style, as on monocles Android): set once the account logged in with a
-- DANE-verified server certificate. From then on DANE is enforced for the account, so a network
-- that strips DNSSEC data can't quietly downgrade the server to the CA check. Cleared only by the
-- user ("Stop requiring DANE").
ALTER TABLE accounts ADD COLUMN dane_pin INTEGER NOT NULL DEFAULT 0;
