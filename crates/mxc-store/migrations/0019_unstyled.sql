-- XEP-0393: the sender asked for this message not to be styled (<unstyled xmlns='urn:xmpp:styling:0'/>).
ALTER TABLE messages ADD COLUMN unstyled INTEGER NOT NULL DEFAULT 0;
