insert into OAUTH_CLIENT_DETAILS (CLIENT_ID, CLIENT_SECRET, scope, AUTHORIZED_GRANT_TYPES,
                                  AUTHORITIES, ACCESS_TOKEN_VALIDITY, REFRESH_TOKEN_VALIDITY)
values ('clientId', '{bcrypt}$2a$10$p3TX4RMQCDIbbqkvBXYqIO7Uuhy0uUkEJZelTddH4bThJ9l5ufe82',
        'read,write', 'password,refresh_token,client_credentials,authorization_code',
        'ROLE_CLIENT,ROLE_TRUSTED_CLIENT', 900, 2592000);


insert into USERS (USERNAME, PASSWORD, ENABLED)
values ('admin', '{bcrypt}$2a$10$UnRhwbh/lfXjytJhnkMT.O2OnkuFrquzzI6QIsOfLOdzryyEX5XGi', 1),
       ('disabled', '{bcrypt}$2a$10$dALCYhD15nj6bWKv0h/FXuuyUTMt43Z9W1NDlavEdbwDfUlObZBRe', 0),
       ('guest', '{bcrypt}$2a$10$Y6oRKlZ33UZ7O6QbLuSZx.YSKOYgYwHs.Xp2hzNvmbuxeGgqB9JKy', 1),
       ('user', '{bcrypt}$2a$10$GCo9l9n6HKLTjECGUFRoheEafg2BDI9EDcZ7Z/cUFD6nkBqzNHs9u', 1);


insert into AUTHORITIES (USERNAME, AUTHORITY)
values ('admin', 'ROLE_ADMIN'),
       ('disabled', 'ROLE_GUEST'),
       ('guest', 'ROLE_GUEST'),
       ('user', 'ROLE_USER');


insert into GROUPS (GROUP_NAME)
values ('GROUP_USERS'),
       ('GROUP_ADMINISTRATORS');


insert into GROUP_AUTHORITIES (GROUP_ID, AUTHORITY)
select ID,
       'ROLE_USER'
from GROUPS
where GROUP_NAME = 'GROUP_USERS';


insert into GROUP_AUTHORITIES (GROUP_ID, AUTHORITY)
select ID,
       'ROLE_USER'
from GROUPS
where GROUP_NAME = 'GROUP_ADMINISTRATORS';


insert into GROUP_AUTHORITIES (GROUP_ID, AUTHORITY)
select ID,
       'ROLE_ADMIN'
from GROUPS
where GROUP_NAME = 'GROUP_ADMINISTRATORS';


insert into GROUP_MEMBERS (GROUP_ID, USERNAME)
select ID,
       'user'
from GROUPS
where GROUP_NAME = 'GROUP_USERS';


insert into GROUP_MEMBERS (GROUP_ID, USERNAME)
select ID,
       'admin'
from GROUPS
where GROUP_NAME = 'GROUP_ADMINISTRATORS';