drop table if exists OAUTH_CLIENT_DETAILS;
create table OAUTH_CLIENT_DETAILS(
  CLIENT_ID varchar(256) null,
  RESOURCE_IDS varchar(256) null,
  CLIENT_SECRET varchar(256) null,
  SCOPE varchar(256) null,
  AUTHORIZED_GRANT_TYPES varchar(256) null,
  WEB_SERVER_REDIRECT_URI varchar(256) null,
  AUTHORITIES varchar(256) null,
  ACCESS_TOKEN_VALIDITY int null,
  REFRESH_TOKEN_VALIDITY int null,
  ADDITIONAL_INFORMATION varchar(4096) null,
  AUTOAPPROVE varchar(256) null,
  primary key (CLIENT_ID)
);

drop table if exists OAUTH_CLIENT_TOKEN;
create table OAUTH_CLIENT_TOKEN(
  TOKEN_ID varchar(256) null,
  TOKEN longvarbinary null,
  AUTHENTICATION_ID varchar(256) null,
  USER_NAME varchar(256) null,
  CLIENT_ID varchar(256) null,
  primary key (AUTHENTICATION_ID)
);

drop table if exists OAUTH_ACCESS_TOKEN;
create table OAUTH_ACCESS_TOKEN(
  TOKEN_ID varchar(256) null,
  TOKEN longvarbinary null,
  AUTHENTICATION_ID varchar(256) null,
  USER_NAME varchar(256) null,
  CLIENT_ID varchar(256) null,
  AUTHENTICATION longvarbinary null,
  REFRESH_TOKEN varchar(256) null,
  primary key (AUTHENTICATION_ID)
);

drop table if exists OAUTH_REFRESH_TOKEN;
create table OAUTH_REFRESH_TOKEN(
  TOKEN_ID varchar(256) null,
  TOKEN longvarbinary null,
  AUTHENTICATION longvarbinary null
);

drop table if exists OAUTH_CODE;
create table OAUTH_CODE(
  CODE varchar(256) null,
  AUTHENTICATION longvarbinary null
);

drop table if exists OAUTH_APPROVALS;
create table OAUTH_APPROVALS(
  USERID varchar(256) null,
  CLIENTID varchar(256) null,
  SCOPE varchar(256) null,
  STATUS varchar(10) null,
  EXPIRESAT timestamp null,
  LASTMODIFIEDAT timestamp null
);

drop table if exists USERS;
create table USERS(
  USERNAME varchar(50) not null,
  PASSWORD varchar(256) not null,
  ENABLED boolean not null,
  primary key (USERNAME)
);

drop table if exists AUTHORITIES;
create table AUTHORITIES(
  USERNAME varchar(50) not null,
  AUTHORITY varchar(50) not null,
  constraint FK_AUTHORITIES_USERS
    foreign key (USERNAME)
    references USERS (USERNAME)
);

drop index if exists IX_AUTH_USERNAME;
create unique index IX_AUTH_USERNAME on AUTHORITIES(
  USERNAME,
  AUTHORITY
);

drop table if exists GROUPS;
create table GROUPS(
  ID bigint not null auto_increment,
  GROUP_NAME varchar(50) not null,
  primary key (ID)
);

drop table if exists GROUP_AUTHORITIES;
create table GROUP_AUTHORITIES(
  GROUP_ID bigint not null,
  AUTHORITY varchar(50) not null,
  constraint FK_GROUP_AUTHORITIES_GROUP
    foreign key (GROUP_ID)
    references GROUPS (ID)
);

drop table if exists GROUP_MEMBERS;
create table GROUP_MEMBERS(
  ID bigint not null auto_increment,
  USERNAME varchar(50) not null,
  GROUP_ID bigint not null,
  primary key (ID),
  constraint FK_GROUP_MEMBERS_GROUP
    foreign key (GROUP_ID)
    references GROUPS (ID)
);
