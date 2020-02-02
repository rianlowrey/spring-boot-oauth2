## Spring Boot OAuth2 Authorization, Authentication, and Resource Service

### Getting Started
1. Generate an RSA public/private keypair for token generation. 
    ```
   ssh-keygen -t rsa -b 4096 -m PEM -f rsa.key
    openssl rsa -in rsa.key -pubout -outform PEM -out rsa.key.pub
    openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER -in rsa.key -out pkcs8.pem
    openssl req -new -x509 -key rsa.key -subj "/C=US/ST=Washington/O=Trusted Certificate Authority/CN=localhost/emailAddress=rian dot lowrey at gmail.com" -out x509.pem -days 365
    ```
2. Update `src/main/resources/application.properties`:
    ```
    ...8<...
    user.oauth.clientId=<id>
    user.oauth.clientSecret=<secret>
    oauth.security.private-key=classpath:pkcs8.pem
    oauth.security.private-key.password=
    oauth.security.public-key=classpath:x509.pem
    ...>8...
    ```
3. Generate new passwords for clients and users, see `src/main/resources/data.sql`.
4. Start the Spring Boot Application, e.g. `./gradlew bootRun`
5. Generate an authorization token
    ```
   curl -u '<clientId>:<clientSecret>' -X POST 'http://localhost:9090/oauth/token?grant_type=password&username=<username>&password=<password>'
    {
      "access_token" : "<JWT Encoded Token>",
      "token_type" : "bearer",
      "refresh_token" : "<Refresh Token>",
      "expires_in" : 299,
      "scope" : "read write",
      "jti" : "<UUID>"
    }
    ```
6. Authenticate using bearer token, e.g.
    ```
   curl -H "Authorization: Bearer <JWT Encoded Token>" 'http://localhost:9090/users/<username>'
   {
     "username": "<username>",
     "authorities": ["ROLE_USER"],
     ...8<...
   }
    ```
