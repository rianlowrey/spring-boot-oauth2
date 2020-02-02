package com.example.oauth.config;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import java.util.Objects;
import javax.sql.DataSource;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.Elements;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter implements WebMvcConfigurer {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    private static final JWSAlgorithm jwsAlgorithm = JWSAlgorithm.RS256;
    private static final JWEAlgorithm jweAlgorithm = JWEAlgorithm.RSA_OAEP_256;
    private static final EncryptionMethod encryptionMethod = EncryptionMethod.A256GCM;

    private static final String encoderId = "bcrypt";

    private static final String GROUP_AUTHORITIES_BY_USERNAME =
        "select g.id, g.group_name, ga.authority "
            + "from groups g, group_members gm, group_authorities ga "
            + "where gm.username = ? and g.id = ga.group_id and g.id = gm.group_id";

    @Value("${oauth.security.realm}")
    private String realm;

    @Value("${spring.security.oauth2.resourceserver.jwk-set-uri}")
    private String jwkSetUri;

    @Value("${oauth.security.private-key}")
    private Resource privateKeyFile;

    @Value("${oauth.security.private-key.password}")
    private Resource privateKeyFilePassword;

    @Value("${oauth.security.public-key}")
    private Resource publicKeyFile;

    @Value("${user.oauth.user.username}")
    private String username;

    @Value("${user.oauth.user.password}")
    private String password;

    @Autowired
    private DataSource dataSource;

    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder)
        throws Exception {
        authenticationManagerBuilder
            .jdbcAuthentication()
            .passwordEncoder(passwordEncoder())
            .dataSource(this.dataSource)
            .groupAuthoritiesByUsername(GROUP_AUTHORITIES_BY_USERNAME);
    }

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .headers().frameOptions().sameOrigin()
            .and()
            .csrf().disable().antMatcher("/**")
            .oauth2ResourceServer(resource -> resource.jwt(Customizer.withDefaults()));
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers(
            "/h2/**",
            "/v3/api-docs",
            "/v3/api-docs/**",
            "/configuration/ui/**",
            "/swagger-resources/**",
            "/configuration/security/**",
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/webjars/**");
    }

    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Bean
    public DelegatingPasswordEncoder passwordEncoder() {
        final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder(10);

        final DelegatingPasswordEncoder delegatingPasswordEncoder =
            new DelegatingPasswordEncoder(encoderId,
                Collections.singletonMap(encoderId, bCryptPasswordEncoder));
        delegatingPasswordEncoder.setDefaultPasswordEncoderForMatches(bCryptPasswordEncoder);
        return delegatingPasswordEncoder;
    }

    @Bean
    public KeyPair keyPair()
        throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, CertificateException {
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        final byte[] privateKeyBytes = IOUtils
            .toByteArray(Objects.requireNonNull(this.privateKeyFile).getInputStream());

        PKCS8EncodedKeySpec pkcs8spec = new PKCS8EncodedKeySpec(privateKeyBytes);

        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8spec);

        CertificateFactory certificateFactory = CertificateFactory.getInstance(Elements.X509);

        X509Certificate x509Certificate = (X509Certificate) certificateFactory
            .generateCertificate(Objects.requireNonNull(this.publicKeyFile).getInputStream());

        PublicKey publicKey = x509Certificate.getPublicKey();

        return new KeyPair(publicKey, privateKey);
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter(final KeyPair keyPair) {
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        jwtAccessTokenConverter.setKeyPair(keyPair);

        DefaultAccessTokenConverter defaultAccessTokenConverter = new DefaultAccessTokenConverter();
        defaultAccessTokenConverter.setUserTokenConverter(new SubjectAttributeUserTokenConverter());

        jwtAccessTokenConverter.setAccessTokenConverter(defaultAccessTokenConverter);

        return jwtAccessTokenConverter;
    }

    @Bean
    public JWTProcessor<SecurityContext> jwtProcessor(final KeyPair keyPair)
        throws MalformedURLException {
        JWKSource<SecurityContext> jwsJwkSource = new RemoteJWKSet<>(new URL(this.jwkSetUri));
        JWSKeySelector<SecurityContext> jwsKeySelector =
            new JWSVerificationKeySelector<>(jwsAlgorithm, jwsJwkSource);

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).build();

        JWKSource<SecurityContext> jweJwkSource = new ImmutableJWKSet<>(new JWKSet(rsaKey));
        JWEKeySelector<SecurityContext> jweKeySelector = new JWEDecryptionKeySelector<>(
            jweAlgorithm, encryptionMethod, jweJwkSource);

        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(jwsKeySelector);
        jwtProcessor.setJWEKeySelector(jweKeySelector);

        return jwtProcessor;
    }

    @Bean
    public JwtDecoder jwtDecoder(final JWTProcessor<SecurityContext> jwtProcessor) {
        return new NimbusJwtDecoder(jwtProcessor);
    }

    @Bean
    public TokenStore tokenStore(final DataSource dataSource) {
        return new JdbcTokenStore(dataSource);
    }

    @Bean
    public DefaultTokenServices tokenServices(final AuthenticationManager authenticationManager,
        final ClientDetailsService clientDetailsService, final TokenStore tokenStore) {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setAuthenticationManager(authenticationManager);
        defaultTokenServices.setClientDetailsService(clientDetailsService);
        defaultTokenServices.setTokenStore(tokenStore);
        defaultTokenServices.setSupportRefreshToken(true);

        return defaultTokenServices;
    }

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource();
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.addAllowedOrigin("*");
        corsConfiguration.addAllowedHeader("*");
        corsConfiguration.addAllowedMethod("*");
        urlBasedCorsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration);

        return new CorsFilter(urlBasedCorsConfigurationSource);
    }
}
