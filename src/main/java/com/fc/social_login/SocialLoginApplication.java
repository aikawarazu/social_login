package com.fc.social_login;

import java.security.Principal;
import java.util.ArrayList;
import javax.servlet.Filter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.CompositeFilter;

@SpringBootApplication
//@EnableOAuth2Sso
@EnableOAuth2Client
@RestController
//@EnableAuthorizationServer
public class SocialLoginApplication extends WebSecurityConfigurerAdapter {

  @Autowired
  private OAuth2ClientContext oauth2ClientContext;

  @RequestMapping("/user")
  public Principal user(Principal principal) {

    return principal;
  }

  public static void main(String[] args) {
    SpringApplication.run(SocialLoginApplication.class, args);
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .antMatcher("/**")
        .authorizeRequests()
        .antMatchers("/", "/login**", "/webjars/**", "/error**")
        .permitAll()
        .anyRequest()
        .authenticated()
        .and().exceptionHandling()
        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/"))
        .and().logout().logoutSuccessUrl("/").permitAll()
        .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        .and().addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class)
    ;
  }

  private Filter ssoFilter() {
    CompositeFilter compositeFilter = new CompositeFilter();
    ArrayList<Filter> filters = new ArrayList<>();
    OAuth2ClientAuthenticationProcessingFilter githubFilter = ssoFilter("/login/github", github());
    filters.add(githubFilter);
    OAuth2ClientAuthenticationProcessingFilter github2Filter = ssoFilter("/login/github2", github2());
    filters.add(github2Filter);
    compositeFilter.setFilters(filters);
    return compositeFilter;
  }

  private OAuth2ClientAuthenticationProcessingFilter ssoFilter(String loginPath, ClientResources clientResources) {
    OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(
        loginPath);
    OAuth2RestTemplate githubTemplate = new OAuth2RestTemplate(clientResources.getClient(), oauth2ClientContext);
    filter.setRestTemplate(githubTemplate);
    UserInfoTokenServices githubTokenServices = new UserInfoTokenServices(
        clientResources.getResource().getUserInfoUri(), clientResources.getClient().getClientId());
    githubTokenServices.setRestTemplate(githubTemplate);
    filter.setTokenServices(githubTokenServices);
    return filter;
  }

  class ClientResources {

    @NestedConfigurationProperty
    private AuthorizationCodeResourceDetails client = new AuthorizationCodeResourceDetails();

    @NestedConfigurationProperty
    private ResourceServerProperties resource = new ResourceServerProperties();

    public AuthorizationCodeResourceDetails getClient() {
      return client;
    }

    public ResourceServerProperties getResource() {
      return resource;
    }
  }

  @Bean
  @ConfigurationProperties("github")
  public ClientResources github() {
    return new ClientResources();
  }

  @Bean
  @ConfigurationProperties("github2")
  public ClientResources github2() {
    return new ClientResources();
  }

  @Bean
  public FilterRegistrationBean oauth2ClientFilterRegistration(
      OAuth2ClientContextFilter filter) {
    FilterRegistrationBean registration = new FilterRegistrationBean();
    registration.setFilter(filter);
    registration.setOrder(-100);
    return registration;
  }

}