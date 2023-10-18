package com.cos.security1.config;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity //  스프링 시큐리티 필터가 스프링 필터 체인에 등록이 됩니다.  CSRF 보호 기능이 활성화
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
// secured 어노테이션 활성화, preAuthorize, postAuthorize 어노테이션 활성화
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final PrincipalOauth2UserService principalOauth2UserService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();  // CSRF 보호 기능 비활성화
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated() // /user/경로로 들어오는 모든 애들은 인증(로그인)이 필요해
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')") // 인증(로그인)도 필요하고 해당 권한이 있는사람만 해당 경로에 들어올수 있게함
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')") // 인증(로그인)도 필요하고 해당 권한이 있는사람만 해당 경로에 들어올수 있게함
                .anyRequest().permitAll() // 위 경로 이외에는 모두 경로를 허용
                .and()
                .formLogin() // 로그인 폼의 형태를 지정
                .loginPage("/loginForm")  // 로그인 폼의 형태로 이동하는 경우는 위 인증이 필요한 경로로 이동할 경우 인증이 안되어 있으면 /login URI로 이동
                .loginProcessingUrl("/login") // /login URI가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행해줌
                .usernameParameter("username")// loadUserByUsername에 있는 파라미터와 매칭
                .defaultSuccessUrl("/") // 성공하면 메인페이지("/")로 이동 만약 특정 위치에 이동했다가 이동한경우 로그인 성공시 자동으로 그 위치로 이동해준다.
                .and()
                .oauth2Login() // oauth2Login이 발생할 때 이동하는 페이지 지정
                .loginPage("/loginForm")
                // 구글 로그인이 완료된 뒤의 후처리가 필요함.
                // 1. 코드 받기(인증),
                // 2. 엑세스 토큰(권한),
                // 3.사용자 프로필 정보를 가져오고, 4. 그 정보를 토대로 회원가입을 자동으로 진행시키기도 함
                .userInfoEndpoint() // 구글 로그인이 완료된 뒤의 후처리가 필요함 TIP. 코드X, (엑세스 토큰 + 사용자 프로필 정보O 가져옴)
                .userService(principalOauth2UserService);
    }
}
