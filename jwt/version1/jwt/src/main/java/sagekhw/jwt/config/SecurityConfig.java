package sagekhw.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;
import sagekhw.jwt.jwt.JwtAccessDeniedHandler;
import sagekhw.jwt.jwt.JwtAuthenticationEntryPoint;
import sagekhw.jwt.jwt.JwtSecurityConfig;
import sagekhw.jwt.jwt.TokenProvider;


/*
    @EnableGlobalMethodSecurity(prePostEnabled = true) 어노테이션은
    메소드 단위로 @PreAuthorize 검증 어노테이션을 사용하기 위해 추가합니다.

    Password Encode는 BCryptPasswordEncoder()를 사용하겠습니다.
 */
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final TokenProvider tokenProvider;
    private final CorsFilter corsFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public SecurityConfig(
            TokenProvider tokenProvider,
            CorsFilter corsFilter,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler
    ) {
        this.tokenProvider = tokenProvider;
        this.corsFilter = corsFilter;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) {
        web
                .ignoring()
                .antMatchers(
                        "/favicon.ico"
                );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //우리는 Token 방식을 사용하므로 csrf 설정을 disable 합니다.
                .csrf().disable()

                .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)

                //예외처리를 위해 만들었던 코드를 지정해줍니다.
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                //데이터 확인을 위해 사용하고 있는 h2-console을 위한 설정을 추가해줍니다.
                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                // 우리는 세션을 사용하지 않기 때문에 세션 설정을 STATELESS로 지정해줍니다.
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                // Token이 없어도 호출할 수 있도록 허용합니다.
                .and()
                .authorizeRequests()
                .antMatchers("/api/hello").permitAll()
                .antMatchers("/api/authenticate").permitAll()
                .antMatchers("/api/signup").permitAll()
                .anyRequest().authenticated()

                // JwtFilter를 addFilterBefore 메소드로 등록했던 JwtSecurityConfig 클래스도 적용해줍니다.
                .and()
                .apply(new JwtSecurityConfig(tokenProvider));
    }

}