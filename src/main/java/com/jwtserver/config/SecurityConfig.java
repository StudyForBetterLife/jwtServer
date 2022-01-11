package com.jwtserver.config;

import com.jwtserver.filter.MyFilter1;
import com.jwtserver.filter.MyFilter3;
import com.jwtserver.filter.MyFilter3;
import com.jwtserver.filter.MyFilter4;
import com.jwtserver.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 시큐리티 필터 체인 중 BasicAuthenticationFilter 전에 MyFilter3을 동작시킨다.
        // 시큐리티 필터 체인을 알아보고 동작 순서를 지정해보자
        http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
        http.addFilterAfter(new MyFilter4(), SecurityContextPersistenceFilter.class);

        http.csrf().disable();
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // session을 사용하지 않도록 한다
                .and()
                .addFilter(corsFilter) // 모든 요청은 corsFilter를 거친다,
                // 인증이 필요 없다면 컨트롤러에 @CrossOrigin 어노테이션을 달아주면 된다.
                // 인증이 필요하다면 corsFilter와 같이 시큐리티 핉터에 등록해줘야 한다
                .formLogin().disable() // form 로그인 사용 하지 않음
                .httpBasic().disable() // 기본적인 http 로그인 방식을 사용하지 않음
                // .formLogin().disable() 으로 인해 UsernamePasswordAuthenticationFilter가 동작하지 않으므로
                // 해당 필터를 상속한 JwtAuthenticationFilter 필터를 등록해준다.
                .addFilter(new JwtAuthenticationFilter(authenticationManager())) // AuthenticationManager는 WebSecurityConfigurerAdapter가 가지고 있다
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
        ;
    }
}
