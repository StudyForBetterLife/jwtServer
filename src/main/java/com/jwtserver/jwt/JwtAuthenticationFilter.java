package com.jwtserver.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// 스프링 시큐리티 필터 체인에 UsernamePasswordAuthenticationFilter가 존재한다.
// POST 방식으로 /login 요청이 들어와 id,pw를 전송하면
// UsernamePasswordAuthenticationFilter 필터가 동작한다.
// SecurityConfig에서 .formLogin().disable() 하였기 때문에 UsernamePasswordAuthenticationFilter가 동작하지 않는다
// 이를 동작하기 위해서 UsernamePasswordAuthenticationFilter 필터를 SecurityConfig에 등록해줘야한다
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login 요청이 오면 로그인 시도를 위해서 실행되는 함수이다.
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter: 로그인 시도중");

        // 1. username, password를 받아서 맞는 정보인지 확인한다.

        // 2. authenticationManager으로 로그인을 실행하면 PrincipalDetailsService가 실행된다
        // 그러면 PrincipalDetailsService의 loadUserByUsername 메소드가 자동으로 실행된다.

        // 3. 권한 관리를 위해서 PrincipalDetails 를 세션에 담는다. (담지 않으면 SecurityConfig의 antMatcher()를 통한 권한관리가 안된다)

        // 4. JWT 토큰을 만들어서 응답해준다.

        return super.attemptAuthentication(request, response);
    }
}
