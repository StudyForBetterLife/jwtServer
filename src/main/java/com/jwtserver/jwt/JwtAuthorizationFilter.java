package com.jwtserver.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.jwtserver.config.auth.PrincipalDetails;
import com.jwtserver.model.User;
import com.jwtserver.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 시큐리티가 가진 filter 중 BasicAuthenticationFilter가 있다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    // 권한, 인증이 필요한 특정 주소에 대한 요청이 들어오면 BasicAuthenticationFilter 필터를 거친다
    // 권한, 인증이 필요하지 않는 주소라면 BasicAuthenticationFilter 필터를 거치지 않는다.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 주소가 요청됨");

        String jwtHeader = request.getHeader(JwtProperties.HEADER_STRING);
        System.out.println("jwtHeader : " + jwtHeader);

        // 헤더에 Authorization 필드가 있는지 확인
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }

        // jwt 토큰을 검증하여 정상적인 사용자인지 확인해야 한다
        String jwtToken = request.getHeader(JwtProperties.HEADER_STRING).replace(JwtProperties.TOKEN_PREFIX, "");

        // 내가 SecurityContext에 집적접근해서 세션을 만들때 자동으로 UserDetailsService에 있는 loadByUsername이 호출됨.
        String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET))
                .build()
                .verify(jwtToken)
                .getClaim("username")
                .asString();

        // 정상적으로 서명된 경우
        if (username != null) {
            User userEntity = userRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

            // Jwt 토큰 서명이 정상적으로 이뤄지면 강제로 Authentication 객체를 생성함
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(
                            principalDetails,
                            null,
                            principalDetails.getAuthorities());

            // 방금 생성한 authentication 객체를 시큐리티 세션에 저장함
            SecurityContextHolder.getContext().setAuthentication(authentication);

        }
        chain.doFilter(request, response);
    }
}


