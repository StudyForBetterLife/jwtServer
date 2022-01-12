package com.jwtserver.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jwtserver.config.auth.PrincipalDetails;
import com.jwtserver.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

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
        try {
            //System.out.println(request.getInputStream().toString()); // inputStream 속에 request body 내용이 담겨있다
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // 2. authenticationManager으로 로그인을 실행하면 PrincipalDetailsService가 실행된다
            // 그러면 PrincipalDetailsService의 loadUserByUsername 메소드가 자동으로 실행된다.
            // 그 후 로그인 정보가 authentication 변수에 담긴다
            // DB에 있는 username과 password가 일치한다는 것을 의미한다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // authentication이 가지고 있는 로그인 정보를 확인하는 코드이다.
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료됨 : username = " + principalDetails.getUser().getUsername());

            // 3. 권한 관리를 위해서 authentication 객체를 반환하여 시큐리티 세션에 담는다
            // (담지 않으면 SecurityConfig의 antMatcher()를 통한 권한관리가 안된다)
            return authentication;

        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    // attemptAuthentication 메소드가 실행되고 사용자 인증이 정상적으로 수행되면 successfulAuthentication 메소드가 실행된다.
    // 해당 메소드에서 jwt 토큰을 만들어 응답해준다
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨 : 인증이 완료되었다는 의미");

        // PrincipalDetails : 사용자의 로그인 정보가 담겨 있다
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // jwt 토큰 발행
        // RSA 방식이 아닌 Hash 암호 방식이다
        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        // 응답 헤더에 "Authorization: Bearer + jwt 토큰" 으로 jwt 토큰을 클라이언트에게 보낸다
        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
        super.successfulAuthentication(request, response, chain, authResult);
    }
}
