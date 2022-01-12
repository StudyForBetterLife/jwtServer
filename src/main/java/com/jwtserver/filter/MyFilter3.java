package com.jwtserver.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse res = (HttpServletResponse) servletResponse;

        System.out.println("필터 3");

        // 토큰 이름이 cos일 경우 인증되도록함.
        // 클라이언트에서 id, pw 가 정상적으로 들어오면 token을 발행하고 이를 응답해준다.
        // 클라이언트는 이후 header에 Authorization 필드의 value값으로 token을 설정하여 요청을 보낸다
        // 서버는 클라이언트가 보낸 token이 서버가 발행한 token인지 검증작업이 필요하다 (RSA, HS256)
//        if (req.getMethod().equals("POST")) {
//            String headerAuth = req.getHeader("Authorization");
//            System.out.println("POST 요청됨");
//            System.out.println(headerAuth);
//
//            // 클라이언트의 요청 header의 Authorization 필드값이 "cos"인 경우에만 인증한다.
//            if (headerAuth.equals("cos")) {
//                filterChain.doFilter(req, res);
//            } else {
//                PrintWriter writer = res.getWriter();
//                writer.println("인증 안됨");
//            }
//        }

        filterChain.doFilter(req,res);

    }
}
