package com.jwtserver.config;

import com.jwtserver.filter.MyFilter1;
import com.jwtserver.filter.MyFilter2;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    // IoC를 활용하여 MyFilter1을 등록하는 방법
    // 시큐리티 필터 체인이 우선적으로 실행된 이후에
    // 내가 등록한 필터가 실행된다.
    // 시큐리티 필터체인의 addFilterBefore, addFilterAfter 모두 사용자가 등록한 필터보다 먼저 실행된다.

    @Bean
    public FilterRegistrationBean<MyFilter1> filter1() {
        FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
        bean.addUrlPatterns("/*");
        bean.setOrder(1); // 번호가 낮을 수록 먼저 실행된다
        return bean;
    }

    @Bean
    public FilterRegistrationBean<MyFilter2> filter2() {
        FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<>(new MyFilter2());
        bean.addUrlPatterns("/*");
        bean.setOrder(0); // 번호가 낮을 수록 먼저 실행된다
        return bean;
    }
}
