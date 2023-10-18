package com.cos.security1.config.auth;


// 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
// 로그인을 진행이 완료되면 시큐리티 session을 만들어줍니다. (Security ContextHolder)에 저장을 시킨다.
// 오브젝트 => Authentication 타입 객체만 session으로 들어갈 수 있다.
// Authentication안에 Member정보가 있어야 됨.
// Member오브젝트 타입 => UserDetails 타입 객체로 변환
// Security Session => Authentication => UserDetails, OAuth2User 가 Authentication에 들어갈 수 있다.


import com.cos.security1.entity.Member;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Data
public class PrincipalDetails implements UserDetails, OAuth2User {

    private Member member;

    private Map<String, Object> attributes;

    // 일반 로그인
    public PrincipalDetails(Member member) {
        this.member = member;
    }

    // OAuth 로그인
    public PrincipalDetails(Member member, Map<String, Object> attributes) {
        this.member = member;
        this.attributes = attributes;
    }

    // 해당 유저의 권한을 리턴하는 곳!
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return member.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return member.getPassword();
    }

    @Override
    public String getUsername() {
        return member.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    // OAuth2User의 메서드 구현
    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return null;
    }
}
