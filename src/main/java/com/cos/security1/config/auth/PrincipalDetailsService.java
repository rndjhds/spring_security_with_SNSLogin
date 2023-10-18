package com.cos.security1.config.auth;

import com.cos.security1.entity.Member;
import com.cos.security1.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// 시큐리티 설정에서 .loginProcessingUrl("/login");
// /login 요청이 자동으로 UserDetailsService 타입으로 Ioc되어 이는 loadByUsername 함수가 실행
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    // 시큐리티 session => Authentication => UserDetails
    // 함수 종료시 @AuthenticationPricipal 어노테이션이 만들어진다.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // loadUserByUsername이 자동으로 UserDetails을 만들고 그 값을 Authentication으로 감싼 다음 시큐리티 session으로 감싸준다.
        Member member = memberRepository.findByUsername(username);
        if (member != null) {
            return new PrincipalDetails(member);
        }
        return null;
    }
}
