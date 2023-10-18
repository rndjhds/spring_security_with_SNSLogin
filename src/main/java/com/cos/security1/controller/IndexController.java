package com.cos.security1.controller;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.entity.Member;
import com.cos.security1.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

// 스프링 시큐리티는 시큐리티 세션이 있다.
@Controller
@RequiredArgsConstructor
public class IndexController {

    private final MemberRepository memberRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/test/login")
    @ResponseBody
    public String testLogin(Authentication authentication, //@AuthenticationPrincipal UserDetails userDetails
                            @AuthenticationPrincipal PrincipalDetails userDetails) { // DI(의존성 주입) @AuthenticationPrincipal로 세션정보를 받아옴
        System.out.println("/test/login =========================");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("authetication = " + principalDetails.getMember());

        //System.out.println("userDetails : " + userDetails.getUsername());
        System.out.println("userDetails : " + userDetails.getMember());

        return "세션 정보 확인하기";
    }

    @GetMapping("/test/oauth/login")
    @ResponseBody
    public String testOauthLogin(Authentication authentication
            , @AuthenticationPrincipal OAuth2User oAuth) { // DI(의존성 주입) @AuthenticationPrincipal로 세션정보를 받아옴
        System.out.println("/test/oauth/login =========================");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        System.out.println("authetication = " + oAuth2User.getAttributes());

        System.out.println("oAuth :" + oAuth.getAttributes());

        return "OAuth 세션 정보 확인하기";
    }

    @GetMapping({"", "/"})
    public String index() {
        System.out.println("인식");
        return "index";
    }

    @GetMapping("/user")
    public String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        System.out.println("principalDetails : " + principalDetails.getMember());
        return "user";
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public String manager() {
        return "manager";
    }

    // spring security가 login을 낚아챔
    // securityConfig을 설정후 login을 낚아채지 않음. 내가 만든 로그인 페이지로 이동하게 됨
    @GetMapping("/loginForm")
    public String login() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }


    @PostMapping("/join")
    public String join(Member member) {
        System.out.println(member);
        member.setRole("ROLE_USER");
        String rawPassword = member.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        member.setPassword(encPassword);
        memberRepository.save(member);
        return "redirect:/loginForm";
    }

    // 특정 메서드에 secure의 기능을 활성화
    @Secured("ROLE_ADMIN") // 권한이 ROLE_ADMIN이 아니면 접근 불가
    @GetMapping("/info")
    @ResponseBody
    public String info() {
        return "개인정보";
    }

    // 조건이 2개이상일떄 사용하기를 권장
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    @ResponseBody
    public String data() {
        return "데이터 정보";
    }

}
