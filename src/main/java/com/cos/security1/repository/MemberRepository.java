package com.cos.security1.repository;

import com.cos.security1.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, Long> {


    Member findByUsername(String username);
}
